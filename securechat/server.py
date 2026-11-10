"""Servidor relay.

Hace pocas cosas, y ninguna requiere ver el contenido de los mensajes:
  1. Autentica a cada cliente con un reto firmado por su clave Ed25519.
  2. Recuerda qué clave pública corresponde a cada nombre (TOFU), para que nadie
     pueda conectarse con el nombre de otro y recibir sus mensajes.
  3. Guarda la prekey firmada de cada usuario, para que puedan escribirle aunque
     esté desconectado.
  4. Reenvía bytes opacos; si el destinatario no está, guarda el sobre cifrado en
     una cola y se lo entrega cuando se conecta.
  5. Avisa a tus contactos de cuándo te conectas o desconectas.

Nunca ve el texto de los mensajes ni posee claves capaces de descifrarlos.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import secrets
import json
import logging
import mimetypes
import os
import re
import ssl
import sys
import time
from pathlib import Path

import nacl.utils
from websockets.asyncio.server import ServerConnection, serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from .crypto import CryptoError, b64d, b64e, encode_fields, verify_signature

log = logging.getLogger("securechat.server")

# Letras (mayúsculas o minúsculas), números, punto, guion y guion bajo. Solo ASCII a
# propósito: con Unicode, "аlice" (con 'а' cirílica) se vería igual que "alice".
# La unicidad no distingue mayúsculas: si existe "Alice", nadie puede registrar "alice".
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9_]$")
USERNAME_HELP = "3-32 caracteres: letras, números, '_', '.' o '-'"
# Cabe un vídeo de ~8 MB cifrado y en base64 (dos veces) dentro de un mensaje.
MAX_FRAME = 20 * 1024 * 1024
LOOKUP_LIMIT = 30  # búsquedas por minuto y conexión (frena la enumeración de usuarios)
AUTH_TIMEOUT = 10
AUTH_CONTEXT = b"securechat-auth-v1"
QUEUE_MAX_MSGS = 300
QUEUE_MAX_BYTES = 64 * 1024 * 1024
QUEUE_TTL = 14 * 24 * 3600
CODE_FAILS_LIMIT = 10  # intentos fallidos de código por IP y minuto

# Con PyInstaller los ficheros de la web van dentro del .exe (sys._MEIPASS).
_BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
WEB_DIR = (_BASE / "web").resolve()
MIME = {".js": "text/javascript", ".webmanifest": "application/manifest+json",
        ".svg": "image/svg+xml", ".png": "image/png", ".css": "text/css",
        ".html": "text/html", ".json": "application/json"}
SECURITY_HEADERS = {
    # libsodium.js compila WebAssembly: necesita 'wasm-unsafe-eval' (no 'unsafe-eval').
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
                               "connect-src 'self'; img-src 'self' data: blob:; media-src blob:; "
                               "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-cache",
}


def auth_message(nonce: bytes, user: str) -> bytes:
    return encode_fields(AUTH_CONTEXT, nonce, user.encode())


def new_access_code() -> str:
    """Código de acceso legible: 8 caracteres sin ambiguos (0/O, 1/I), unos 40 bits."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_code(code) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def serve_static(connection: ServerConnection, request: Request) -> Response | None:
    """Sirve la web estática. Las peticiones WebSocket siguen su camino (None)."""
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return None
    path = request.path.split("?", 1)[0]
    if path == "/config.json":  # la web pregunta si este servidor pide código de acceso
        relay = getattr(connection.server, "relay", None)
        body = json.dumps({"code_required": bool(relay and relay.access_code)}).encode()
        return _response(200, "OK", body, "application/json")
    if path == "/":
        path = "/index.html"
    target = (WEB_DIR / path.lstrip("/")).resolve()
    if not target.is_relative_to(WEB_DIR) or not target.is_file():
        return _response(404, "Not Found", b"404", "text/plain")
    ctype = MIME.get(target.suffix) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype.endswith(("json", "javascript")):
        ctype += "; charset=utf-8"
    return _response(200, "OK", target.read_bytes(), ctype)


def _response(status: int, reason: str, body: bytes, ctype: str) -> Response:
    headers = Headers(SECURITY_HEADERS)
    headers["Content-Type"] = ctype
    headers["Content-Length"] = str(len(body))
    return Response(status, reason, headers, body)


def client_ip(ws: ServerConnection) -> str:
    """IP del cliente. Detrás de un túnel local (cloudflared) todas las conexiones
    llegan desde 127.0.0.1, así que en ese caso usamos la cabecera del túnel."""
    ip = (ws.remote_address or ("?",))[0]
    if ip in ("127.0.0.1", "::1") and ws.request is not None:
        fwd = ws.request.headers.get("CF-Connecting-IP") or ws.request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return ip


def canon(name: str) -> str:
    """Clave interna de un usuario: sin distinguir mayúsculas."""
    return name.lower()


def spk_message(user: str, spk: bytes, created: int) -> bytes:
    # Igual que securechat.sealed.spk_message (no se importa para no crear un ciclo)
    return encode_fields(b"securechat-v1", b"spk", user.encode(), spk, created.to_bytes(8, "big"))


class RelayServer:
    def __init__(self, db_path: Path | None = None, queue_dir: Path | None = None,
                 access_code: str | None = None):
        self.db_path = db_path
        self.queue_dir = queue_dir
        # Si hay código, solo entra quien lo conozca (el dueño se lo da a sus amigos)
        self.access_code = normalize_code(access_code) or None
        self._code_fails: dict[str, list[float]] = {}
        # canon(nombre) -> {"name": grafía registrada, "key": bytes, "bundle": dict | None}
        self.registry: dict[str, dict] = {}
        self.online: dict[str, ServerConnection] = {}       # canon -> conexión
        self.queues: dict[str, list[dict]] = {}             # canon -> sobres en espera
        self.related: dict[str, set[str]] = {}              # con quién ha hablado cada uno
        if db_path and db_path.exists():
            for name, v in json.loads(db_path.read_text(encoding="utf-8")).items():
                if isinstance(v, str):  # formato antiguo: {"nombre": "clave"}
                    v = {"name": name, "key": v}
                self.registry[canon(v["name"])] = {"name": v["name"], "key": b64d(v["key"]),
                                                   "bundle": v.get("bundle")}
        if queue_dir and queue_dir.exists():
            for f in queue_dir.glob("*.json"):
                self.queues[f.stem] = json.loads(f.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ persistencia

    def _save(self) -> None:
        if not self.db_path:
            return
        data = {c: {"name": r["name"], "key": b64e(r["key"]), "bundle": r["bundle"]}
                for c, r in self.registry.items()}
        tmp = self.db_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.db_path)

    def _save_queue(self, c: str) -> None:
        if not self.queue_dir:
            return
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        f = self.queue_dir / f"{c}.json"
        if self.queues.get(c):
            tmp = f.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.queues[c]), encoding="utf-8")
            os.replace(tmp, f)
        elif f.exists():
            f.unlink()

    # ------------------------------------------------------------ conexión

    async def _authenticate(self, ws: ServerConnection) -> str | None:
        hello = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
        user, key = hello.get("user", ""), b64d(hello.get("identity_key", ""))
        if hello.get("type") != "hello" or not USERNAME_RE.match(user) or len(key) != 32:
            await _send(ws, type="error", code="bad_hello", message=f"nombre inválido ({USERNAME_HELP})")
            return None
        if self.access_code:
            ip = client_ip(ws)
            now = time.monotonic()
            fails = self._code_fails[ip] = [t for t in self._code_fails.get(ip, []) if now - t < 60]
            if len(fails) >= CODE_FAILS_LIMIT:
                await _send(ws, type="error", code="too_many", message="demasiados intentos, espera un minuto")
                return None
            given = normalize_code(hello.get("code"))
            if not hmac.compare_digest(given, self.access_code):
                if given:  # solo cuenta como intento quien prueba un código (no quien no envía ninguno)
                    fails.append(now)
                await _send(ws, type="error", code="bad_code",
                            message="código de acceso incorrecto: pídeselo a quien gestiona el servidor")
                return None
        nonce = nacl.utils.random(32)
        await _send(ws, type="challenge", nonce=b64e(nonce))
        reply = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
        verify_signature(key, auth_message(nonce, user), b64d(reply.get("sig", "")))

        known = self.registry.get(canon(user))
        if known is None:
            self.registry[canon(user)] = {"name": user, "key": key, "bundle": None}
            self._save()
            log.info("nuevo usuario registrado: %s", user)
            return user
        if known["key"] != key:
            await _send(ws, type="error", code="name_taken", message="ese nombre de usuario ya está en uso")
            return None
        return known["name"]  # siempre con la grafía con la que se registró

    async def handler(self, ws: ServerConnection) -> None:
        user = None
        lookups: list[float] = []
        try:
            user = await self._authenticate(ws)
            if user is None:
                return
            c = canon(user)
            old = self.online.get(c)
            if old is not None:
                await old.close(4000, "sesión iniciada en otro sitio")
            self.online[c] = ws
            await _send(ws, type="welcome", user=user)
            log.info("%s conectado (%d en línea)", user, len(self.online))
            await self._flush_queue(c, ws)
            await self._presence(c, True)

            async for raw in ws:
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "send":
                    await self._relay(ws, user, msg)
                elif t in ("lookup", "bundle"):
                    now = time.monotonic()
                    lookups[:] = [x for x in lookups if now - x < 60] + [now]
                    if len(lookups) > LOOKUP_LIMIT:
                        await _send(ws, type="error", code="rate_limited", id=msg.get("id"),
                                    message="demasiadas búsquedas, espera un momento")
                    elif t == "lookup":
                        await _send(ws, type="lookup", id=msg.get("id"), **self._lookup(msg.get("user")))
                    else:
                        await _send(ws, type="bundle", id=msg.get("id"), **self._bundle(msg.get("user")))
                elif t == "prekey":
                    await self._store_prekey(ws, c, msg)
                elif t == "who":
                    await _send(ws, type="who", users=sorted(self.registry[x]["name"] for x in self.online))
                else:
                    await _send(ws, type="error", code="unknown_type", message="tipo desconocido")
        except (CryptoError, ValueError, KeyError, TypeError, TimeoutError, json.JSONDecodeError):
            if user is None:
                await _send(ws, type="error", code="auth_failed", message="autenticación fallida")
            else:
                await _send(ws, type="error", code="bad_request", message="petición inválida")
        except ConnectionClosed:
            pass
        finally:
            if user and self.online.get(canon(user)) is ws:
                del self.online[canon(user)]
                log.info("%s desconectado", user)
                await self._presence(canon(user), False)

    async def _presence(self, c: str, online: bool) -> None:
        """Avisa a quien ha hablado con este usuario de que entra o sale.

        Los clientes descartan entonces la sesión en vivo con él y negocian otra:
        al recargar la página, el estado de la sesión se pierde.
        """
        name = self.registry[c]["name"]
        for other in self.related.get(c, ()):
            if other in self.online:
                await _send(self.online[other], type="presence", user=name, online=online)

    # ------------------------------------------------------------ directorio

    def _lookup(self, name) -> dict:
        """¿Existe el usuario? Devuelve su grafía oficial y si está conectado."""
        if not isinstance(name, str) or not USERNAME_RE.match(name):
            return {"exists": False, "user": None, "online": False}
        known = self.registry.get(canon(name))
        if known is None:
            return {"exists": False, "user": None, "online": False}
        return {"exists": True, "user": known["name"], "online": canon(name) in self.online}

    def _bundle(self, name) -> dict:
        """Prekey firmada de un usuario, para escribirle aunque no esté conectado."""
        info = self._lookup(name)
        if not info["exists"]:
            return info
        r = self.registry[canon(name)]
        return {**info, "identity_key": b64e(r["key"]), "prekey": r["bundle"]}

    async def _store_prekey(self, ws: ServerConnection, c: str, msg: dict) -> None:
        r = self.registry[c]
        spk, created = b64d(msg["spk"]), int(msg["created"])
        verify_signature(r["key"], spk_message(r["name"], spk, created), b64d(msg["sig"]))
        if len(spk) != 32:
            raise ValueError("prekey inválida")
        bundle = {"spk": msg["spk"], "sig": msg["sig"], "created": created}
        if r["bundle"] != bundle:
            r["bundle"] = bundle
            self._save()

    # --------------------------------------------------------------- reenvío

    async def _relay(self, ws: ServerConnection, sender: str, msg: dict) -> None:
        to, payload, rid = msg.get("to"), msg.get("payload"), msg.get("id")
        if not isinstance(to, str) or not isinstance(payload, dict) or canon(to) not in self.registry:
            await _send(ws, type="error", code="no_user", to=to, id=rid, message=f"el usuario '{to}' no existe")
            return
        ct, cs = canon(to), canon(sender)
        self.related.setdefault(ct, set()).add(cs)
        self.related.setdefault(cs, set()).add(ct)
        # El remitente lo pone el servidor a partir de la sesión autenticada,
        # nunca se copia de lo que diga el cliente.
        target = self.online.get(ct)
        if target is not None:
            try:
                await target.send(json.dumps({"type": "deliver", "from": sender, "payload": payload}))
                if rid is not None:
                    await _send(ws, type="ack", id=rid, status="delivered")
                return
            except ConnectionClosed:
                pass
        if payload.get("kind") != "sealed":
            # Los mensajes de sesión en vivo no sirven de nada en diferido.
            await _send(ws, type="error", code="offline", to=to, id=rid, message=f"'{to}' no está conectado")
            return
        self._enqueue(ct, {"from": sender, "payload": payload, "at": int(time.time())})
        if rid is not None:
            await _send(ws, type="ack", id=rid, status="queued")

    def _enqueue(self, c: str, item: dict) -> None:
        now = int(time.time())
        q = [x for x in self.queues.get(c, []) if now - x["at"] < QUEUE_TTL] + [item]
        while len(q) > QUEUE_MAX_MSGS or sum(len(json.dumps(x["payload"])) for x in q) > QUEUE_MAX_BYTES:
            q.pop(0)  # se descartan los más antiguos
        self.queues[c] = q
        self._save_queue(c)

    async def _flush_queue(self, c: str, ws: ServerConnection) -> None:
        q = self.queues.pop(c, [])
        if not q:
            return
        for item in q:
            self.related.setdefault(c, set()).add(canon(item["from"]))
            self.related.setdefault(canon(item["from"]), set()).add(c)
            await ws.send(json.dumps({"type": "deliver", "from": item["from"], "payload": item["payload"],
                                      "queued_at": item["at"]}))
        self._save_queue(c)
        log.info("entregados %d mensajes en espera a %s", len(q), self.registry[c]["name"])


async def _send(ws: ServerConnection, **msg) -> None:
    try:
        await ws.send(json.dumps(msg))
    except ConnectionClosed:
        pass


async def run(host: str, port: int, db: Path | None = None, tls: ssl.SSLContext | None = None,
              queue_dir: Path | None = None, tls_port: int | None = None,
              relay: RelayServer | None = None) -> None:
    """Arranca la web + relay. Con `tls` y `tls_port` sirve además HTTPS en otro puerto."""
    server = relay or RelayServer(db, queue_dir)
    servers = [await serve(server.handler, host, port, max_size=MAX_FRAME,
                           process_request=serve_static, ssl=None if tls_port else tls)]
    if tls and tls_port:
        servers.append(await serve(server.handler, host, tls_port, max_size=MAX_FRAME,
                                   process_request=serve_static, ssl=tls))
    for s in servers:
        s.relay = server  # para que /config.json sepa si hace falta código
    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    log.info("web y relay en %s://%s:%d", "https" if tls and not tls_port else "http", shown, port)
    if tls and tls_port:
        log.info("web y relay en https://%s:%d", shown, tls_port)
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main() -> None:
    p = argparse.ArgumentParser(
        description="Servidor de SecureChat para uso local o en tu red (Wi-Fi). "
                    "No está pensado para exponerse a internet.")
    p.add_argument("--lan", action="store_true",
                   help="acepta conexiones de otros equipos de tu red local (por defecto, solo este equipo)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--db", type=Path, default=Path("server_users.json"),
                   help="fichero donde guardar el registro nombre -> clave pública")
    p.add_argument("--queue", type=Path, default=Path("server_queue"),
                   help="carpeta donde guardar los mensajes cifrados en espera")
    p.add_argument("--code", help="código de acceso (por defecto se genera uno al arrancar)")
    p.add_argument("--no-code", action="store_true", help="no pedir código de acceso")
    p.add_argument("--cert", type=Path, help="certificado TLS (PEM) para servir por HTTPS")
    p.add_argument("--key", type=Path, help="clave privada TLS (PEM)")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    tls = None
    if args.cert:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)
    code = None if args.no_code else (args.code or new_access_code())
    host = "0.0.0.0" if args.lan else "127.0.0.1"
    print_banner(args.port, code, args.lan, bool(tls))
    relay = RelayServer(args.db, args.queue, code)
    try:
        asyncio.run(run(host, args.port, relay=relay, tls=tls))
    except KeyboardInterrupt:
        pass


def local_ips() -> list[str]:
    import socket
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))  # no envía nada: solo elige la interfaz de salida
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(ips)


def print_banner(port: int, code: str | None, lan: bool, tls: bool) -> None:
    scheme = "https" if tls else "http"
    lines = ["", "  SecureChat - servidor local", "  " + "-" * 40,
             f"  En este equipo:    {scheme}://localhost:{port}"]
    if lan:
        lines += [f"  En tu red (Wi-Fi): {scheme}://{ip}:{port}" for ip in local_ips()]
    else:
        lines.append("  (solo este equipo; usa --lan para tu red Wi-Fi)")
    lines.append(f"  Código de acceso:  {code}" if code else "  Sin código de acceso")
    if code:
        lines.append("  Dáselo solo a quien quieras dejar entrar.")
    print("\n".join(lines + [""]), flush=True)


if __name__ == "__main__":
    main()
