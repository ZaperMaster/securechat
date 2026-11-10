"""Servidor relay.

Solo hace tres cosas:
  1. Autentica a cada cliente con un reto firmado por su clave Ed25519.
  2. Recuerda qué clave pública corresponde a cada nombre (TOFU), para que nadie
     pueda conectarse con el nombre de otro y recibir sus mensajes.
  3. Reenvía bytes opacos entre usuarios conectados.

Nunca ve el texto de los mensajes ni posee claves capaces de descifrarlos.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
from pathlib import Path

import mimetypes
import ssl

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


WEB_DIR = Path(__file__).resolve().parent.parent / "web"
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


def serve_static(connection: ServerConnection, request: Request) -> Response | None:
    """Sirve la web estática. Las peticiones WebSocket siguen su camino (None)."""
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return None
    path = request.path.split("?", 1)[0]
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


def canon(name: str) -> str:
    """Clave interna de un usuario: sin distinguir mayúsculas."""
    return name.lower()


class RelayServer:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path
        # canon(nombre) -> (nombre tal y como se registró, clave pública)
        self.registry: dict[str, tuple[str, bytes]] = {}
        self.online: dict[str, ServerConnection] = {}  # canon(nombre) -> conexión
        if db_path and db_path.exists():
            for name, v in json.loads(db_path.read_text(encoding="utf-8")).items():
                if isinstance(v, str):  # formato antiguo: {"nombre": "clave"}
                    v = {"name": name, "key": v}
                self.registry[canon(v["name"])] = (v["name"], b64d(v["key"]))

    def _save(self) -> None:
        if not self.db_path:
            return
        tmp = self.db_path.with_suffix(".tmp")
        data = {c: {"name": n, "key": b64e(k)} for c, (n, k) in self.registry.items()}
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.db_path)

    async def _authenticate(self, ws: ServerConnection) -> str | None:
        hello = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
        user, key = hello.get("user", ""), b64d(hello.get("identity_key", ""))
        if hello.get("type") != "hello" or not USERNAME_RE.match(user) or len(key) != 32:
            await _send(ws, type="error", code="bad_hello", message=f"nombre inválido ({USERNAME_HELP})")
            return None
        nonce = nacl.utils.random(32)
        await _send(ws, type="challenge", nonce=b64e(nonce))
        reply = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
        verify_signature(key, auth_message(nonce, user), b64d(reply.get("sig", "")))

        known = self.registry.get(canon(user))
        if known is None:
            self.registry[canon(user)] = (user, key)
            self._save()
            log.info("nuevo usuario registrado: %s", user)
            return user
        if known[1] != key:
            await _send(ws, type="error", code="name_taken",
                        message="ese nombre de usuario ya está en uso")
            return None
        return known[0]  # siempre con la grafía con la que se registró

    async def handler(self, ws: ServerConnection) -> None:
        user = None
        lookups: list[float] = []
        try:
            user = await self._authenticate(ws)
            if user is None:
                return
            old = self.online.get(canon(user))
            if old is not None:
                await old.close(4000, "sesión iniciada en otro sitio")
            self.online[canon(user)] = ws
            await _send(ws, type="welcome", user=user)
            log.info("%s conectado (%d en línea)", user, len(self.online))

            async for raw in ws:
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "send":
                    await self._relay(ws, user, msg)
                elif t == "lookup":
                    now = asyncio.get_running_loop().time()
                    lookups[:] = [x for x in lookups if now - x < 60] + [now]
                    if len(lookups) > LOOKUP_LIMIT:
                        await _send(ws, type="error", code="rate_limited", id=msg.get("id"),
                                    message="demasiadas búsquedas, espera un momento")
                        continue
                    await _send(ws, type="lookup", id=msg.get("id"), **self._lookup(msg.get("user")))
                elif t == "who":
                    await _send(ws, type="who", users=sorted(self.registry[c][0] for c in self.online))
                else:
                    await _send(ws, type="error", code="unknown_type", message="tipo desconocido")
        except (CryptoError, ValueError, KeyError, TimeoutError, json.JSONDecodeError):
            await _send(ws, type="error", code="auth_failed", message="autenticación fallida")
        except ConnectionClosed:
            pass
        finally:
            if user and self.online.get(canon(user)) is ws:
                del self.online[canon(user)]
                log.info("%s desconectado", user)

    def _lookup(self, name) -> dict:
        """¿Existe el usuario? Devuelve su grafía oficial y si está conectado.

        No devuelve la clave pública: la clave se obtiene en el handshake, firmada.
        """
        if not isinstance(name, str) or not USERNAME_RE.match(name):
            return {"exists": False, "user": None, "online": False}
        known = self.registry.get(canon(name))
        if known is None:
            return {"exists": False, "user": None, "online": False}
        return {"exists": True, "user": known[0], "online": canon(name) in self.online}

    async def _relay(self, ws: ServerConnection, sender: str, msg: dict) -> None:
        to, payload = msg.get("to"), msg.get("payload")
        target = self.online.get(canon(to)) if isinstance(to, str) else None
        if target is None or not isinstance(payload, dict):
            await _send(ws, type="error", code="offline", to=to,
                        message=f"'{to}' no está conectado")
            return
        # El remitente lo pone el servidor a partir de la sesión autenticada,
        # nunca se copia de lo que diga el cliente.
        try:
            await _send(target, type="deliver", **{"from": sender}, payload=payload)
        except ConnectionClosed:
            await _send(ws, type="error", code="offline", to=to,
                        message=f"'{to}' no está conectado")


async def _send(ws: ServerConnection, **msg) -> None:
    try:
        await ws.send(json.dumps(msg))
    except ConnectionClosed:
        pass


async def run(host: str, port: int, db: Path | None, tls: ssl.SSLContext | None = None) -> None:
    server = RelayServer(db)
    async with serve(server.handler, host, port, max_size=MAX_FRAME,
                     process_request=serve_static, ssl=tls) as ws_server:
        scheme = "https" if tls else "http"
        shown = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
        log.info("web y relay en %s://%s:%d", scheme, shown, port)
        await ws_server.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(description="Servidor relay de SecureChat")
    p.add_argument("--host", default="127.0.0.1",
                   help="usa 0.0.0.0 para aceptar conexiones de otros equipos de tu red")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--db", type=Path, default=Path("server_users.json"),
                   help="fichero donde guardar el registro nombre -> clave pública")
    p.add_argument("--cert", type=Path, help="certificado TLS (PEM) para servir por HTTPS")
    p.add_argument("--key", type=Path, help="clave privada TLS (PEM)")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    tls = None
    if args.cert:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)
    try:
        asyncio.run(run(args.host, args.port, args.db, tls))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
