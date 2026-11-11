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
from .ratchet import DEVICE_RE, spk_message
from .push import MAX_SUBS, Pusher, valid_subscription
from .email_verify import CODE_TTL, MAX_TRIES, EmailHasher, mask, new_code, normalize_email, valid_email

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
KEYSTORE_LIMIT = 10    # descargas de copias de clave por IP y minuto

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
    relay = getattr(connection.server, "relay", None)
    if path == "/keystore" and relay is not None:
        return relay.keystore_response(connection, request)
    if path == "/config.json":  # la web pregunta si este servidor pide código de acceso
        body = json.dumps({"push_key": relay.pusher.public_key if relay else None,
                           "code_required": bool(relay and relay.access_code),
                           "email_required": bool(relay and relay.email_sender)}).encode()
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


MAX_DEVICES = 6
MAX_OPKS = 100


# Estado que ven los demás: en línea, ausente o invisible (aparece desconectado)
STATUSES = ("online", "away", "invisible")


class RelayServer:
    def __init__(self, db_path: Path | None = None, queue_dir: Path | None = None,
                 access_code: str | None = None, email_sender=None):
        self.db_path = db_path
        self.queue_dir = queue_dir
        # Con email_sender, las cuentas nuevas deben confirmar un correo (anti-bots)
        self.email_sender = email_sender
        self.email_hash = EmailHasher(db_path.with_name(db_path.stem + "_secret.key") if db_path else None)
        self.pusher = Pusher(db_path.with_name(db_path.stem + "_vapid.pem") if db_path else None)
        # Si hay código, solo entra quien lo conozca (el dueño se lo da a sus amigos)
        self.access_code = normalize_code(access_code) or None
        self._code_fails: dict[str, list[float]] = {}
        self._keystore_hits: dict[str, list[float]] = {}
        # canon(nombre) -> {"name", "key", "devices": {id: {"bundle", "opks", "seen"}}, ...}
        self.registry: dict[str, dict] = {}
        self.online: dict[str, dict[str, ServerConnection]] = {}  # canon -> {dispositivo: conexión}
        self.queues: dict[str, list[dict]] = {}                   # "canon|dispositivo" -> sobres
        self.related: dict[str, set[str]] = {}                    # con quién ha hablado cada uno
        if db_path and db_path.exists():
            for name, v in json.loads(db_path.read_text(encoding="utf-8")).items():
                if isinstance(v, str):  # formato antiguo: {"nombre": "clave"}
                    v = {"name": name, "key": v}
                self.registry[canon(v["name"])] = {
                    "name": v["name"], "key": b64d(v["key"]), "email": v.get("email"),
                    "keystore": v.get("keystore"), "last_seen": v.get("last_seen"),
                    "hide_last_seen": v.get("hide_last_seen", False), "push": v.get("push", []),
                    "status": v.get("status", "online"),
                    "devices": v.get("devices", {})}
        if queue_dir and queue_dir.exists():
            for f in queue_dir.glob("*__*.json"):
                c, dev = f.stem.split("__", 1)
                self.queues[f"{c}|{dev}"] = json.loads(f.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ persistencia

    def _save(self) -> None:
        if not self.db_path:
            return
        data = {c: {"name": r["name"], "key": b64e(r["key"]), "email": r.get("email"),
                    "keystore": r.get("keystore"), "last_seen": r.get("last_seen"),
                    "hide_last_seen": r.get("hide_last_seen", False), "push": r.get("push", []),
                    "status": r.get("status", "online"),
                    "devices": r.get("devices", {})}
                for c, r in self.registry.items()}
        tmp = self.db_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.db_path)

    def _save_queue(self, qk: str) -> None:
        if not self.queue_dir:
            return
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        f = self.queue_dir / (qk.replace("|", "__") + ".json")
        if self.queues.get(qk):
            tmp = f.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.queues[qk]), encoding="utf-8")
            os.replace(tmp, f)
        elif f.exists():
            f.unlink()

    # ------------------------------------------------------------ conexión

    async def _authenticate(self, ws: ServerConnection) -> tuple[str, str] | None:
        hello = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
        user, key = hello.get("user", ""), b64d(hello.get("identity_key", ""))
        device = hello.get("device")
        if hello.get("type") != "hello" or not USERNAME_RE.match(user) or len(key) != 32:
            await _send(ws, type="error", code="bad_hello", message=f"nombre inválido ({USERNAME_HELP})")
            return None
        if not isinstance(device, str) or not DEVICE_RE.match(device):
            await _send(ws, type="error", code="old_client",
                        message="tu app está desactualizada: recarga la página para usar la versión nueva")
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
            email_hash = None
            if self.email_sender:
                email_hash = await self._verify_email(ws, hello.get("email"))
                if email_hash is None:
                    return None
                if canon(user) in self.registry:  # alguien lo registró mientras tanto
                    await _send(ws, type="error", code="name_taken", message="ese nombre de usuario ya está en uso")
                    return None
            known = self.registry[canon(user)] = {"name": user, "key": key, "email": email_hash, "devices": {}}
            log.info("nuevo usuario registrado: %s", user)
        elif known["key"] != key:
            await _send(ws, type="error", code="name_taken", message="ese nombre de usuario ya está en uso")
            return None
        # Dispositivo: se registra (máximo MAX_DEVICES; se olvida el que lleve más sin conectarse)
        devs = known.setdefault("devices", {})
        if device not in devs:
            while len(devs) >= MAX_DEVICES:
                oldest = min(devs, key=lambda d: devs[d].get("seen", 0))
                self._forget_device(canon(user), oldest)
            devs[device] = {"bundle": None, "opks": [], "seen": int(time.time())}
        devs[device]["seen"] = int(time.time())
        self._save()
        return known["name"], device

    def _forget_device(self, c: str, device: str) -> None:
        self.registry[c].get("devices", {}).pop(device, None)
        qk = f"{c}|{device}"
        if self.queues.pop(qk, None) is not None:
            self._save_queue(qk)

    async def _verify_email(self, ws: ServerConnection, email) -> str | None:
        """Envía un código al correo y espera a que el usuario lo escriba."""
        if not valid_email(email):
            await _send(ws, type="error", code="email_required",
                        message="para crear una cuenta en este servidor hace falta un correo válido")
            return None
        email = normalize_email(email)
        h = self.email_hash(email)
        if any(r.get("email") == h for r in self.registry.values()):
            await _send(ws, type="error", code="email_used", message="ese correo ya tiene una cuenta")
            return None
        code = new_code()
        try:
            await self.email_sender.send(email, code)
        except Exception:  # noqa: BLE001 - cualquier fallo de SMTP
            log.exception("no se pudo enviar el correo")
            await _send(ws, type="error", code="email_failed",
                        message="el servidor no pudo enviar el correo; avisa a quien lo gestiona")
            return None
        await _send(ws, type="verify_needed", to=mask(email))
        deadline = time.monotonic() + CODE_TTL
        for left in range(MAX_TRIES - 1, -1, -1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            msg = json.loads(await asyncio.wait_for(ws.recv(), remaining))
            if msg.get("type") == "verify" and hmac.compare_digest(str(msg.get("code", "")).strip(), code):
                return h
            if left:
                await _send(ws, type="verify_failed", left=left, message=f"código incorrecto, te quedan {left} intentos")
        await _send(ws, type="error", code="verify_failed", message="no se pudo verificar el correo; vuelve a intentarlo")
        return None

    async def handler(self, ws: ServerConnection) -> None:
        user = device = None
        lookups: list[float] = []
        try:
            auth = await self._authenticate(ws)
            if auth is None:
                return
            user, device = auth
            c = canon(user)
            mine = self.online.setdefault(c, {})
            old = mine.get(device)
            if old is not None:  # el mismo dispositivo se conecta otra vez (otra pestaña)
                await old.close(4000, "sesión iniciada en otro sitio")
            first = not mine
            mine[device] = ws
            r = self.registry[c]
            await _send(ws, type="welcome", user=user, device=device,
                        devices=[d for d in r["devices"] if d != device],
                        opks=len(r["devices"][device].get("opks", [])))
            log.info("%s conectado desde %s (%d en línea)", user, device, len(self.online))
            await self._flush_queue(c, device, ws)
            # Mis otros dispositivos se enteran de que existe este (para mandarle copias)
            for d, conn in list(mine.items()):
                if d != device:
                    await _send(conn, type="my-devices", devices=[x for x in r["devices"] if x != d])
            if first and r.get("status") != "invisible":
                await self._presence(c, True)

            async for raw in ws:
                msg = json.loads(raw)
                t = msg.get("type")
                if t == "send":
                    await self._relay(ws, user, device, msg)
                elif t in ("lookup", "bundle"):
                    now = time.monotonic()
                    lookups[:] = [x for x in lookups if now - x < 60] + [now]
                    if len(lookups) > LOOKUP_LIMIT:
                        await _send(ws, type="error", code="rate_limited", id=msg.get("id"),
                                    message="demasiadas búsquedas, espera un momento")
                    elif t == "lookup":
                        await _send(ws, type="lookup", id=msg.get("id"), **self._lookup(msg.get("user")))
                    else:
                        await _send(ws, type="bundle", id=msg.get("id"), **self._bundle(msg.get("user"), c))
                elif t == "prekeys":
                    try:
                        n = self._store_prekeys(c, device, msg)
                        await _send(ws, type="prekeys_ok", id=msg.get("id"), opks=n)
                    except (ValueError, KeyError, TypeError, CryptoError) as exc:
                        await _send(ws, type="error", code="bad_prekeys", id=msg.get("id"), message=str(exc))
                elif t == "devices":
                    devs = self.registry[c]["devices"]
                    await _send(ws, type="devices", id=msg.get("id"), current=device,
                                devices=[{"device": d, "seen": v.get("seen"), "online": d in self.online.get(c, {})}
                                         for d, v in devs.items()])
                elif t == "remove-device":
                    d = msg.get("device")
                    if isinstance(d, str) and d != device and d in self.registry[c]["devices"]:
                        conn = self.online.get(c, {}).get(d)
                        if conn is not None:
                            await conn.close(4001, "dispositivo desvinculado")
                        self._forget_device(c, d)
                        self._save()
                    await _send(ws, type="ack", id=msg.get("id"), status="ok")
                elif t == "push-sub":
                    sub = msg.get("sub")
                    if valid_subscription(sub):
                        subs = [x for x in self.registry[c].get("push", []) if x["endpoint"] != sub["endpoint"]]
                        self.registry[c]["push"] = (subs + [sub])[-MAX_SUBS:]
                        self._save()
                elif t == "push-unsub":
                    subs = self.registry[c].get("push", [])
                    self.registry[c]["push"] = [x for x in subs if x["endpoint"] != msg.get("endpoint")]
                    self._save()
                elif t == "privacy":
                    reg = self.registry[c]
                    hide = not bool(msg.get("last_seen", True))
                    changed = reg.get("hide_last_seen") != hide
                    reg["hide_last_seen"] = hide
                    status = msg.get("status")
                    if status in STATUSES and reg.get("status", "online") != status:
                        if status == "invisible":
                            # Para los demás, se acaba de desconectar
                            reg["last_seen"] = int(time.time())
                        reg["status"] = status
                        changed = True
                        await self._presence(c, status != "invisible")
                    if changed:
                        self._save()
                elif t == "keystore":
                    try:
                        self._store_keystore(c, msg.get("blob"))
                    except (ValueError, KeyError, TypeError, CryptoError) as exc:
                        await _send(ws, type="error", code="bad_keystore", message=str(exc))
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
            if user:
                c = canon(user)
                mine = self.online.get(c, {})
                if mine.get(device) is ws:
                    del mine[device]
                    if c in self.registry and device in self.registry[c].get("devices", {}):
                        self.registry[c]["devices"][device]["seen"] = int(time.time())
                    log.info("%s desconectado de %s", user, device)
                    if not mine:
                        self.online.pop(c, None)
                        if self.registry[c].get("status") != "invisible":
                            # Invisible: la última conexión se queda donde estaba
                            self.registry[c]["last_seen"] = int(time.time())
                            self._save()
                            await self._presence(c, False)

    async def _presence(self, c: str, online: bool) -> None:
        """Avisa a quien ha hablado con este usuario de que entra o sale."""
        r = self.registry[c]
        last = None if online or r.get("hide_last_seen") else r.get("last_seen")
        away = online and r.get("status") == "away"
        for other in self.related.get(c, ()):
            for conn in list(self.online.get(other, {}).values()):
                await _send(conn, type="presence", user=r["name"], online=online, away=away, last_seen=last)

    # ------------------------------------------------------------ directorio

    def _lookup(self, name) -> dict:
        """¿Existe el usuario? Devuelve su grafía oficial y si está conectado."""
        if not isinstance(name, str) or not USERNAME_RE.match(name):
            return {"exists": False, "user": None, "online": False}
        known = self.registry.get(canon(name))
        if known is None:
            return {"exists": False, "user": None, "online": False}
        status = known.get("status", "online")
        online = bool(self.online.get(canon(name))) and status != "invisible"
        info = {"exists": True, "user": known["name"], "online": online, "away": online and status == "away"}
        if not online and not known.get("hide_last_seen") and known.get("last_seen"):
            info["last_seen"] = known["last_seen"]
        return info

    def _bundle(self, name, asker: str) -> dict:
        """Prekeys de cada dispositivo de un usuario. Entrega (y borra) una OPK por dispositivo."""
        info = self._lookup(name)
        if not info["exists"]:
            return info
        c = canon(name)
        r = self.registry[c]
        devices = []
        for d, v in r.get("devices", {}).items():
            if not v.get("bundle"):
                continue
            opks = v.get("opks", [])
            devices.append({"device": d, **v["bundle"], "opk": opks.pop(0) if opks else None})
        self._save()
        self.related.setdefault(c, set()).add(asker)
        self.related.setdefault(asker, set()).add(c)
        return {**info, "identity_key": b64e(r["key"]), "devices": devices}

    def _store_prekeys(self, c: str, device: str, msg: dict) -> int:
        r = self.registry[c]
        spk, created = b64d(msg["spk"]), int(msg["created"])
        if len(spk) != 32:
            raise ValueError("prekey inválida")
        verify_signature(r["key"], spk_message(r["name"], device, spk, created), b64d(msg["sig"]))
        d = r["devices"][device]
        d["bundle"] = {"spk": msg["spk"], "sig": msg["sig"], "created": created}
        new = [k for k in msg.get("opks", []) if isinstance(k, str) and len(b64d(k)) == 32]
        known = set(d.get("opks", []))
        d["opks"] = (d.get("opks", []) + [k for k in new if k not in known])[-MAX_OPKS:]
        self._save()
        return len(d["opks"])

    # --------------------------------------------- copia cifrada de la clave

    def _store_keystore(self, c: str, blob) -> None:
        """Guarda la clave del usuario CIFRADA con su contraseña (Argon2id + XSalsa20).

        Sirve para iniciar sesión desde otro dispositivo. El servidor no puede abrirla;
        solo comprueba que es la clave de esta cuenta (misma clave pública).
        """
        r = self.registry[c]
        if not isinstance(blob, dict) or len(json.dumps(blob)) > 4096:
            raise ValueError("copia de clave inválida")
        required = {"version", "kdf", "opslimit", "memlimit", "salt", "public_key", "ciphertext"}
        if not required <= blob.keys() or b64d(blob["public_key"]) != r["key"]:
            raise ValueError("copia de clave inválida")
        if blob.get("opslimit", 0) < 2 or blob.get("memlimit", 0) < 32 * 1024 * 1024:
            raise ValueError("parámetros de Argon2id demasiado débiles")
        clean = {k: blob[k] for k in sorted(required | {"username"}) if k in blob}
        if r.get("keystore") != clean:
            r["keystore"] = clean
            self._save()

    def keystore_response(self, connection: ServerConnection, request: Request) -> Response:
        """GET /keystore?user=NOMBRE[&code=CODIGO]: copia cifrada para iniciar sesión.

        Cualquiera que la descargue podría intentar adivinar la contraseña sin conexión,
        así que se limita el ritmo por IP y, si el servidor tiene código, se exige.
        """
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(request.path).query)
        ip = (connection.remote_address or ("?",))[0]
        if ip in ("127.0.0.1", "::1"):
            ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", ip).split(",")[0].strip()
        now = time.monotonic()
        hits = self._keystore_hits[ip] = [t for t in self._keystore_hits.get(ip, []) if now - t < 60] + [now]
        if len(hits) > KEYSTORE_LIMIT:
            return _response(429, "Too Many Requests", b'{"error": "demasiados intentos, espera un minuto"}',
                             "application/json")
        if self.access_code and not hmac.compare_digest(normalize_code(q.get("code", [""])[0]), self.access_code):
            return _response(403, "Forbidden", b'{"error": "codigo de acceso incorrecto"}', "application/json")
        name = q.get("user", [""])[0]
        r = self.registry.get(canon(name)) if USERNAME_RE.match(name) else None
        if not r or not r.get("keystore"):
            return _response(404, "Not Found", b'{"error": "no encontrada"}', "application/json")
        body = json.dumps({"user": r["name"], "blob": r["keystore"]}).encode()
        return _response(200, "OK", body, "application/json")

    # --------------------------------------------------------------- reenvío

    async def _relay(self, ws: ServerConnection, sender: str, sender_dev: str, msg: dict) -> None:
        """Entrega un sobre cifrado a UN dispositivo concreto (o lo guarda si no está)."""
        to, device, payload, rid = msg.get("to"), msg.get("device"), msg.get("payload"), msg.get("id")
        ct, cs = canon(to) if isinstance(to, str) else "", canon(sender)
        if ct not in self.registry or not isinstance(payload, dict):
            await _send(ws, type="error", code="no_user", to=to, id=rid, message=f"el usuario '{to}' no existe")
            return
        devices = list(self.registry[ct].get("devices", {}))
        if device not in devices:
            await _send(ws, type="error", code="no_device", to=to, id=rid, devices=devices,
                        message="ese dispositivo ya no existe")
            return
        if ct != cs:
            self.related.setdefault(ct, set()).add(cs)
            self.related.setdefault(cs, set()).add(ct)
        # El remitente lo pone el servidor a partir de la sesión autenticada,
        # nunca se copia de lo que diga el cliente.
        target = self.online.get(ct, {}).get(device)
        if target is not None:
            try:
                await target.send(json.dumps({"type": "deliver", "from": sender, "payload": payload}))
                await _send(ws, type="ack", id=rid, status="delivered", devices=devices)
                return
            except ConnectionClosed:
                pass
        if msg.get("ephemeral"):  # "escribiendo…": si no está, se descarta
            await _send(ws, type="ack", id=rid, status="dropped", devices=devices)
            return
        self._enqueue(f"{ct}|{device}", {"from": sender, "payload": payload, "at": int(time.time())})
        # Aviso al móvil (sin contenido) si no tiene ningún dispositivo conectado
        if not msg.get("silent") and ct != cs and not self.online.get(ct) and self.registry[ct].get("push"):
            asyncio.get_running_loop().create_task(self._push(ct))
        await _send(ws, type="ack", id=rid, status="queued", devices=devices)

    async def _push(self, c: str) -> None:
        r = self.registry.get(c)
        if not r:
            return
        alive = await self.pusher.notify(c, r.get("push", []))
        if len(alive) != len(r.get("push", [])):
            r["push"] = alive
            self._save()

    def _enqueue(self, qk: str, item: dict) -> None:
        now = int(time.time())
        q = [x for x in self.queues.get(qk, []) if now - x["at"] < QUEUE_TTL] + [item]
        while len(q) > QUEUE_MAX_MSGS or sum(len(json.dumps(x["payload"])) for x in q) > QUEUE_MAX_BYTES:
            q.pop(0)  # se descartan los más antiguos
        self.queues[qk] = q
        self._save_queue(qk)

    async def _flush_queue(self, c: str, device: str, ws: ServerConnection) -> None:
        qk = f"{c}|{device}"
        q = self.queues.pop(qk, [])
        if not q:
            return
        for item in q:
            other = canon(item["from"])
            if other != c:
                self.related.setdefault(c, set()).add(other)
                self.related.setdefault(other, set()).add(c)
            await ws.send(json.dumps({"type": "deliver", "from": item["from"], "payload": item["payload"],
                                      "queued_at": item["at"]}))
        self._save_queue(qk)
        log.info("entregados %d mensajes en espera a %s (%s)", len(q), self.registry[c]["name"], device)


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
    p.add_argument("--email", action="store_true",
                   help="exigir verificación por correo al crear cuenta (SMTP en variables SECURECHAT_SMTP_*)")
    p.add_argument("--email-pruebas", action="store_true",
                   help="verificación por correo, pero el código se muestra en esta consola")
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
    sender = None
    if args.email_pruebas:
        from .email_verify import ConsoleSender
        sender = ConsoleSender()
    elif args.email:
        from .email_verify import SmtpSender
        sender = SmtpSender.from_env()
        if sender is None:
            p.error("--email necesita SECURECHAT_SMTP_HOST, _USER, _PASSWORD (y opcional _PORT, _FROM)")
    relay = RelayServer(args.db, args.queue, code, sender)
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
