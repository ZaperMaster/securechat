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
  6. Remitente oculto (sealed sender): por una conexión anónima entrega sobres en los
     que ni siquiera pone quién los manda, a quien demuestre tener la "clave de entrega"
     del destinatario (que este solo da a sus contactos).

Nunca ve el texto de los mensajes ni posee claves capaces de descifrarlos.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
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
from .ratchet import DEVICE_RE, KEM_PUB_BYTES, kem_message, spk_message
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
EMAIL_SENDS_PER_HOUR = 5
LOOKUP_LIMIT = 30  # búsquedas por minuto y conexión (frena la enumeración de usuarios)
PREVIEW_LIMIT = 20  # vistas previas de enlaces por minuto y conexión
MAX_FANOUT = 64 * 6   # destinos de un mensaje de grupo (64 miembros × 6 dispositivos)
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
    # Solo HTTPS durante un año (los navegadores la ignoran si se entra por http://localhost)
    "Strict-Transport-Security": "max-age=31536000",
    # La web solo puede usar cámara y micrófono (llamadas y notas de voz); nada de ubicación, etc.
    "Permissions-Policy": "camera=(self), microphone=(self), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CLOUD_MAX = 12 * 1024 * 1024  # copia cifrada de la cuenta (en base64)
CLOUD_INTERVAL = 20            # segundos mínimos entre copias de una cuenta
SEALED_LIMIT = 600          # envíos anónimos por minuto e IP
MAX_BLOCKED = 1000          # usuarios bloqueados por cuenta
REPORTS_PER_DAY = 10        # denuncias por cuenta y día
KEYSTORE_AUTH_FAILS = 10     # contraseñas incorrectas por cuenta antes de bloquear la descarga
KEYSTORE_LOCK = 15 * 60      # durante 15 minutos
VERIFY_EMAILS_PER_IP = 5     # correos de verificación por IP y hora (anti-spam)
VERIFY_EMAILS_PER_ADDR = 3   # y por dirección de correo


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


def real_ip(remote, headers) -> str:
    """IP del cliente. Detrás de un túnel local (cloudflared, Tailscale) todas las conexiones
    llegan desde 127.0.0.1, así que usamos la cabecera del túnel. De X-Forwarded-For se
    toma la ÚLTIMA dirección: es la que añade el túnel; las anteriores las puede inventar
    el cliente para saltarse los límites por IP."""
    ip = (remote or ("?",))[0]
    if ip in ("127.0.0.1", "::1") and headers is not None:
        cf = headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        fwd = [x.strip() for x in headers.get("X-Forwarded-For", "").split(",") if x.strip()]
        if fwd:
            return fwd[-1]
    return ip


def client_ip(ws: ServerConnection) -> str:
    return real_ip(ws.remote_address, ws.request.headers if ws.request is not None else None)


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
        self.pusher = Pusher(db_path.with_name(db_path.stem + "_vapid.pem") if db_path else None,
                             fcm_path=db_path.with_name(db_path.stem + "_fcm.json") if db_path else None)
        # Si hay código, solo entra quien lo conozca (el dueño se lo da a sus amigos)
        self.access_code = normalize_code(access_code) or None
        self._code_fails: dict[str, list[float]] = {}
        self._keystore_hits: dict[str, list[float]] = {}
        self._email_sends: dict[str, list[float]] = {}  # envíos de códigos por cuenta (límite por hora)
        self._verify_sends: dict[str, list[float]] = {}  # correos de alta por IP y por dirección
        self._keystore_fails: dict[str, list[float]] = {}  # contraseñas incorrectas por cuenta
        self._lookups: dict[str, list[float]] = {}  # búsquedas de usuarios por cuenta
        self._reports: dict[str, list[float]] = {}  # denuncias por cuenta (límite diario)
        self._sealed_hits: dict[str, list[float]] = {}  # envíos anónimos por IP
        self._cloud_mem: dict[str, tuple[str, int]] = {}  # copias en memoria (servidor sin base de datos)
        self._cloud_last: dict[str, float] = {}
        self.reports_path = db_path.with_name(db_path.stem + "_denuncias.jsonl") if db_path else None
        # Relé de llamadas (TURN): direcciones que se dan a los navegadores y secreto de sus credenciales
        self.turn_urls: list[str] = []
        self.turn_port: int | None = None
        self.turn_secret = secrets.token_bytes(32)
        # canon(nombre) -> {"name", "key", "devices": {id: {"bundle", "opks", "seen"}}, ...}
        self.registry: dict[str, dict] = {}
        self.online: dict[str, dict[str, ServerConnection]] = {}  # canon -> {dispositivo: conexión}
        self.queues: dict[str, list[dict]] = {}                   # "canon|dispositivo" -> sobres
        self.related: dict[str, set[str]] = {}                    # con quién ha hablado cada uno
        # Datos en SQLite (usuarios.db junto a donde antes iba usuarios.json, que se migra solo)
        self.store = None
        if db_path:
            from .storage import Store, migrate_legacy
            self.store = Store(db_path.with_suffix(".db"))
            migrate_legacy(self.store, db_path, queue_dir)
            for c, v in self.store.load_accounts().items():
                self.registry[canon(v["name"])] = self._from_row(v)
            self.queues = self.store.load_queues()

    # ------------------------------------------------------------ persistencia

    _FIELDS = ("email", "keystore", "keystore_auth", "last_seen", "recovery", "recovery_auth", "uak", "uak_epoch")

    @classmethod
    def _from_row(cls, v: dict) -> dict:
        r = {"name": v["name"], "key": b64d(v["key"]), **{k: v.get(k) for k in cls._FIELDS},
             "blocked": v.get("blocked", []), "hide_last_seen": v.get("hide_last_seen", False),
             "push": v.get("push", []), "status": v.get("status", "online"), "devices": v.get("devices", {})}
        return r

    @classmethod
    def _to_row(cls, r: dict) -> dict:
        return {"name": r["name"], "key": b64e(r["key"]), **{k: r.get(k) for k in cls._FIELDS},
                "blocked": r.get("blocked", []), "hide_last_seen": r.get("hide_last_seen", False),
                "push": r.get("push", []), "status": r.get("status", "online"), "devices": r.get("devices", {})}

    def _save(self) -> None:
        """Guarda en la base de datos las cuentas que han cambiado (en una transacción)."""
        if self.store:
            self.store.save_accounts({c: self._to_row(r) for c, r in self.registry.items()})

    def _save_queue(self, qk: str) -> None:
        if self.store:
            self.store.save_queue(qk, self.queues.get(qk, []))

    # ------------------------------------------------------------ conexión

    async def _check_code(self, ws: ServerConnection, hello: dict) -> bool:
        if not self.access_code:
            return True
        ip = client_ip(ws)
        now = time.monotonic()
        fails = self._code_fails[ip] = [t for t in self._code_fails.get(ip, []) if now - t < 60]
        if len(fails) >= CODE_FAILS_LIMIT:
            await _send(ws, type="error", code="too_many", message="demasiados intentos, espera un minuto")
            return False
        given = normalize_code(hello.get("code"))
        if not hmac.compare_digest(given, self.access_code):
            if given:  # solo cuenta como intento quien prueba un código (no quien no envía ninguno)
                fails.append(now)
            await _send(ws, type="error", code="bad_code",
                        message="código de acceso incorrecto: pídeselo a quien gestiona el servidor")
            return False
        return True

    async def _authenticate(self, ws: ServerConnection, hello: dict) -> tuple[str, str] | None:
        user, key = hello.get("user", ""), b64d(hello.get("identity_key", ""))
        device = hello.get("device")
        if hello.get("type") != "hello" or not USERNAME_RE.match(user) or len(key) != 32:
            await _send(ws, type="error", code="bad_hello", message=f"nombre inválido ({USERNAME_HELP})")
            return None
        if not isinstance(device, str) or not DEVICE_RE.match(device):
            await _send(ws, type="error", code="old_client",
                        message="tu app está desactualizada: recarga la página para usar la versión nueva")
            return None
        if not await self._check_code(ws, hello):
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
        # Que nadie use el servidor para llenar de correos la bandeja de otra persona
        now, ip = time.monotonic(), f"ip:{client_ip(ws)}"
        by_ip = [t for t in self._verify_sends.get(ip, []) if now - t < 3600]
        by_addr = [t for t in self._verify_sends.get(h, []) if now - t < 3600]
        if len(by_ip) >= VERIFY_EMAILS_PER_IP or len(by_addr) >= VERIFY_EMAILS_PER_ADDR:
            await _send(ws, type="error", code="too_many",
                        message="se han pedido demasiados códigos; espera un rato antes de volver a intentarlo")
            return None
        self._verify_sends[ip], self._verify_sends[h] = by_ip + [now], by_addr + [now]
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

    async def _start_email_change(self, ws: ServerConnection, c: str, msg: dict) -> dict | None:
        """Añadir o cambiar el correo de una cuenta ya creada: se manda un código al correo nuevo."""
        rid = msg.get("id")

        async def fail(code: str, message: str) -> None:
            await _send(ws, type="error", id=rid, code=code, message=message)

        if not self.email_sender:
            await fail("email_unavailable", "este servidor no tiene configurado el envío de correos")
            return None
        email = msg.get("email")
        if not valid_email(email):
            await fail("email_invalid", "ese correo no es válido")
            return None
        email = normalize_email(email)
        h = self.email_hash(email)
        if any(r.get("email") == h for k, r in self.registry.items() if k != c):
            await fail("email_used", "ese correo ya tiene una cuenta")
            return None
        now = time.monotonic()
        sends = self._email_sends[c] = [t for t in self._email_sends.get(c, []) if now - t < 3600] + [now]
        if len(sends) > EMAIL_SENDS_PER_HOUR:
            await fail("too_many", "has pedido demasiados códigos; espera un rato")
            return None
        code = new_code()
        try:
            await self.email_sender.send(email, code, purpose="change")
        except Exception:  # noqa: BLE001 - cualquier fallo de SMTP
            log.exception("no se pudo enviar el correo")
            await fail("email_failed", "el servidor no pudo enviar el correo; avisa a quien lo gestiona")
            return None
        await _send(ws, type="email-code-sent", id=rid, to=mask(email))
        return {"hash": h, "code": code, "deadline": now + CODE_TTL, "tries": MAX_TRIES}

    async def _finish_email_change(self, ws: ServerConnection, c: str, msg: dict, pending: dict | None) -> dict | None:
        rid = msg.get("id")
        if not pending or time.monotonic() > pending["deadline"]:
            await _send(ws, type="error", id=rid, code="code_expired", message="el código ha caducado; pide otro")
            return None
        if hmac.compare_digest(str(msg.get("code", "")).strip(), pending["code"]):
            if any(r.get("email") == pending["hash"] for k, r in self.registry.items() if k != c):
                await _send(ws, type="error", id=rid, code="email_used", message="ese correo ya tiene una cuenta")
                return None
            self.registry[c]["email"] = pending["hash"]
            self._save()
            log.info("%s ha vinculado un correo", self.registry[c]["name"])
            await _send(ws, type="email-ok", id=rid)
            return None
        pending["tries"] -= 1
        if pending["tries"] <= 0:
            await _send(ws, type="error", id=rid, code="code_expired", message="demasiados intentos; pide otro código")
            return None
        await _send(ws, type="error", id=rid, code="wrong_code",
                    message=f"código incorrecto, te quedan {pending['tries']} intentos")
        return pending

    async def handler(self, ws: ServerConnection) -> None:
        user = device = None
        previews: list[float] = []
        pending_email: dict | None = None  # cambio de correo a medias (código enviado)
        try:
            hello = json.loads(await asyncio.wait_for(ws.recv(), AUTH_TIMEOUT))
            if isinstance(hello, dict) and hello.get("type") == "anon-hello":
                await self._anon(ws, hello)
                return
            auth = await self._authenticate(ws, hello)
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
                        opks=len(r["devices"][device].get("opks", [])),
                        has_email=bool(r.get("email")), email_available=bool(self.email_sender),
                        blocked=[self.registry[b]["name"] for b in r.get("blocked", []) if b in self.registry],
                        uak_epoch=r.get("uak_epoch") if r.get("uak") else None)
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
                elif t == "send-many":
                    await self._relay_many(ws, user, msg)
                elif t in ("lookup", "bundle"):
                    now = time.monotonic()
                    # Por cuenta: abrir más conexiones no da más búsquedas
                    lookups = self._lookups[c] = [x for x in self._lookups.get(c, []) if now - x < 60] + [now]
                    if len(lookups) > LOOKUP_LIMIT:
                        await _send(ws, type="error", code="rate_limited", id=msg.get("id"),
                                    message="demasiadas búsquedas, espera un momento")
                    elif t == "lookup":
                        await _send(ws, type="lookup", id=msg.get("id"), **self._lookup(msg.get("user"), c))
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
                elif t == "turn":
                    if self.turn_urls:
                        from .turn import make_credentials
                        username, credential = make_credentials(self.turn_secret, c)
                        await _send(ws, type="turn", id=msg.get("id"), urls=self.turn_urls,
                                    username=username, credential=credential)
                    else:
                        await _send(ws, type="error", id=msg.get("id"), code="no_turn", message="sin relé de llamadas")
                elif t == "set-email":
                    pending_email = await self._start_email_change(ws, c, msg)
                elif t == "confirm-email":
                    pending_email = await self._finish_email_change(ws, c, msg, pending_email)
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
                        self._store_keystore(c, msg.get("blob"), msg.get("auth"))
                    except (ValueError, KeyError, TypeError, CryptoError) as exc:
                        await _send(ws, type="error", code="bad_keystore", message=str(exc))
                elif t == "set-uak":
                    # Mi clave de entrega (la que doy a mis contactos para que me escriban sin identificarse)
                    uak, epoch = msg.get("uak"), msg.get("epoch")
                    if isinstance(uak, str) and len(b64d(uak)) == 16 and isinstance(epoch, int) and 0 < epoch < 2**31:
                        self.registry[c]["uak"], self.registry[c]["uak_epoch"] = uak, epoch
                        self._save()
                        await _send(ws, type="ack", id=msg.get("id"), status="ok")
                        for d, conn in list(self.online.get(c, {}).items()):
                            if conn is not ws:
                                await _send(conn, type="uak", epoch=epoch)
                    else:
                        await _send(ws, type="error", id=msg.get("id"), code="bad_request", message="clave de entrega inválida")
                elif t in ("backup-put", "backup-get", "backup-delete"):
                    await self._cloud(ws, c, msg)
                elif t == "block":
                    await self._set_block(ws, c, msg)
                elif t == "report":
                    await self._report(ws, c, msg)
                elif t == "recovery":
                    try:
                        self._store_recovery(c, msg.get("blob"), msg.get("auth"))
                        await _send(ws, type="ack", id=msg.get("id"), status="ok")
                    except (ValueError, KeyError, TypeError, CryptoError) as exc:
                        await _send(ws, type="error", id=msg.get("id"), code="bad_recovery", message=str(exc))
                elif t == "recovery-delete":
                    self.registry[c].pop("recovery", None)
                    self.registry[c].pop("recovery_auth", None)
                    self._save()
                    await _send(ws, type="ack", id=msg.get("id"), status="ok")
                elif t == "preview":
                    now = time.monotonic()
                    previews[:] = [x for x in previews if now - x < 60] + [now]
                    if len(previews) > PREVIEW_LIMIT:
                        await _send(ws, type="error", code="rate_limited", id=msg.get("id"), message="demasiadas vistas previas")
                    else:
                        asyncio.create_task(self._preview(ws, msg))
                elif t == "delete-account":
                    # La conexión ya demostró tener la clave privada; además se firma la petición
                    # para que no baste con colar un mensaje en una sesión ajena abierta.
                    verify_signature(self.registry[c]["key"], b"securechat-delete-account|" + c.encode(),
                                     b64d(msg.get("sig", "")))
                    await _send(ws, type="ack", id=msg.get("id"), status="ok")
                    await self._delete_account(c)
                    return
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

    async def _cloud(self, ws: ServerConnection, c: str, msg: dict) -> None:
        """Copia de la cuenta (chats, grupos, contactos y ajustes) CIFRADA en el dispositivo con una
        clave que sale de la identidad. El servidor la guarda y la devuelve a la propia cuenta, nada más:
        no puede leerla. Sirve para que un dispositivo nuevo recupere todo al iniciar sesión."""
        t, rid = msg["type"], msg.get("id")
        if t == "backup-get":
            got = self.store.cloud_get(c) if self.store else self._cloud_mem.get(c)
            await _send(ws, type="backup", id=rid, data=got[0] if got else None, at=got[1] if got else None)
            return
        if t == "backup-delete":
            if self.store:
                self.store.cloud_delete(c)
            self._cloud_mem.pop(c, None)
            await _send(ws, type="ack", id=rid, status="ok")
            return
        data = msg.get("data")
        if not isinstance(data, str) or not data or len(data) > CLOUD_MAX:
            await _send(ws, type="error", id=rid, code="too_big", message="la copia es demasiado grande")
            return
        b64d(data)  # tiene que ser base64 válido (si no, CryptoError -> petición inválida)
        now = time.monotonic()
        if now - self._cloud_last.get(c, 0) < CLOUD_INTERVAL:
            await _send(ws, type="error", id=rid, code="rate_limited", message="espera un poco antes de otra copia")
            return
        self._cloud_last[c] = now
        at = int(time.time())
        if self.store:
            self.store.cloud_put(c, data, at)
        else:
            self._cloud_mem[c] = (data, at)
        await _send(ws, type="ack", id=rid, status="ok", at=at)

    def blocks(self, owner: str, other: str) -> bool:
        """¿`owner` ha bloqueado a `other`? (los dos en canon)"""
        r = self.registry.get(owner)
        return bool(r) and other in r.get("blocked", ())

    async def _set_block(self, ws: ServerConnection, c: str, msg: dict) -> None:
        """Bloquear o desbloquear: el servidor deja de entregarte lo que esa cuenta te envíe
        (sin decírselo) y de enseñarle si estás conectado. Así sabe a quién has bloqueado,
        pero sin esto podría seguir llenándote el móvil de avisos."""
        other = canon(msg.get("user", "")) if isinstance(msg.get("user"), str) else ""
        r = self.registry[c]
        if other not in self.registry or other == c:
            await _send(ws, type="error", id=msg.get("id"), code="no_user", message="ese usuario no existe")
            return
        blocked = [b for b in r.get("blocked", []) if b != other and b in self.registry]
        if msg.get("on", True):
            if len(blocked) >= MAX_BLOCKED:
                await _send(ws, type="error", id=msg.get("id"), code="too_many", message="has bloqueado demasiados usuarios")
                return
            blocked.append(other)
        r["blocked"] = blocked
        self._save()
        await _send(ws, type="ack", id=msg.get("id"), status="ok")
        # Mis otros dispositivos se enteran al momento
        names = [self.registry[b]["name"] for b in blocked]
        for conn in list(self.online.get(c, {}).values()):
            if conn is not ws:
                await _send(conn, type="blocked", users=names)
        if msg.get("on", True) and c in self.online and other in self.online:
            for conn in list(self.online[other].values()):
                await _send(conn, type="presence", user=r["name"], online=False, away=False, last_seen=None)

    async def _report(self, ws: ServerConnection, c: str, msg: dict) -> None:
        """Denuncia: la guarda para quien gestiona el servidor. Solo incluye los mensajes
        que quien denuncia decide adjuntar (el servidor no puede leer ningún otro)."""
        rid = msg.get("id")
        other = canon(msg.get("user", "")) if isinstance(msg.get("user"), str) else ""
        if other not in self.registry or other == c:
            await _send(ws, type="error", id=rid, code="no_user", message="ese usuario no existe")
            return
        now = time.time()
        recent = self._reports[c] = [t for t in self._reports.get(c, []) if now - t < 86400]
        if len(recent) >= REPORTS_PER_DAY:
            await _send(ws, type="error", id=rid, code="too_many", message="has enviado demasiadas denuncias hoy")
            return
        recent.append(now)
        reason = msg.get("reason") if msg.get("reason") in ("spam", "acoso", "suplantacion", "ilegal", "otro") else "otro"
        note = str(msg.get("note") or "")[:1000]
        quoted = []
        for m in (msg.get("messages") or [])[:10] if isinstance(msg.get("messages"), list) else []:
            if isinstance(m, dict) and isinstance(m.get("text"), str):
                quoted.append({"at": int(m["at"]) if isinstance(m.get("at"), (int, float)) else None, "text": m["text"][:2000]})
        entry = {"at": int(now), "by": self.registry[c]["name"], "user": self.registry[other]["name"],
                 "reason": reason, "note": note, "messages": quoted}
        if self.reports_path:
            with self.reports_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        log.warning("denuncia de %s contra %s (%s)", entry["by"], entry["user"], reason)
        await _send(ws, type="ack", id=rid, status="ok")

    async def _anon(self, ws: ServerConnection, hello: dict) -> None:
        """Conexión anónima: solo sirve para entregar sobres con remitente oculto.
        No se sabe de quién es; se limita por IP para que nadie la use para inundar."""
        if not await self._check_code(ws, hello):
            return
        await _send(ws, type="anon-ready")
        ip = client_ip(ws)
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                    if not isinstance(msg, dict) or msg.get("type") not in ("sealed-send", "sealed-send-many"):
                        await _send(ws, type="error", code="unknown_type", message="tipo desconocido")
                        continue
                    now = time.monotonic()
                    hits = self._sealed_hits[ip] = [t for t in self._sealed_hits.get(ip, []) if now - t < 60] + [now]
                    if len(hits) > SEALED_LIMIT:
                        await _send(ws, type="error", id=msg.get("id"), code="rate_limited", message="demasiados envíos, espera")
                        continue
                    if msg["type"] == "sealed-send":
                        await self._relay_sealed(ws, msg)
                    else:
                        await self._relay_sealed_many(ws, msg)
                except (ValueError, KeyError, TypeError, CryptoError, json.JSONDecodeError):
                    await _send(ws, type="error", code="bad_request", message="petición inválida")
        except ConnectionClosed:
            pass

    async def _relay_sealed(self, ws: ServerConnection, msg: dict) -> None:
        """Como _relay, pero sin remitente: el sobre (cifrado para el destinatario) lo lleva dentro.
        Solo pasa si trae la clave de entrega del destinatario."""
        to, device, payload, rid = msg.get("to"), msg.get("device"), msg.get("payload"), msg.get("id")
        ct = canon(to) if isinstance(to, str) else ""
        r = self.registry.get(ct)
        uak = msg.get("uak")
        # Mismo error si el usuario no existe o la clave no vale: no se puede usar para buscar cuentas
        if not r or not r.get("uak") or not isinstance(uak, str) or not hmac.compare_digest(uak.encode(), r["uak"].encode()):
            await _send(ws, type="error", id=rid, code="bad_uak", message="no se puede entregar sin identificarse")
            return
        if not isinstance(payload, dict) or payload.get("kind") != "sealed" or not isinstance(payload.get("box"), str) \
                or set(payload) != {"kind", "box"}:
            await _send(ws, type="error", id=rid, code="bad_request", message="sobre inválido")
            return
        devices = list(r.get("devices", {}))
        if device not in devices:
            await _send(ws, type="error", code="no_device", to=to, id=rid, devices=devices, message="ese dispositivo ya no existe")
            return
        if msg.get("urgent") and r.get("push"):
            asyncio.get_running_loop().create_task(self._push(ct, call=True))
        target = self.online.get(ct, {}).get(device)
        if target is not None:
            try:
                await target.send(json.dumps({"type": "deliver", "from": None, "payload": payload}))
                await _send(ws, type="ack", id=rid, status="delivered", devices=devices)
                return
            except ConnectionClosed:
                pass
        if msg.get("ephemeral"):
            await _send(ws, type="ack", id=rid, status="dropped", devices=devices)
            return
        self._enqueue(f"{ct}|{device}", {"from": None, "payload": payload, "at": int(time.time())})
        if not msg.get("silent") and not msg.get("urgent") and not self.online.get(ct) and r.get("push"):
            asyncio.get_running_loop().create_task(self._push(ct))
        await _send(ws, type="ack", id=rid, status="queued", devices=devices)

    async def _relay_sealed_many(self, ws: ServerConnection, msg: dict) -> None:
        """Mensaje de grupo con remitente oculto: el cuerpo (cifrado una vez con la sender key)
        es el mismo para todos, y cada destinatario trae su cabecera sellada (quién lo envía,
        su dispositivo y el grupo, que solo ese destinatario puede abrir) y su clave de entrega."""
        targets, body, rid = msg.get("targets"), msg.get("body"), msg.get("id")
        if not isinstance(targets, list) or not 0 < len(targets) <= MAX_FANOUT or not isinstance(body, dict) \
                or set(body) != {"nonce", "ct", "sig"} or not all(isinstance(body[k], str) for k in body):
            await _send(ws, type="error", code="bad_request", id=rid, message="envío de grupo inválido")
            return
        now = int(time.time())
        results, devices, to_push = [], {}, set()
        for tg in targets:
            if not isinstance(tg, dict):
                results.append({"status": "bad_request"})
                continue
            to, device, uak, hdr = tg.get("to"), tg.get("device"), tg.get("uak"), tg.get("hdr")
            ct = canon(to) if isinstance(to, str) else ""
            r = self.registry.get(ct)
            if not r or not r.get("uak") or not isinstance(uak, str) or not hmac.compare_digest(uak.encode(), r["uak"].encode()):
                results.append({"to": to, "device": device, "status": "bad_uak"})
                continue
            if not isinstance(hdr, str) or len(hdr) > 2048:
                results.append({"to": to, "device": device, "status": "bad_request"})
                continue
            devs = list(r.get("devices", {}))
            devices[r["name"]] = devs
            if device not in devs:
                results.append({"to": to, "device": device, "status": "no_device"})
                continue
            payload = {"kind": "sealed-g", "hdr": hdr, "body": body}
            conn = self.online.get(ct, {}).get(device)
            if conn is not None:
                try:
                    await conn.send(json.dumps({"type": "deliver", "from": None, "payload": payload}))
                    results.append({"to": to, "device": device, "status": "delivered"})
                    continue
                except ConnectionClosed:
                    pass
            self._enqueue(f"{ct}|{device}", {"from": None, "payload": payload, "at": now})
            results.append({"to": to, "device": device, "status": "queued"})
            if not msg.get("silent") and not self.online.get(ct) and r.get("push"):
                to_push.add(ct)
        for ct in to_push:
            asyncio.get_running_loop().create_task(self._push(ct))
        await _send(ws, type="ack", id=rid, status="ok", results=results, devices=devices)

    async def _preview(self, ws: ServerConnection, msg: dict) -> None:
        """Vista previa de un enlace (en otro hilo, para no frenar al resto)."""
        from .preview import PreviewError, link_preview
        try:
            data = await asyncio.wait_for(asyncio.to_thread(link_preview, msg.get("url")), 12)
            await _send(ws, type="preview", id=msg.get("id"), **data)
        except (PreviewError, TimeoutError) as exc:
            await _send(ws, type="error", code="no_preview", id=msg.get("id"), message=str(exc) or "sin vista previa")
        except ConnectionClosed:
            pass
        except Exception:  # noqa: BLE001 - una página rara no debe tumbar nada
            log.warning("vista previa fallida", exc_info=True)
            await _send(ws, type="error", code="no_preview", id=msg.get("id"), message="sin vista previa")

    async def _delete_account(self, c: str) -> None:
        """Borra la cuenta para siempre: claves, copia cifrada, correo, avisos y mensajes en espera.
        El nombre queda libre para que otra persona pueda registrarlo."""
        r = self.registry.get(c)
        if r is None:
            return
        if r.get("status") != "invisible" and c in self.online:
            r["last_seen"] = None
            await self._presence(c, False)
        for d in list(r.get("devices", {})):
            self._forget_device(c, d)
        if self.store:
            self.store.cloud_delete(c)
        self._cloud_mem.pop(c, None)
        conns = list(self.online.pop(c, {}).values())
        del self.registry[c]
        for other in self.registry.values():
            if c in other.get("blocked", ()):
                other["blocked"] = [b for b in other["blocked"] if b != c]
        for other in self.related.pop(c, set()):
            self.related.get(other, set()).discard(c)
        self._save()
        log.info("cuenta borrada: %s", r["name"])
        for conn in conns:
            await conn.close(4002, "cuenta borrada")

    async def _presence(self, c: str, online: bool) -> None:
        """Avisa a quien ha hablado con este usuario de que entra o sale."""
        r = self.registry[c]
        last = None if online or r.get("hide_last_seen") else r.get("last_seen")
        away = online and r.get("status") == "away"
        for other in self.related.get(c, ()):
            if other == c or self.blocks(c, other):
                continue  # las copias a mis otros dispositivos no me hacen "contacto" de mí mismo
            for conn in list(self.online.get(other, {}).values()):
                await _send(conn, type="presence", user=r["name"], online=online, away=away, last_seen=last)

    # ------------------------------------------------------------ directorio

    def _lookup(self, name, asker: str | None = None) -> dict:
        """¿Existe el usuario? Devuelve su grafía oficial y si está conectado."""
        if not isinstance(name, str) or not USERNAME_RE.match(name):
            return {"exists": False, "user": None, "online": False}
        known = self.registry.get(canon(name))
        if known is None:
            return {"exists": False, "user": None, "online": False}
        if asker and self.blocks(canon(name), asker):
            return {"exists": True, "user": known["name"], "online": False, "away": False}
        status = known.get("status", "online")
        online = bool(self.online.get(canon(name))) and status != "invisible"
        info = {"exists": True, "user": known["name"], "online": online, "away": online and status == "away"}
        if not online and not known.get("hide_last_seen") and known.get("last_seen"):
            info["last_seen"] = known["last_seen"]
        return info

    def _bundle(self, name, asker: str) -> dict:
        """Prekeys de cada dispositivo de un usuario. Entrega (y borra) una OPK por dispositivo."""
        info = self._lookup(name, asker)
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
        if msg.get("kem") is not None:
            # Prekey poscuántica (PQXDH): firmada con la identidad, como la clásica
            kem, kem_created = b64d(msg["kem"]), int(msg["kem_created"])
            if len(kem) != KEM_PUB_BYTES:
                raise ValueError("prekey poscuántica inválida")
            verify_signature(r["key"], kem_message(r["name"], device, kem, kem_created), b64d(msg["kem_sig"]))
            d["bundle"].update(kem=msg["kem"], kem_sig=msg["kem_sig"], kem_created=kem_created)
        new = [k for k in msg.get("opks", []) if isinstance(k, str) and len(b64d(k)) == 32]
        known = set(d.get("opks", []))
        d["opks"] = (d.get("opks", []) + [k for k in new if k not in known])[-MAX_OPKS:]
        self._save()
        return len(d["opks"])

    # --------------------------------------------- copia cifrada de la clave

    def _store_keystore(self, c: str, blob, auth=None) -> None:
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
        changed = r.get("keystore") != clean
        if changed:
            r["keystore"] = clean
            r.pop("keystore_auth", None)  # una copia nueva necesita su propia prueba
        # Prueba de contraseña: el cliente la saca de la MISMA derivación Argon2id que cifra la
        # copia (con otra etiqueta), así que solo quien sabe la contraseña puede generarla.
        # Guardamos su hash: con él no se puede ni descifrar la copia ni sacar la prueba.
        if isinstance(auth, str):
            raw = b64d(auth)
            if len(raw) != 32:
                raise ValueError("prueba de contraseña inválida")
            digest = hashlib.sha256(raw).hexdigest()
            if r.get("keystore_auth") != digest:
                r["keystore_auth"] = digest
                changed = True
        if changed:
            self._save()

    def _store_recovery(self, c: str, blob, auth) -> None:
        """Copia de la clave cifrada con el código de recuperación (por si olvidas la contraseña).

        Como la de la contraseña, el servidor no puede abrirla; solo la entrega a quien
        demuestra conocer el código (guardamos el hash de esa prueba, nunca el código).
        """
        r = self.registry[c]
        if not isinstance(blob, dict) or set(blob) != {"version", "public_key", "ciphertext"} \
                or blob["version"] != 1 or len(json.dumps(blob)) > 1024 or b64d(blob["public_key"]) != r["key"]:
            raise ValueError("copia de recuperación inválida")
        raw = b64d(auth) if isinstance(auth, str) else b""
        if len(raw) != 32:
            raise ValueError("prueba de recuperación inválida")
        r["recovery"] = dict(blob)
        r["recovery_auth"] = hashlib.sha256(raw).hexdigest()
        self._save()

    def keystore_response(self, connection: ServerConnection, request: Request) -> Response:
        """GET /keystore?user=NOMBRE[&code=CODIGO]: copia cifrada para iniciar sesión.

        Cualquiera que la descargue podría intentar adivinar la contraseña sin conexión,
        así que se limita el ritmo por IP y, si el servidor tiene código, se exige.
        """
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(request.path).query)
        ip = real_ip(connection.remote_address, request.headers)
        now = time.monotonic()
        hits = self._keystore_hits[ip] = [t for t in self._keystore_hits.get(ip, []) if now - t < 60] + [now]
        if len(hits) > KEYSTORE_LIMIT:
            return _response(429, "Too Many Requests", b'{"error": "demasiados intentos, espera un minuto"}',
                             "application/json")
        if self.access_code and not hmac.compare_digest(normalize_code(q.get("code", [""])[0]), self.access_code):
            return _response(403, "Forbidden", b'{"error": "codigo de acceso incorrecto"}', "application/json")
        name = q.get("user", [""])[0]
        if "@" in name:
            # Inicio de sesión con correo: se compara su huella, la dirección nunca se guarda
            h = self.email_hash(name) if valid_email(name) else None
            r = next((x for x in self.registry.values() if h and x.get("email") == h), None)
        else:
            r = self.registry.get(canon(name)) if USERNAME_RE.match(name) else None
        if q.get("recovery"):
            return self._recovery_response(r, request, now)
        if not r or not r.get("keystore"):
            return _response(404, "Not Found", b'{"error": "no encontrada"}', "application/json")
        ks = r["keystore"]
        if r.get("keystore_auth"):
            # Sin la prueba de contraseña solo se dan los parámetros de Argon2id (sal incluida):
            # así nadie puede llevarse la copia para probar contraseñas sin conexión.
            given = request.headers.get("X-SC-Keystore-Auth", "")
            if not given:
                params = {k: ks[k] for k in ("version", "kdf", "opslimit", "memlimit", "salt") if k in ks}
                body = json.dumps({"user": r["name"], "auth_required": True, "params": params}).encode()
                return _response(200, "OK", body, "application/json")
            key = canon(r["name"])
            fails = self._keystore_fails[key] = [t for t in self._keystore_fails.get(key, []) if now - t < KEYSTORE_LOCK]
            if len(fails) >= KEYSTORE_AUTH_FAILS:
                return _response(429, "Too Many Requests",
                                 b'{"error": "demasiados intentos con esta cuenta, espera 15 minutos"}', "application/json")
            try:
                ok = hmac.compare_digest(hashlib.sha256(b64d(given)).hexdigest(), r["keystore_auth"])
            except (ValueError, CryptoError):
                ok = False
            if not ok:
                fails.append(now)
                return _response(403, "Forbidden", b'{"error": "contrasena incorrecta", "code": "bad_password"}',
                                 "application/json")
            self._keystore_fails.pop(key, None)
        body = json.dumps({"user": r["name"], "blob": ks}).encode()
        return _response(200, "OK", body, "application/json")

    def _recovery_response(self, r: dict | None, request: Request, now: float) -> Response:
        """GET /keystore?user=NOMBRE&recovery=1 con la prueba del código en X-SC-Recovery-Auth."""
        not_found = _response(404, "Not Found", b'{"error": "no encontrada"}', "application/json")
        if not r:
            return not_found
        key = canon(r["name"])
        fails = self._keystore_fails[key] = [t for t in self._keystore_fails.get(key, []) if now - t < KEYSTORE_LOCK]
        if len(fails) >= KEYSTORE_AUTH_FAILS:
            return _response(429, "Too Many Requests",
                             b'{"error": "demasiados intentos con esta cuenta, espera 15 minutos"}', "application/json")
        try:
            given = b64d(request.headers.get("X-SC-Recovery-Auth", ""))
        except (ValueError, CryptoError):
            given = b""
        # Sin copia de recuperación se responde igual que con un código incorrecto (y cuenta como fallo):
        # así no se puede averiguar quién tiene código configurado.
        ok = bool(r.get("recovery_auth")) and len(given) == 32 and \
            hmac.compare_digest(hashlib.sha256(given).hexdigest(), r["recovery_auth"])
        if not ok:
            fails.append(now)
            return _response(403, "Forbidden", b'{"error": "codigo incorrecto", "code": "bad_recovery"}', "application/json")
        self._keystore_fails.pop(key, None)
        return _response(200, "OK", json.dumps({"user": r["name"], "recovery": r["recovery"]}).encode(), "application/json")

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
        if self.blocks(ct, cs):
            # Bloqueado: no se entrega ni se avisa, y no se le dice (parece que se ha guardado)
            await _send(ws, type="ack", id=rid, status="queued", devices=devices)
            return
        if ct != cs:
            self.related.setdefault(ct, set()).add(cs)
            self.related.setdefault(cs, set()).add(ct)
        # El remitente lo pone el servidor a partir de la sesión autenticada,
        # nunca se copia de lo que diga el cliente.
        # Llamada entrante (el cliente marca la oferta como urgente): avisamos al móvil SIEMPRE,
        # porque Android congela la app en segundo plano sin cerrar la conexión y el servidor
        # la ve "conectada" aunque no pueda sonar. Si la app está a la vista, el aviso no se muestra.
        if msg.get("urgent") and ct != cs and self.registry[ct].get("push"):
            asyncio.get_running_loop().create_task(self._push(ct, call=True))
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
        if not msg.get("silent") and not msg.get("urgent") and ct != cs and not self.online.get(ct) \
                and self.registry[ct].get("push"):
            asyncio.get_running_loop().create_task(self._push(ct))
        await _send(ws, type="ack", id=rid, status="queued", devices=devices)

    async def _relay_many(self, ws: ServerConnection, sender: str, msg: dict) -> None:
        """Mensaje de grupo con sender keys: la MISMA copia cifrada para muchos dispositivos.
        Devuelve el estado de cada uno y la lista de dispositivos de cada destinatario
        (para que el cliente detecte dispositivos nuevos y les dé la clave)."""
        targets, payload, rid = msg.get("targets"), msg.get("payload"), msg.get("id")
        if not isinstance(targets, list) or not 0 < len(targets) <= MAX_FANOUT or not isinstance(payload, dict):
            await _send(ws, type="error", code="bad_request", id=rid, message="envío de grupo inválido")
            return
        cs = canon(sender)
        now = int(time.time())
        results, devices, to_push = [], {}, set()
        envelope = json.dumps({"type": "deliver", "from": sender, "payload": payload})
        for tg in targets:
            to, device = (tg.get("to"), tg.get("device")) if isinstance(tg, dict) else (None, None)
            ct = canon(to) if isinstance(to, str) else ""
            if ct not in self.registry or ct == cs:
                results.append({"to": to, "device": device, "status": "no_user"})
                continue
            devs = list(self.registry[ct].get("devices", {}))
            devices[self.registry[ct]["name"]] = devs
            if device not in devs:
                results.append({"to": to, "device": device, "status": "no_device"})
                continue
            if self.blocks(ct, cs):
                results.append({"to": to, "device": device, "status": "queued"})
                continue
            self.related.setdefault(ct, set()).add(cs)
            self.related.setdefault(cs, set()).add(ct)
            conn = self.online.get(ct, {}).get(device)
            if conn is not None:
                try:
                    await conn.send(envelope)
                    results.append({"to": to, "device": device, "status": "delivered"})
                    continue
                except ConnectionClosed:
                    pass
            self._enqueue(f"{ct}|{device}", {"from": sender, "payload": payload, "at": now})
            results.append({"to": to, "device": device, "status": "queued"})
            if not msg.get("silent") and not self.online.get(ct) and self.registry[ct].get("push"):
                to_push.add(ct)
        for ct in to_push:
            asyncio.get_running_loop().create_task(self._push(ct))
        await _send(ws, type="ack", id=rid, status="ok", results=results, devices=devices)

    async def _push(self, c: str, call: bool = False) -> None:
        r = self.registry.get(c)
        if not r:
            return
        alive = await self.pusher.notify(c, r.get("push", []), call=call)
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
            other = canon(item["from"]) if item.get("from") else c  # remitente oculto: no se sabe
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
    if server.turn_urls and server.turn_port:
        from .turn import TurnServer
        servers.append(await TurnServer(server.turn_secret).start("127.0.0.1", server.turn_port))
    shown = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    log.info("web y relay en %s://%s:%d", "https" if tls and not tls_port else "http", shown, port)
    if tls and tls_port:
        log.info("web y relay en https://%s:%d", shown, tls_port)
    try:
        await asyncio.gather(*(s.serve_forever() for s in servers))
    finally:
        # Al pararlo (p. ej. desde el icono de la bandeja) se liberan los puertos
        for s in servers:
            s.close()


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
    p.add_argument("--turn", type=int, metavar="PUERTO",
                   help="arranca el relé de llamadas (TURN por TCP) en este puerto, solo para este equipo")
    p.add_argument("--denuncias", action="store_true", help="muestra las denuncias recibidas y sale")
    p.add_argument("--cert", type=Path, help="certificado TLS (PEM) para servir por HTTPS")
    p.add_argument("--key", type=Path, help="clave privada TLS (PEM)")
    args = p.parse_args()
    if args.denuncias:
        print_reports(args.db.with_name(args.db.stem + "_denuncias.jsonl"))
        return
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
    if args.turn:
        relay.turn_port = args.turn
        relay.turn_urls = [f"turn:127.0.0.1:{args.turn}?transport=tcp"]
    try:
        asyncio.run(run(host, args.port, relay=relay, tls=tls))
    except KeyboardInterrupt:
        pass


def print_reports(path: Path) -> None:
    """Lista las denuncias (las más recientes al final)."""
    if not path.exists():
        print("No hay denuncias.")
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("at", 0)))
        print(f"\n[{when}] @{e.get('by')} denuncia a @{e.get('user')} por {e.get('reason')}")
        if e.get("note"):
            print(f"  Nota: {e['note']}")
        for m in e.get("messages", []):
            at = time.strftime("%Y-%m-%d %H:%M", time.localtime(m["at"])) if m.get("at") else "?"
            print(f"  > [{at}] {m.get('text', '')}")


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
