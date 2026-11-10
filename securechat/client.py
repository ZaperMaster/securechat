"""Lógica de red del cliente, independiente de la interfaz (CLI, GUI o tests).

Cómo se envía un mensaje:
  * Si hay una sesión en vivo con el contacto (los dos conectados), se usa: cada
    mensaje lleva una clave nueva del ratchet (secreto hacia adelante fuerte).
  * Si no la hay y el contacto está conectado, se negocia una (handshake).
  * Si el contacto está desconectado, se envía un "sobre sellado" con su prekey
    firmada (ver sealed.py). El servidor lo guarda y se lo entrega al conectarse.

Las sesiones solo viven mientras los dos siguen conectados: al conectarse o
desconectarse alguien, ambos lados las descartan y negocian otra la próxima vez.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from . import content
from .contacts import Contacts
from .crypto import CryptoError, b64d, b64e
from .sealed import PrekeyStore, open_sealed, seal, verify_bundle
from .server import MAX_FRAME, auth_message
from .session import IdentityMismatch, Session


class ClientError(Exception):
    pass


@dataclass
class Event:
    """Algo que la interfaz debe mostrar al usuario."""
    kind: str   # message | profile | session | presence | identity_changed | warning | disconnected
    peer: str = ""
    text: str = ""


class ChatClient:
    def __init__(self, name: str, identity: SigningKey, contacts: Contacts,
                 prekeys_path: Path | None = None, code: str | None = None):
        self.name = name
        self.code = code  # código de acceso del servidor, si lo pide
        self.identity = identity
        self.contacts = contacts
        self.prekeys = PrekeyStore(name, identity, prekeys_path)
        self.sessions: dict[str, Session] = {}
        self.online: dict[str, bool] = {}
        self.profiles: dict[str, str] = {}  # nombre visible que cada contacto nos envía
        self._pending: dict[str, tuple[Session, asyncio.Future]] = {}
        self._requests: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self._known: dict[str, str] = {}  # minúsculas -> grafía oficial
        self._who: asyncio.Future | None = None
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self.ws: ClientConnection | None = None
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------ conexión

    async def connect(self, url: str) -> None:
        self.ws = await connect(url, max_size=MAX_FRAME)
        await self._send(type="hello", user=self.name, code=self.code,
                         identity_key=b64e(bytes(self.identity.verify_key)))
        challenge = json.loads(await self.ws.recv())
        if challenge.get("type") != "challenge":
            raise ClientError(challenge.get("message", "respuesta inesperada del servidor"))
        sig = self.identity.sign(auth_message(b64d(challenge["nonce"]), self.name)).signature
        await self._send(type="auth", sig=b64e(sig))
        welcome = json.loads(await self.ws.recv())
        if welcome.get("type") != "welcome":
            raise ClientError(welcome.get("message", "autenticación rechazada"))
        self.name = self.prekeys.user = welcome["user"]  # grafía oficial
        self.sessions.clear()  # una conexión nueva empieza sin sesiones en vivo
        self._task = asyncio.create_task(self._recv_loop())
        await self._send(type="prekey", **self.prekeys.bundle())

    async def close(self) -> None:
        if self.ws:
            await self.ws.close()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)

    # ------------------------------------------------------------- acciones

    async def _request(self, timeout: float = 15, **msg) -> dict:
        """Envía una petición con id y espera la respuesta del servidor."""
        self._next_id += 1
        rid = self._next_id
        fut = asyncio.get_running_loop().create_future()
        self._requests[rid] = fut
        try:
            await self._send(id=rid, **msg)
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            raise ClientError("el servidor no responde") from None
        finally:
            self._requests.pop(rid, None)

    async def lookup(self, name: str) -> dict:
        """Pregunta al servidor si existe un usuario: {exists, user, online}."""
        r = await self._request(type="lookup", user=name, timeout=5)
        info = {"exists": r["exists"], "user": r["user"], "online": r["online"]}
        if info["exists"]:
            self._known[name.lower()] = info["user"]
            self.online[info["user"]] = info["online"]
        return info

    async def resolve(self, name: str) -> str:
        """Devuelve la grafía oficial del usuario o lanza ClientError si no existe."""
        if name in self.sessions:
            return name
        if name.lower() in self._known:
            return self._known[name.lower()]
        info = await self.lookup(name)
        if not info["exists"]:
            raise ClientError(f"el usuario '{name}' no existe")
        return info["user"]

    async def open_session(self, peer: str, timeout: float = 10) -> Session:
        peer = await self.resolve(peer)
        if peer.lower() == self.name.lower():
            raise ClientError("no puedes abrir una sesión contigo mismo")
        session, hs1 = Session.initiate(self.name, self.identity, peer)
        fut = asyncio.get_running_loop().create_future()
        self._pending[peer] = (session, fut)
        await self._send(type="send", to=peer, payload=hs1)
        try:
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            raise ClientError(f"'{peer}' no respondió al handshake") from None
        finally:
            if self._pending.get(peer, (None, None))[1] is fut:
                del self._pending[peer]

    async def send_text(self, peer: str, text: str) -> str:
        return await self.send_content(peer, content.text(text))

    async def send_content(self, peer: str, plaintext: str) -> str:
        """Envía contenido cifrado. Devuelve "delivered" o "queued" (en espera)."""
        peer = await self.resolve(peer)
        if peer.lower() == self.name.lower():
            raise ClientError("no puedes escribirte a ti mismo")
        session = self.sessions.get(peer)
        if session is None and self.online.get(peer, True):
            try:
                session = await self.open_session(peer, timeout=5)
            except IdentityMismatch:
                raise
            except ClientError:
                session = None  # no está o no responde: usamos un sobre sellado
        if session is not None:
            try:
                r = await self._request(type="send", to=peer, payload=session.encrypt(plaintext))
                return r["status"]
            except ClientError:
                self.sessions.pop(peer, None)  # se desconectó justo ahora
        return await self._send_sealed(peer, plaintext)

    async def _send_sealed(self, peer: str, plaintext: str) -> str:
        r = await self._request(type="bundle", user=peer)
        if not r.get("exists"):
            raise ClientError(f"el usuario '{peer}' no existe")
        if not r.get("prekey"):
            raise ClientError(f"'{peer}' no está conectado y aún no admite mensajes en diferido")
        ident, spk = verify_bundle({**r["prekey"], "user": r["user"], "identity_key": r["identity_key"]},
                                   self.contacts.pinned_key(peer))
        self.contacts.pin(peer, ident)
        payload = seal(self.name, self.identity, peer, ident, spk, plaintext)
        return (await self._request(type="send", to=peer, payload=payload))["status"]

    async def who(self) -> list[str]:
        self._who = asyncio.get_running_loop().create_future()
        await self._send(type="who")
        return await asyncio.wait_for(self._who, 5)

    # ------------------------------------------------------------ recepción

    async def _recv_loop(self) -> None:
        try:
            async for raw in self.ws:
                try:
                    await self._dispatch(json.loads(raw))
                except (ValueError, KeyError, TypeError) as exc:
                    self._emit("warning", text=f"mensaje malformado ignorado: {exc}")
        except ConnectionClosed:
            pass
        finally:
            for fut in [f for _, f in self._pending.values()] + list(self._requests.values()):
                if not fut.done():
                    fut.set_exception(ClientError("conexión cerrada"))
            self._emit("disconnected")

    async def _dispatch(self, msg: dict) -> None:
        t = msg.get("type")
        fut = self._requests.get(msg.get("id")) if msg.get("id") is not None else None
        if t == "deliver":
            await self._on_deliver(msg["from"], msg["payload"])
        elif t == "presence":
            peer = msg["user"]
            self.online[peer] = msg["online"]
            self.sessions.pop(peer, None)  # su estado de sesión ya no es fiable
            self._emit("presence", peer, "en línea" if msg["online"] else "desconectado")
        elif fut is not None and not fut.done():
            if t == "error":
                fut.set_exception(ClientError(msg.get("message", "error del servidor")))
            else:
                fut.set_result(msg)
        elif t == "who" and self._who and not self._who.done():
            self._who.set_result(msg["users"])
        elif t == "error":
            pending = self._pending.get(msg.get("to"))
            if msg.get("code") == "offline" and pending and not pending[1].done():
                pending[1].set_exception(ClientError(msg.get("message", "usuario no conectado")))
            else:
                self._emit("warning", msg.get("to") or "", msg.get("message", "error del servidor"))

    async def _on_deliver(self, sender: str, payload: dict) -> None:
        kind = payload.get("kind")
        try:
            if kind == "hs1":
                await self._on_hs1(sender, payload)
            elif kind == "hs2":
                self._on_hs2(sender, payload)
            elif kind == "reset":
                self.sessions.pop(sender, None)
            elif kind == "msg":
                session = self.sessions.get(sender)
                if session is None:
                    # Su sesión es de antes de que nos reconectáramos: que negocie otra.
                    await self._send(type="send", to=sender, payload={"kind": "reset"})
                    raise CryptoError("llegó un mensaje de una sesión caducada; pídele que lo reenvíe")
                lost_before = session.lost
                text = session.decrypt(payload)
                if session.lost > lost_before:
                    self._emit("warning", sender, f"se perdieron {session.lost - lost_before} "
                               f"mensaje(s) de {sender} (¿manipulación en el servidor?)")
                self._on_content(sender, text)
            elif kind == "sealed":
                text, ident = open_sealed(self.name, self.identity, sender, payload, self.prekeys,
                                          self.contacts.pinned_key(sender))
                self.contacts.pin(sender, ident)
                self._on_content(sender, text)
            else:
                raise CryptoError(f"tipo de payload desconocido: {kind!r}")
        except IdentityMismatch as exc:
            self._fail_pending(sender, exc)
            self._emit("identity_changed", sender, str(exc))
        except CryptoError as exc:
            if kind == "hs2":
                self._fail_pending(sender, exc)
            self._emit("warning", sender, f"descartado mensaje de {sender}: {exc}")

    def _on_content(self, sender: str, text: str) -> None:
        c = content.decode(text)
        if c["t"] == "profile":
            name = str(c.get("name") or "")[:content.MAX_NAME]
            self.profiles[sender] = name
            self._emit("profile", sender, name)
        else:
            self._emit("message", sender, content.describe(c))

    async def _on_hs1(self, sender: str, hs1: dict) -> None:
        # Si los dos iniciamos a la vez, gana el handshake del nombre menor.
        if sender in self._pending and self.name < sender:
            return
        session, hs2 = Session.accept(self.name, self.identity, sender, hs1,
                                      self.contacts.pinned_key(sender))
        self.contacts.pin(sender, session.peer_identity)
        renewed = sender in self.sessions
        self.sessions[sender] = session
        self.online[sender] = True
        await self._send(type="send", to=sender, payload=hs2)
        pending = self._pending.pop(sender, None)
        if pending and not pending[1].done():
            pending[1].set_result(session)
        self._emit("session", sender, "sesión renovada" if renewed else "sesión iniciada")

    def _on_hs2(self, sender: str, hs2: dict) -> None:
        pending = self._pending.get(sender)
        if pending is None:
            raise CryptoError("hs2 no solicitado")
        session, fut = pending
        session.complete(hs2, self.contacts.pinned_key(sender))
        self.contacts.pin(sender, session.peer_identity)
        self.sessions[sender] = session
        self.online[sender] = True
        if not fut.done():
            fut.set_result(session)
        self._emit("session", sender, "sesión iniciada")

    def _fail_pending(self, peer: str, exc: Exception) -> None:
        pending = self._pending.get(peer)
        if pending and not pending[1].done():
            pending[1].set_exception(exc)

    # ------------------------------------------------------------ utilidades

    def _emit(self, kind: str, peer: str = "", text: str = "") -> None:
        self.events.put_nowait(Event(kind, peer, text))

    async def _send(self, **msg) -> None:
        if self.ws is None:
            raise ClientError("no conectado")
        await self.ws.send(json.dumps(msg))
