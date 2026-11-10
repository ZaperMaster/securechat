"""Lógica de red del cliente, independiente de la interfaz (CLI, GUI o tests)."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from nacl.signing import SigningKey
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from . import content
from .contacts import Contacts
from .crypto import CryptoError, b64d, b64e
from .server import MAX_FRAME, auth_message
from .session import IdentityMismatch, Session


class ClientError(Exception):
    pass


@dataclass
class Event:
    """Algo que la interfaz debe mostrar al usuario."""
    kind: str          # message | session | identity_changed | warning | disconnected
    peer: str = ""
    text: str = ""


class ChatClient:
    def __init__(self, name: str, identity: SigningKey, contacts: Contacts):
        self.name = name
        self.identity = identity
        self.contacts = contacts
        self.sessions: dict[str, Session] = {}
        self._pending: dict[str, tuple[Session, asyncio.Future]] = {}
        self._who: asyncio.Future | None = None
        self._lookups: dict[int, asyncio.Future] = {}
        self._lookup_id = 0
        self.profiles: dict[str, str] = {}  # nombre visible que cada contacto nos envía
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self.ws: ClientConnection | None = None
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------ conexión

    async def connect(self, url: str) -> None:
        self.ws = await connect(url, max_size=MAX_FRAME)
        await self._send(type="hello", user=self.name,
                         identity_key=b64e(bytes(self.identity.verify_key)))
        challenge = json.loads(await self.ws.recv())
        if challenge.get("type") != "challenge":
            raise ClientError(challenge.get("message", "respuesta inesperada del servidor"))
        sig = self.identity.sign(auth_message(b64d(challenge["nonce"]), self.name)).signature
        await self._send(type="auth", sig=b64e(sig))
        welcome = json.loads(await self.ws.recv())
        if welcome.get("type") != "welcome":
            raise ClientError(welcome.get("message", "autenticación rechazada"))
        self.name = welcome["user"]  # grafía oficial (p. ej. "Alice" aunque escribieras "alice")
        self._task = asyncio.create_task(self._recv_loop())

    async def close(self) -> None:
        if self.ws:
            await self.ws.close()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)

    # ------------------------------------------------------------- acciones

    async def lookup(self, name: str) -> dict:
        """Pregunta al servidor si existe un usuario: {exists, user, online}."""
        self._lookup_id += 1
        rid = self._lookup_id
        fut = asyncio.get_running_loop().create_future()
        self._lookups[rid] = fut
        try:
            await self._send(type="lookup", user=name, id=rid)
            return await asyncio.wait_for(fut, 5)
        finally:
            self._lookups.pop(rid, None)

    async def resolve(self, name: str) -> str:
        """Devuelve la grafía oficial del usuario o lanza ClientError si no existe."""
        if name in self.sessions:
            return name
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

    async def send_text(self, peer: str, text: str) -> None:
        await self.send_content(peer, content.text(text))

    async def send_content(self, peer: str, plaintext: str) -> None:
        peer = await self.resolve(peer)
        session = self.sessions.get(peer) or await self.open_session(peer)
        await self._send(type="send", to=peer, payload=session.encrypt(plaintext))

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
            for _, fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(ClientError("conexión cerrada"))
            self._emit("disconnected")

    async def _dispatch(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "deliver":
            await self._on_deliver(msg["from"], msg["payload"])
        elif t == "who" and self._who and not self._who.done():
            self._who.set_result(msg["users"])
        elif t == "lookup" and (fut := self._lookups.get(msg.get("id"))) and not fut.done():
            fut.set_result({"exists": msg["exists"], "user": msg["user"], "online": msg["online"]})
        elif t == "error" and (fut := self._lookups.get(msg.get("id"))) and not fut.done():
            fut.set_exception(ClientError(msg.get("message", "error del servidor")))
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
            elif kind == "msg":
                session = self.sessions.get(sender)
                if session is None:
                    raise CryptoError("mensaje sin sesión establecida")
                lost_before = session.lost
                text = session.decrypt(payload)
                if session.lost > lost_before:
                    self._emit("warning", sender, f"se perdieron {session.lost - lost_before} "
                               f"mensaje(s) de {sender} (¿manipulación en el servidor?)")
                c = content.decode(text)
                if c["t"] == "profile":
                    name = str(c.get("name") or "")[:content.MAX_NAME]
                    self.profiles[sender] = name
                    self._emit("profile", sender, name)
                else:
                    self._emit("message", sender, content.describe(c))
            else:
                raise CryptoError(f"tipo de payload desconocido: {kind!r}")
        except IdentityMismatch as exc:
            self._fail_pending(sender, exc)
            self._emit("identity_changed", sender, str(exc))
        except CryptoError as exc:
            if kind == "hs2":
                self._fail_pending(sender, exc)
            self._emit("warning", sender, f"descartado mensaje de {sender}: {exc}")

    async def _on_hs1(self, sender: str, hs1: dict) -> None:
        # Si los dos iniciamos a la vez, gana el handshake del nombre menor.
        if sender in self._pending and self.name < sender:
            return
        session, hs2 = Session.accept(self.name, self.identity, sender, hs1,
                                      self.contacts.pinned_key(sender))
        self.contacts.pin(sender, session.peer_identity)
        renewed = sender in self.sessions
        self.sessions[sender] = session
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
