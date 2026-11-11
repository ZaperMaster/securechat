"""Lógica de red del cliente, independiente de la interfaz (CLI, GUI o tests).

Protocolo v2 (ver ratchet.py): cada mensaje se cifra con Double Ratchet para CADA
dispositivo del destinatario, y además se manda una copia ("sync") a mis otros
dispositivos para que vean lo que he enviado. La primera vez con un dispositivo
se usa X3DH con sus prekeys, así que no hace falta que esté conectado.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from . import content
from .contacts import Contacts
from .crypto import CryptoError, b64d, b64e
from .ratchet import DeviceKeys, IdentityMismatch, decrypt_from, encrypt_for, initiate
from .server import MAX_FRAME, auth_message

DEVICE_CACHE_TTL = 60


class ClientError(Exception):
    pass


@dataclass
class Event:
    """Algo que la interfaz debe mostrar al usuario."""
    kind: str   # message | profile | receipt | sync | presence | identity_changed | warning | disconnected
    peer: str = ""
    text: str = ""


class ChatClient:
    def __init__(self, name: str, identity: SigningKey, contacts: Contacts,
                 prekeys_path: Path | None = None, code: str | None = None):
        self.name = name
        self.identity = identity
        self.contacts = contacts
        self.code = code  # código de acceso del servidor, si lo pide
        self.keys = DeviceKeys(name, identity, prekeys_path)
        self.my_devices: list[str] = []           # mis OTROS dispositivos
        self.online: dict[str, bool] = {}
        self.profiles: dict[str, str] = {}
        self._devices: dict[str, dict] = {}       # peer -> {"ik", "list", "bundles", "at"}
        self._requests: dict[int, asyncio.Future] = {}
        self._next_id = 0
        self._known: dict[str, str] = {}
        self._who: asyncio.Future | None = None
        self._send_lock = asyncio.Lock()
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self.ws: ClientConnection | None = None
        self._task: asyncio.Task | None = None

    @property
    def device(self) -> str:
        return self.keys.device

    # ------------------------------------------------------------ conexión

    async def connect(self, url: str, email: str | None = None, on_verify=None) -> None:
        """Conecta y se autentica. Si el servidor pide verificar el correo (solo al
        crear la cuenta), `on_verify(destino, error)` debe devolver el código recibido."""
        self.ws = await connect(url, max_size=MAX_FRAME)
        await self._send(type="hello", user=self.name, code=self.code, email=email, device=self.device,
                         identity_key=b64e(bytes(self.identity.verify_key)))
        challenge = json.loads(await self.ws.recv())
        if challenge.get("type") != "challenge":
            raise ClientError(challenge.get("message", "respuesta inesperada del servidor"))
        sig = self.identity.sign(auth_message(b64d(challenge["nonce"]), self.name)).signature
        await self._send(type="auth", sig=b64e(sig))
        welcome = json.loads(await self.ws.recv())
        error = target = None
        while welcome.get("type") in ("verify_needed", "verify_failed"):
            if on_verify is None:
                raise ClientError("este servidor pide verificar un correo al crear la cuenta")
            if welcome["type"] == "verify_needed":
                target = welcome["to"]
            else:
                error = welcome.get("message")
            await self._send(type="verify", code=await on_verify(target, error))
            welcome = json.loads(await self.ws.recv())
        if welcome.get("type") != "welcome":
            raise ClientError(welcome.get("message", "autenticación rechazada"))
        self.name = self.keys.user = welcome["user"]  # grafía oficial
        self.my_devices = welcome.get("devices", [])
        self._devices.clear()
        self._task = asyncio.create_task(self._recv_loop())
        await self._request(**self.keys.upload_message(welcome.get("opks", 0)))

    async def close(self) -> None:
        if self.ws:
            await self.ws.close()
        if self._task:
            await asyncio.gather(self._task, return_exceptions=True)

    # ------------------------------------------------------------- peticiones

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
        if name.lower() == self.name.lower():
            return self.name
        if name.lower() in self._known:
            return self._known[name.lower()]
        info = await self.lookup(name)
        if not info["exists"]:
            raise ClientError(f"el usuario '{name}' no existe")
        return info["user"]

    async def who(self) -> list[str]:
        self._who = asyncio.get_running_loop().create_future()
        await self._send(type="who")
        return await asyncio.wait_for(self._who, 5)

    async def devices(self) -> list[dict]:
        return (await self._request(type="devices"))["devices"]

    async def _peer_devices(self, peer: str, refresh: bool = False) -> dict:
        """Dispositivos de un usuario (con sus prekeys). Se cachean un minuto."""
        info = self._devices.get(peer.lower())
        if info and not refresh and time.monotonic() - info["at"] < DEVICE_CACHE_TTL:
            return info
        r = await self._request(type="bundle", user=peer)
        if not r.get("exists"):
            raise ClientError(f"el usuario '{peer}' no existe")
        ik = b64d(r["identity_key"])
        if peer.lower() != self.name.lower():
            pinned = self.contacts.pinned_key(r["user"])
            if pinned is not None and pinned != ik:
                raise IdentityMismatch(r["user"], pinned, ik)
            self.contacts.pin(r["user"], ik)
        info = {"user": r["user"], "ik": ik, "list": [d["device"] for d in r["devices"]],
                "bundles": {d["device"]: d for d in r["devices"]}, "at": time.monotonic()}
        self._devices[peer.lower()] = info
        return info

    # --------------------------------------------------------------- envío

    async def send_text(self, peer: str, text: str) -> str:
        return await self.send_content(peer, content.text(text))

    async def send_content(self, peer: str, plaintext: str, *, silent: bool = False,
                           ephemeral: bool = False, sync: bool = True) -> str:
        """Cifra y envía a todos los dispositivos de `peer` (y una copia a los míos).

        Devuelve "delivered" si algún dispositivo lo recibió ya, o "queued" si espera.
        """
        peer = await self.resolve(peer)
        if peer.lower() == self.name.lower():
            raise ClientError("no puedes escribirte a ti mismo")
        async with self._send_lock:  # el orden importa para el ratchet
            statuses = await self._send_to_user(peer, plaintext, silent=silent, ephemeral=ephemeral)
            if sync and not ephemeral and self.my_devices:
                wrapped = json.dumps({"t": "sync", "to": peer, "c": json.loads(plaintext)}, ensure_ascii=False)
                await self._send_to_user(self.name, wrapped, silent=True, ephemeral=False)
        return "delivered" if "delivered" in statuses else "queued"

    async def _send_to_user(self, user: str, plaintext: str, *, silent: bool, ephemeral: bool) -> list[str]:
        mine = user.lower() == self.name.lower()
        info = None
        if mine:
            targets = list(self.my_devices)
        else:
            info = await self._peer_devices(user)
            targets = list(info["list"])
        statuses = []
        tried: set[str] = set()
        while targets:
            dev = targets.pop(0)
            if dev in tried:
                continue
            tried.add(dev)
            r = self.keys.session(user, dev)
            if r is None:
                if ephemeral:
                    continue  # "escribiendo…" no merece abrir sesión
                if mine:
                    info = await self._peer_devices(self.name, refresh=True)
                elif dev not in info["bundles"]:
                    info = await self._peer_devices(user, refresh=True)
                bundle = info["bundles"].get(dev)
                if bundle is None:
                    continue  # ese dispositivo aún no ha publicado sus prekeys
                ik = info["ik"]
                r = initiate(self.name, self.device, self.identity, user if not mine else self.name, dev, ik,
                             bundle, None if mine else self.contacts.pinned_key(user))
                self.keys.push_new(user, dev, r)
            payload = encrypt_for(self.name, self.device, r, plaintext)
            self.keys.store(user, dev, r)
            try:
                ack = await self._request(type="send", to=user, device=dev, payload=payload,
                                          **({"silent": True} if silent else {}),
                                          **({"ephemeral": True} if ephemeral else {}))
            except ClientError as exc:
                if "dispositivo" in str(exc):
                    self.keys.drop(user, dev)
                    continue
                raise
            statuses.append(ack["status"])
            # ¿Tiene dispositivos que no conocíamos? También se lo mandamos a ellos
            fresh = [d for d in ack.get("devices", []) if d != self.device and d not in tried and d not in targets]
            if fresh and not mine:
                info = await self._peer_devices(user, refresh=True)
                targets += fresh
            elif fresh and mine:
                self.my_devices = [d for d in ack["devices"] if d != self.device]
                targets += fresh
        return statuses

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
            for fut in list(self._requests.values()):
                if not fut.done():
                    fut.set_exception(ClientError("conexión cerrada"))
            self._emit("disconnected")

    async def _dispatch(self, msg: dict) -> None:
        t = msg.get("type")
        fut = self._requests.get(msg.get("id")) if msg.get("id") is not None else None
        if t == "deliver":
            await self._on_deliver(msg["from"], msg["payload"])
        elif t == "my-devices":
            self.my_devices = [d for d in msg["devices"] if d != self.device]
            self._devices.pop(self.name.lower(), None)
        elif t == "presence":
            self.online[msg["user"]] = msg["online"]
            self._emit("presence", msg["user"], "en línea" if msg["online"] else "desconectado")
        elif fut is not None and not fut.done():
            if t == "error":
                fut.set_exception(ClientError(msg.get("message", "error del servidor")))
            else:
                fut.set_result(msg)
        elif t == "who" and self._who and not self._who.done():
            self._who.set_result(msg["users"])
        elif t == "error":
            self._emit("warning", msg.get("to") or "", msg.get("message", "error del servidor"))

    async def _on_deliver(self, sender: str, payload: dict) -> None:
        mine = sender.lower() == self.name.lower()
        try:
            if payload.get("kind") != "dr":
                raise CryptoError("formato antiguo: pídele que actualice la app")
            pinned = bytes(self.identity.verify_key) if mine else self.contacts.pinned_key(sender)
            text, ik = decrypt_from(self.name, self.keys, sender, payload, pinned)
            if ik is not None and not mine:
                self.contacts.pin(sender, ik)
            if mine and payload.get("dev") not in self.my_devices:
                self.my_devices.append(payload["dev"])
            self._on_content(sender, text, mine)
        except IdentityMismatch as exc:
            self._emit("identity_changed", sender, str(exc))
        except CryptoError as exc:
            self._emit("warning", sender, f"No se pudo leer un mensaje de {sender}: {exc}")

    def _on_content(self, sender: str, text: str, mine: bool) -> None:
        c = content.decode(text)
        if mine:
            if c["t"] == "sync" and isinstance(c.get("c"), dict):
                inner = c["c"]
                self._emit("sync", str(c.get("to", "")), content.describe(inner) if inner.get("t") not in content.SILENT else "")
            return
        if c.get("mid") and not self.keys.first_time(c["mid"]):
            return  # repetido
        if c["t"] == "receipt":
            self._emit("receipt", sender, f"{c.get('s')}:{','.join(c.get('ids', []))}")
            return
        if c["t"] in content.SILENT and c["t"] != "profile":
            return  # reacciones, ediciones, "escribiendo…", grupos: la terminal no los muestra
        if isinstance(c.get("mid"), str) and c["t"] != "profile":
            # Como el doble check de WhatsApp: "ya lo tengo" (va cifrado como cualquier mensaje)
            asyncio.get_running_loop().create_task(self._send_receipt(sender, [c["mid"]], "delivered"))
        if c["t"] == "profile":
            name = str(c.get("name") or "")[:content.MAX_NAME]
            self.profiles[sender] = name
            self._emit("profile", sender, name)
        else:
            prefix = "[grupo] " if c.get("g") else ""
            self._emit("message", sender, prefix + content.describe(c))

    async def _send_receipt(self, peer: str, ids: list[str], status: str) -> None:
        try:
            await self.send_content(peer, content.receipt(ids, status), silent=True, sync=False)
        except (ClientError, CryptoError):
            pass  # las confirmaciones son opcionales

    # ------------------------------------------------------------ utilidades

    def _emit(self, kind: str, peer: str = "", text: str = "") -> None:
        self.events.put_nowait(Event(kind, peer, text))

    async def _send(self, **msg) -> None:
        if self.ws is None:
            raise ClientError("no conectado")
        await self.ws.send(json.dumps(msg))
