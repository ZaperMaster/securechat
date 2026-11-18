"""Servidor TURN mínimo (RFC 5766 / 8656) sobre TCP para las llamadas.

Cuando dos dispositivos no pueden verse directamente (wifi con los equipos aislados,
routers que no dejan "salir y volver a entrar", datos móviles...), el audio y el vídeo
pasan por aquí. Siguen cifrados de extremo a extremo con DTLS-SRTP: este servidor solo
reenvía paquetes que no puede leer.

Solo lo pueden usar quienes han iniciado sesión: las credenciales son temporales, al
estilo de la "TURN REST API" que entienden los navegadores:
    usuario    = "<caducidad unix>:<nombre>"
    contraseña = base64(HMAC-SHA1(secreto del servidor, usuario))

Escucha solo en este equipo (TCP). Desde internet se llega a través de Tailscale Funnel,
que pone el TLS (`turns:`). Las "direcciones de relé" son puertos UDP de este mismo
equipo: como los dos participantes usan este servidor, los paquetes van de un relé a otro
sin salir del ordenador.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import socket
import struct
import time
import zlib

log = logging.getLogger("securechat.turn")

MAGIC = 0x2112A442
MAGIC_BYTES = struct.pack("!I", MAGIC)

# Métodos y clases de mensaje STUN/TURN
BINDING, ALLOCATE, REFRESH, SEND, DATA, CREATE_PERMISSION, CHANNEL_BIND = 0x001, 0x003, 0x004, 0x006, 0x007, 0x008, 0x009
REQUEST, INDICATION, SUCCESS, ERROR = 0x000, 0x010, 0x100, 0x110

# Atributos
USERNAME, MESSAGE_INTEGRITY, ERROR_CODE = 0x0006, 0x0008, 0x0009
CHANNEL_NUMBER, LIFETIME, XOR_PEER_ADDRESS, DATA_ATTR = 0x000C, 0x000D, 0x0012, 0x0013
REALM, NONCE, XOR_RELAYED_ADDRESS, REQUESTED_TRANSPORT = 0x0014, 0x0015, 0x0016, 0x0019
XOR_MAPPED_ADDRESS, SOFTWARE, FINGERPRINT = 0x0020, 0x8022, 0x8028

REALM_NAME = "securechat"
DEFAULT_LIFETIME = 600
MAX_LIFETIME = 3600
PERMISSION_TTL = 300
MAX_ALLOCATIONS = 200
CRED_TTL = 12 * 3600


# --------------------------------------------------------------- credenciales

def make_credentials(secret: bytes, user: str, ttl: int = CRED_TTL) -> tuple[str, str]:
    username = f"{int(time.time()) + ttl}:{user}"
    return username, _password(secret, username)


def _password(secret: bytes, username: str) -> str:
    return base64.b64encode(hmac.new(secret, username.encode(), hashlib.sha1).digest()).decode()


def _long_term_key(username: str, password: str) -> bytes:
    return hashlib.md5(f"{username}:{REALM_NAME}:{password}".encode()).digest()  # noqa: S324 - lo exige el RFC


# --------------------------------------------------------------- mensajes

def msg_type(method: int, cls: int) -> int:
    return (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | cls


def split_type(t: int) -> tuple[int, int]:
    method = (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2)
    return method, t & 0x0110


def parse(buf: bytes) -> tuple[int, bytes, list[tuple[int, bytes, int]]]:
    """-> (tipo, id de transacción, [(atributo, valor, posición)])"""
    t, length, magic = struct.unpack_from("!HHI", buf, 0)
    if magic != MAGIC or len(buf) < 20 + length:
        raise ValueError("no es un mensaje STUN")
    tid, attrs, off = buf[8:20], [], 20
    while off + 4 <= 20 + length:
        at, al = struct.unpack_from("!HH", buf, off)
        attrs.append((at, buf[off + 4:off + 4 + al], off))
        off += 4 + ((al + 3) & ~3)
    return t, tid, attrs


def build(t: int, tid: bytes, attrs: list[tuple[int, bytes]], key: bytes | None = None, fingerprint: bool = True) -> bytes:
    body = b"".join(struct.pack("!HH", at, len(v)) + v + b"\0" * (-len(v) % 4) for at, v in attrs)
    if key:
        head = struct.pack("!HH", t, len(body) + 24) + MAGIC_BYTES + tid
        body += struct.pack("!HH", MESSAGE_INTEGRITY, 20) + hmac.new(key, head + body, hashlib.sha1).digest()
    if fingerprint:
        head = struct.pack("!HH", t, len(body) + 8) + MAGIC_BYTES + tid
        body += struct.pack("!HHI", FINGERPRINT, 4, (zlib.crc32(head + body) ^ 0x5354554E) & 0xFFFFFFFF)
    return struct.pack("!HH", t, len(body)) + MAGIC_BYTES + tid + body


def integrity_ok(buf: bytes, attrs: list[tuple[int, bytes, int]], key: bytes) -> bool:
    for at, val, off in attrs:
        if at == MESSAGE_INTEGRITY:
            head = buf[0:2] + struct.pack("!H", off + 24 - 20) + buf[4:20]
            return hmac.compare_digest(hmac.new(key, head + buf[20:off], hashlib.sha1).digest(), val)
    return False


def xor_address(val: bytes, tid: bytes) -> tuple[str, int]:
    family, port = val[1], struct.unpack("!H", val[2:4])[0] ^ (MAGIC >> 16)
    if family == 1:
        raw = bytes(a ^ b for a, b in zip(val[4:8], MAGIC_BYTES))
        return socket.inet_ntop(socket.AF_INET, raw), port
    raw = bytes(a ^ b for a, b in zip(val[4:20], MAGIC_BYTES + tid))
    return socket.inet_ntop(socket.AF_INET6, raw), port


def enc_xor_address(ip: str, port: int, tid: bytes) -> bytes:
    if ":" in ip:
        family, raw, key = 2, socket.inet_pton(socket.AF_INET6, ip), MAGIC_BYTES + tid
    else:
        family, raw, key = 1, socket.inet_pton(socket.AF_INET, ip), MAGIC_BYTES
    return struct.pack("!BBH", 0, family, port ^ (MAGIC >> 16)) + bytes(a ^ b for a, b in zip(raw, key))


def error_attr(code: int, reason: str) -> tuple[int, bytes]:
    return ERROR_CODE, struct.pack("!HBB", 0, code // 100, code % 100) + reason.encode()


# --------------------------------------------------------------- relés

class _RelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, alloc: "Allocation"):
        self.alloc = alloc

    def datagram_received(self, data: bytes, addr) -> None:
        self.alloc.from_peer(data, (addr[0], addr[1]))


class Allocation:
    """Un puerto UDP de relé, ligado a una conexión TCP de un navegador."""

    def __init__(self, conn: "_Conn", transport: asyncio.DatagramTransport, relay_ip: str, lifetime: int):
        self.conn, self.transport, self.relay_ip = conn, transport, relay_ip
        self.port = transport.get_extra_info("sockname")[1]
        self.expires = time.monotonic() + lifetime
        self.perms: dict[str, float] = {}
        self.channels: dict[int, tuple[str, int]] = {}
        self.by_addr: dict[tuple[str, int], int] = {}

    def permitted(self, ip: str) -> bool:
        return self.perms.get(ip, 0) > time.monotonic()

    def from_peer(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.permitted(addr[0]):
            return
        chan = self.by_addr.get(addr)
        if chan is not None:
            self.conn.write(struct.pack("!HH", chan, len(data)) + data + b"\0" * (-len(data) % 4))
        else:
            tid = secrets.token_bytes(12)
            self.conn.write(build(msg_type(DATA, INDICATION), tid,
                                  [(XOR_PEER_ADDRESS, enc_xor_address(*addr, tid)), (DATA_ATTR, data)], fingerprint=False))

    def send_to(self, addr: tuple[str, int], data: bytes) -> None:
        if self.permitted(addr[0]) and not self.transport.is_closing():
            self.transport.sendto(data, addr)

    def close(self) -> None:
        self.transport.close()


class _Conn:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        peer = writer.get_extra_info("peername") or ("127.0.0.1", 0)
        self.addr = (peer[0], peer[1])
        self.nonce = secrets.token_hex(12).encode()
        self.alloc: Allocation | None = None

    def write(self, data: bytes) -> None:
        if not self.writer.is_closing():
            self.writer.write(data)


class TurnServer:
    def __init__(self, secret: bytes, relay_ip: str = "127.0.0.1"):
        self.secret, self.relay_ip = secret, relay_ip
        self.allocations: set[Allocation] = set()

    async def start(self, host: str, port: int) -> asyncio.base_events.Server:
        server = await asyncio.start_server(self._handle, host, port)
        asyncio.get_running_loop().create_task(self._expire())
        log.info("relé de llamadas (TURN) en tcp://%s:%d", host, port)
        return server

    async def _expire(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            for a in [a for a in self.allocations if a.expires < now]:
                self._drop(a)

    def _drop(self, a: Allocation) -> None:
        a.close()
        self.allocations.discard(a)
        if a.conn.alloc is a:
            a.conn.alloc = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = _Conn(writer)
        try:
            while True:
                head = await reader.readexactly(4)
                if 0x40 <= head[0] <= 0x7F:  # ChannelData: número de canal + longitud + datos (+ relleno)
                    chan, length = struct.unpack("!HH", head)
                    data = await reader.readexactly(length)
                    if length % 4:
                        await reader.readexactly(-length % 4)
                    if conn.alloc and chan in conn.alloc.channels:
                        conn.alloc.send_to(conn.alloc.channels[chan], data)
                    continue
                length = struct.unpack("!H", head[2:4])[0]
                buf = head + await reader.readexactly(16 + length)
                try:
                    await self._message(conn, buf)
                except (ValueError, struct.error, OSError) as exc:
                    log.debug("mensaje TURN descartado: %s", exc)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            if conn.alloc:
                self._drop(conn.alloc)
            writer.close()

    async def _message(self, conn: _Conn, buf: bytes) -> None:
        t, tid, attrs = parse(buf)
        method, cls = split_type(t)
        get = lambda a: next((v for at, v, _ in attrs if at == a), None)  # noqa: E731
        alloc = conn.alloc

        if cls == INDICATION and method == SEND:
            peer, data = get(XOR_PEER_ADDRESS), get(DATA_ATTR)
            if alloc and peer and data is not None:
                alloc.send_to(xor_address(peer, tid), data)
            return
        if cls != REQUEST:
            return

        def reply(attrs_out, key=None):
            conn.write(build(msg_type(method, SUCCESS), tid, attrs_out, key))

        def fail(code, reason, key=None, challenge=False):
            extra = [(REALM, REALM_NAME.encode()), (NONCE, conn.nonce)] if challenge else []
            conn.write(build(msg_type(method, ERROR), tid, [error_attr(code, reason), *extra], key))

        if method == BINDING:
            return reply([(XOR_MAPPED_ADDRESS, enc_xor_address(*conn.addr, tid))])

        # Todo lo demás exige credenciales válidas (TURN de largo plazo)
        username = get(USERNAME)
        if username is None or get(MESSAGE_INTEGRITY) is None:
            return fail(401, "Unauthorized", challenge=True)
        if get(NONCE) != conn.nonce:
            return fail(438, "Stale Nonce", challenge=True)
        name = username.decode(errors="replace")
        expiry = name.split(":", 1)[0]
        if not expiry.isdigit() or int(expiry) < time.time():
            return fail(401, "Unauthorized", challenge=True)
        key = _long_term_key(name, _password(self.secret, name))
        if not integrity_ok(buf, attrs, key):
            return fail(401, "Unauthorized", challenge=True)

        if method == ALLOCATE:
            if alloc:
                return fail(437, "Allocation Mismatch", key)
            transport_attr = get(REQUESTED_TRANSPORT)
            if not transport_attr or transport_attr[0] != 17:
                return fail(442, "Unsupported Transport Protocol", key)
            if len(self.allocations) >= MAX_ALLOCATIONS:
                return fail(486, "Allocation Quota Reached", key)
            lifetime = min(MAX_LIFETIME, struct.unpack("!I", get(LIFETIME))[0] if get(LIFETIME) else DEFAULT_LIFETIME)
            loop = asyncio.get_running_loop()
            # El protocolo se crea antes que la Allocation: se enlazan justo después
            proto = _RelayProtocol(None)  # type: ignore[arg-type]
            transport, _ = await loop.create_datagram_endpoint(lambda: proto, local_addr=(self.relay_ip, 0))
            alloc = conn.alloc = Allocation(conn, transport, self.relay_ip, lifetime)
            proto.alloc = alloc
            self.allocations.add(alloc)
            return reply([(XOR_RELAYED_ADDRESS, enc_xor_address(self.relay_ip, alloc.port, tid)),
                          (XOR_MAPPED_ADDRESS, enc_xor_address(*conn.addr, tid)),
                          (LIFETIME, struct.pack("!I", lifetime))], key)

        if alloc is None:
            return fail(437, "Allocation Mismatch", key)

        if method == REFRESH:
            lifetime = min(MAX_LIFETIME, struct.unpack("!I", get(LIFETIME))[0] if get(LIFETIME) else DEFAULT_LIFETIME)
            if lifetime == 0:
                self._drop(alloc)
            else:
                alloc.expires = time.monotonic() + lifetime
            return reply([(LIFETIME, struct.pack("!I", lifetime))], key)

        if method == CREATE_PERMISSION:
            peers = [v for at, v, _ in attrs if at == XOR_PEER_ADDRESS]
            if not peers:
                return fail(400, "Bad Request", key)
            for v in peers:
                alloc.perms[xor_address(v, tid)[0]] = time.monotonic() + PERMISSION_TTL
            return reply([], key)

        if method == CHANNEL_BIND:
            chan_attr, peer = get(CHANNEL_NUMBER), get(XOR_PEER_ADDRESS)
            if not chan_attr or not peer:
                return fail(400, "Bad Request", key)
            chan = struct.unpack("!H", chan_attr[:2])[0]
            addr = xor_address(peer, tid)
            if not 0x4000 <= chan <= 0x7FFF or alloc.by_addr.get(addr, chan) != chan \
                    or alloc.channels.get(chan, addr) != addr:
                return fail(400, "Bad Request", key)
            alloc.channels[chan] = addr
            alloc.by_addr[addr] = chan
            alloc.perms[addr[0]] = time.monotonic() + PERMISSION_TTL
            return reply([], key)

        return fail(400, "Bad Request", key)
