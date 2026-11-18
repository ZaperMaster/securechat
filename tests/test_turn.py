"""El relé de llamadas (TURN) reenvía datos entre dos navegadores que no se ven."""

import asyncio
import secrets
import struct

from securechat import turn
from securechat.turn import (ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, DATA, DATA_ATTR, ERROR, INDICATION,
                             LIFETIME, NONCE, REALM, REQUEST, REQUESTED_TRANSPORT, SEND, SUCCESS, USERNAME,
                             XOR_PEER_ADDRESS, XOR_RELAYED_ADDRESS, build, enc_xor_address, make_credentials,
                             msg_type, parse, split_type, xor_address)

from test_integration import run


class Client:
    """Cliente TURN mínimo, como el de un navegador, para las pruebas."""

    def __init__(self, reader, writer, username, password):
        self.r, self.w, self.username, self.password = reader, writer, username, password
        self.key = None
        self.nonce = None

    async def read(self):
        head = await self.r.readexactly(4)
        if 0x40 <= head[0] <= 0x7F:
            chan, length = struct.unpack("!HH", head)
            data = await self.r.readexactly(length)
            if length % 4:
                await self.r.readexactly(-length % 4)
            return ("channel", chan, data)
        length = struct.unpack("!H", head[2:4])[0]
        buf = head + await self.r.readexactly(16 + length)
        t, tid, attrs = parse(buf)
        return ("msg", t, tid, {a: v for a, v, _ in attrs})

    async def request(self, method, attrs, auth=True):
        tid = secrets.token_bytes(12)
        extra = [(USERNAME, self.username.encode()), (REALM, b"securechat"), (NONCE, self.nonce)] if auth else []
        self.w.write(build(msg_type(method, REQUEST), tid, [*attrs, *extra], self.key if auth else None))
        _, t, rtid, got = await self.read()
        assert rtid == tid
        return split_type(t)[1], got, rtid


def test_turn_relays_between_two_clients():
    async def main():
        secret = secrets.token_bytes(32)
        server = await turn.TurnServer(secret).start("127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def connect(name):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            user, pwd = make_credentials(secret, name)
            c = Client(r, w, user, pwd)
            # Sin credenciales: el servidor responde 401 con el reto (realm + nonce)
            cls, got, _ = await c.request(ALLOCATE, [(REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))], auth=False)
            assert cls == ERROR and got[REALM] == b"securechat"
            c.nonce = got[NONCE]
            c.key = turn._long_term_key(user, pwd)
            cls, got, tid = await c.request(ALLOCATE, [(REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))])
            assert cls == SUCCESS and struct.unpack("!I", got[LIFETIME])[0] > 0
            c.relay = xor_address(got[XOR_RELAYED_ADDRESS], tid)
            return c

        a, b = await connect("ana"), await connect("bea")
        # Cada uno da permiso al relé del otro
        for me, other in ((a, b), (b, a)):
            tid = secrets.token_bytes(12)
            cls, _, _ = await me.request(CREATE_PERMISSION, [(XOR_PEER_ADDRESS, enc_xor_address(*other.relay, tid))])
            assert cls == SUCCESS

        # Ana envía con una indicación SEND; a Bea le llega como DATA
        tid = secrets.token_bytes(12)
        a.w.write(build(msg_type(SEND, INDICATION), tid, [(XOR_PEER_ADDRESS, enc_xor_address(*b.relay, tid)),
                                                          (DATA_ATTR, b"audio cifrado")]))
        kind, t, rtid, got = await asyncio.wait_for(b.read(), 3)
        assert split_type(t) == (DATA, INDICATION) and got[DATA_ATTR] == b"audio cifrado"
        assert xor_address(got[XOR_PEER_ADDRESS], rtid) == a.relay

        # Con un canal (ChannelBind), los datos van con una cabecera de solo 4 bytes
        tid = secrets.token_bytes(12)
        cls, _, _ = await b.request(CHANNEL_BIND, [(turn.CHANNEL_NUMBER, struct.pack("!HH", 0x4001, 0)),
                                                   (XOR_PEER_ADDRESS, enc_xor_address(*a.relay, tid))])
        assert cls == SUCCESS
        b.w.write(struct.pack("!HH", 0x4001, 5) + b"hola!" + b"\0\0\0")
        kind, t, rtid, got = await asyncio.wait_for(a.read(), 3)
        assert got[DATA_ATTR] == b"hola!"

        # Credenciales caducadas o inventadas: rechazadas
        r, w = await asyncio.open_connection("127.0.0.1", port)
        bad = Client(r, w, "1:intruso", "x")
        _, got, _ = await bad.request(ALLOCATE, [(REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))], auth=False)
        bad.nonce, bad.key = got[NONCE], turn._long_term_key("1:intruso", "x")
        cls, got, _ = await bad.request(ALLOCATE, [(REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))])
        assert cls == ERROR

        for c in (a, b, bad):
            c.w.close()
        server.close()
    run(main())
