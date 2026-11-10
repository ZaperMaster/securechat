"""Servidor relay real + dos clientes, todo en el mismo proceso."""

import asyncio
import json

import pytest
from nacl.signing import SigningKey
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

from securechat.client import ChatClient, ClientError
from securechat.contacts import Contacts
from securechat.server import MAX_FRAME, RelayServer, serve_static


async def next_event(client, kind, timeout=5):
    while True:
        ev = await asyncio.wait_for(client.events.get(), timeout)
        if ev.kind == kind:
            return ev


def run(coro):
    asyncio.run(asyncio.wait_for(coro, 20))


async def start_server(relay=None):
    relay = relay or RelayServer()
    srv = await serve(relay.handler, "127.0.0.1", 0, max_size=MAX_FRAME,
                      process_request=serve_static)
    port = srv.sockets[0].getsockname()[1]
    return srv, f"ws://127.0.0.1:{port}", relay


async def new_client(url, name, key=None, contacts=None):
    c = ChatClient(name, key or SigningKey.generate(), contacts or Contacts(None))
    await c.connect(url)
    return c


def test_end_to_end_chat():
    async def main():
        srv, url, relay = await start_server()
        alice, bob = await new_client(url, "alice"), await new_client(url, "bob")

        # Espiamos lo que pasa por el servidor para comprobar que no ve el texto.
        seen = []
        original = relay._relay

        async def spy(ws, sender, msg):
            seen.append(json.dumps(msg))
            await original(ws, sender, msg)
        relay._relay = spy

        await alice.send_text("bob", "mensaje secreto 1234")
        ev = await next_event(bob, "message")
        assert (ev.peer, ev.text) == ("alice", "mensaje secreto 1234")

        await bob.send_text("alice", "recibido")
        assert (await next_event(alice, "message")).text == "recibido"

        assert not any("secreto" in s for s in seen)
        assert alice.contacts.pinned_key("bob") == bytes(bob.identity.verify_key)
        assert bob.contacts.pinned_key("alice") == bytes(alice.identity.verify_key)
        assert sorted(await alice.who()) == ["alice", "bob"]

        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_simultaneous_open():
    async def main():
        srv, url, _ = await start_server()
        alice, bob = await new_client(url, "alice"), await new_client(url, "bob")
        await asyncio.gather(alice.open_session("bob"), bob.open_session("alice"))
        await alice.send_text("bob", "ping")
        assert (await next_event(bob, "message")).text == "ping"
        await bob.send_text("alice", "pong")
        assert (await next_event(alice, "message")).text == "pong"
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_offline_peer():
    async def main():
        srv, url, _ = await start_server()
        alice = await new_client(url, "alice")
        with pytest.raises(ClientError):
            await alice.open_session("nadie")
        await alice.close(); srv.close()
    run(main())


def test_name_squatting_rejected():
    async def main():
        srv, url, _ = await start_server()
        await (await new_client(url, "alice")).close()
        with pytest.raises(ClientError):
            await new_client(url, "alice")  # otra clave, mismo nombre
        srv.close()
    run(main())


def test_bad_auth_signature_rejected():
    async def main():
        srv, url, _ = await start_server()
        key = SigningKey.generate()
        async with connect(url) as ws:
            from securechat.crypto import b64e
            await ws.send(json.dumps({"type": "hello", "user": "eve",
                                      "identity_key": b64e(bytes(key.verify_key))}))
            json.loads(await ws.recv())
            await ws.send(json.dumps({"type": "auth", "sig": b64e(bytes(64))}))
            assert json.loads(await ws.recv())["code"] == "auth_failed"
        srv.close()
    run(main())


def test_identity_change_is_detected():
    """Bob reinstala (nueva clave) en un servidor que no lo recuerda: Alice lo detecta."""
    async def main():
        srv, url, _ = await start_server()
        alice_contacts = Contacts(None)
        alice = await new_client(url, "alice", contacts=alice_contacts)
        bob = await new_client(url, "bob")
        await alice.open_session("bob")
        await bob.close(); await alice.close(); srv.close()

        srv, url, _ = await start_server()  # servidor nuevo (o malicioso)
        alice = await new_client(url, "alice", key=alice.identity, contacts=alice_contacts)
        impostor = await new_client(url, "bob")
        with pytest.raises(ClientError):
            await impostor.open_session("alice", timeout=1)
        ev = await next_event(alice, "identity_changed")
        assert ev.peer == "bob"
        await alice.close(); await impostor.close(); srv.close()
    run(main())


async def http_get(url, path):
    host, port = url.removeprefix("ws://").split(":")
    reader, writer = await asyncio.open_connection(host, int(port))
    writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = await reader.read()
    writer.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return int(head.split()[1]), head.decode(), body


def test_serves_web_app_safely():
    async def main():
        srv, url, _ = await start_server()
        status, head, body = await http_get(url, "/")
        assert status == 200 and b"SecureChat" in body
        assert "Content-Security-Policy" in head and "text/html" in head
        status, head, _ = await http_get(url, "/js/protocol.js")
        assert status == 200 and "text/javascript" in head
        for evil in ("/../securechat/server.py", "/%2e%2e/README.md", r"/..\README.md", "/nope.js"):
            assert (await http_get(url, evil))[0] == 404, evil
        srv.close()
    run(main())


def test_lookup_and_case_insensitive_names():
    async def main():
        srv, url, _ = await start_server()
        alice = await new_client(url, "Alice.Dev")
        bob = await new_client(url, "bob")
        assert await bob.lookup("alice.dev") == {"exists": True, "user": "Alice.Dev", "online": True}
        assert (await bob.lookup("nadie"))["exists"] is False
        assert (await bob.lookup("../etc"))["exists"] is False
        # Escribir el nombre con otras mayúsculas llega a la misma persona
        await bob.send_text("ALICE.DEV", "hola")
        ev = await next_event(alice, "message")
        assert (ev.peer, ev.text) == ("bob", "hola")
        assert "Alice.Dev" in bob.sessions
        # Nadie puede registrar el mismo nombre cambiando mayúsculas
        with pytest.raises(ClientError):
            await new_client(url, "alice.dev")
        # Mensajes a usuarios inexistentes: error claro, sin crear sesión
        with pytest.raises(ClientError, match="no existe"):
            await bob.send_text("fantasma", "¿hola?")
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_media_and_profile_content():
    async def main():
        from securechat import content
        srv, url, _ = await start_server()
        alice, bob = await new_client(url, "alice"), await new_client(url, "bob")
        img = {"t": "image", "mime": "image/png", "name": "foto.png", "data": "A" * 3_000_000}
        await alice.send_content("bob", json.dumps(img))
        assert (await next_event(bob, "message")).text == "[imagen: foto.png]"
        await alice.send_content("bob", json.dumps({"t": "profile", "name": "Alicia 🌸", "avatar": None}))
        assert (await next_event(bob, "profile")).text == "Alicia 🌸"
        assert content.decode("no es json") == {"t": "text", "body": "no es json"}
        await alice.close(); await bob.close(); srv.close()
    run(main())
