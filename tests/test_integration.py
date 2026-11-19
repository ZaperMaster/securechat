"""Servidor relay real + dos clientes, todo en el mismo proceso."""

import asyncio
import base64
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

        async def spy(ws, sender, dev, msg):
            seen.append(json.dumps(msg))
            await original(ws, sender, dev, msg)
        relay._relay = spy

        assert await alice.send_text("bob", "mensaje secreto 1234") == "delivered"
        ev = await next_event(bob, "message")
        assert (ev.peer, ev.text) == ("alice", "mensaje secreto 1234")
        await bob.send_text("alice", "recibido")
        assert (await next_event(alice, "message")).text == "recibido"

        assert not any("secreto" in s for s in seen)
        assert all('"kind": "dr"' in s for s in seen)  # todo va por Double Ratchet
        assert alice.contacts.pinned_key("bob") == bytes(bob.identity.verify_key)
        assert bob.contacts.pinned_key("alice") == bytes(alice.identity.verify_key)
        assert sorted(await alice.who()) == ["alice", "bob"]
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_simultaneous_first_messages():
    async def main():
        srv, url, _ = await start_server()
        alice, bob = await new_client(url, "alice"), await new_client(url, "bob")
        await asyncio.gather(alice.send_text("bob", "ping"), bob.send_text("alice", "pong"))
        assert (await next_event(bob, "message")).text == "ping"
        assert (await next_event(alice, "message")).text == "pong"
        for i in range(3):
            await alice.send_text("bob", f"a{i}")
            assert (await next_event(bob, "message")).text == f"a{i}"
            await bob.send_text("alice", f"b{i}")
            assert (await next_event(alice, "message")).text == f"b{i}"
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_unknown_user():
    async def main():
        srv, url, _ = await start_server()
        alice = await new_client(url, "alice")
        with pytest.raises(ClientError, match="no existe"):
            await alice.send_text("nadie", "hola")
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
            await ws.send(json.dumps({"type": "hello", "user": "eve", "device": "dispositivo1",
                                      "identity_key": b64e(bytes(key.verify_key))}))
            json.loads(await ws.recv())
            await ws.send(json.dumps({"type": "auth", "sig": b64e(bytes(64))}))
            assert json.loads(await ws.recv())["code"] == "auth_failed"
        srv.close()
    run(main())


def test_old_clients_are_told_to_update():
    async def main():
        srv, url, _ = await start_server()
        async with connect(url) as ws:
            from securechat.crypto import b64e
            await ws.send(json.dumps({"type": "hello", "user": "viejo",
                                      "identity_key": b64e(bytes(SigningKey.generate().verify_key))}))
            assert json.loads(await ws.recv())["code"] == "old_client"
        srv.close()
    run(main())


def test_identity_change_is_detected():
    """Bob reinstala (nueva clave) en un servidor que no lo recuerda: Alice lo detecta."""
    async def main():
        srv, url, _ = await start_server()
        alice_contacts = Contacts(None)
        alice = await new_client(url, "alice", contacts=alice_contacts)
        bob = await new_client(url, "bob")
        await alice.send_text("bob", "hola")
        await bob.close(); await alice.close(); srv.close()

        srv, url, _ = await start_server()  # servidor nuevo (o malicioso)
        alice = await new_client(url, "alice", key=alice.identity, contacts=alice_contacts)
        impostor = await new_client(url, "bob")
        from securechat.ratchet import IdentityMismatch
        with pytest.raises(IdentityMismatch):
            await alice.send_text("bob", "¿eres tú?")  # al enviar
        await impostor.send_text("alice", "soy bob, de verdad")  # y al recibir
        assert (await next_event(alice, "identity_changed")).peer == "bob"
        await alice.close(); await impostor.close(); srv.close()
    run(main())


def test_two_devices_same_account(tmp_path):
    """La misma cuenta en el móvil y el ordenador: los dos reciben, y lo que envía
    uno aparece también en el otro."""
    async def main():
        srv, url, _ = await start_server()
        key = SigningKey.generate()
        movil = ChatClient("ana", key, Contacts(None), prekeys_path=tmp_path / "movil.keys")
        pc = ChatClient("ana", key, Contacts(None), prekeys_path=tmp_path / "pc.keys")
        await movil.connect(url)
        await pc.connect(url)
        assert movil.device != pc.device
        bob = await new_client(url, "bob")

        await bob.send_text("ana", "hola Ana")
        assert (await next_event(movil, "message")).text == "hola Ana"
        assert (await next_event(pc, "message")).text == "hola Ana"

        await movil.send_text("bob", "te escribo desde el móvil")
        assert (await next_event(bob, "message")).text == "te escribo desde el móvil"
        sync = await next_event(pc, "sync")
        assert (sync.peer, sync.text) == ("bob", "te escribo desde el móvil")

        # El ordenador se desconecta; al volver recibe lo que llegó mientras tanto
        await pc.close()
        await bob.send_text("ana", "¿me lees en los dos?")
        assert (await next_event(movil, "message")).text == "¿me lees en los dos?"
        pc2 = ChatClient("ana", key, Contacts(None), prekeys_path=tmp_path / "pc.keys")
        await pc2.connect(url)
        assert pc2.device == pc.device
        assert (await next_event(pc2, "message")).text == "¿me lees en los dos?"
        assert len(await movil.devices()) == 2
        await movil.close(); await pc2.close(); await bob.close(); srv.close()
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
        info = await bob.lookup("alice.dev")
        assert (info["exists"], info["user"], info["online"], info["away"]) == (True, "Alice.Dev", True, False)
        assert (await bob.lookup("nadie"))["exists"] is False
        assert (await bob.lookup("../etc"))["exists"] is False
        # Escribir el nombre con otras mayúsculas llega a la misma persona
        await bob.send_text("ALICE.DEV", "hola")
        ev = await next_event(alice, "message")
        assert (ev.peer, ev.text) == ("bob", "hola")
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


def test_delete_account_frees_the_name():
    async def main():
        srv, url, relay = await start_server()
        key = SigningKey.generate()
        alice = await new_client(url, "alice", key)
        bob = await new_client(url, "bob")
        await bob.send_text("alice", "hola")
        await next_event(alice, "message")

        # Una firma que no es de la cuenta no borra nada
        bad = SigningKey.generate().sign(b"securechat-delete-account|alice").signature
        await alice.ws.send(json.dumps({"type": "delete-account", "id": "x", "sig": base64.b64encode(bad).decode()}))
        await asyncio.sleep(0.2)
        assert "alice" in relay.registry

        alice = await new_client(url, "alice", key)
        sig = key.sign(b"securechat-delete-account|alice").signature
        ack = await alice._request(type="delete-account", sig=base64.b64encode(sig).decode())
        assert ack["status"] == "ok"
        await asyncio.sleep(0.2)
        assert "alice" not in relay.registry
        assert not any(k.startswith("alice|") for k in relay.queues)
        assert "alice" not in relay.related.get("bob", set())

        # El nombre queda libre para otra persona (otra clave)
        other = await new_client(url, "alice")
        assert "alice" in relay.registry
        await other.close(); await bob.close(); srv.close()
    run(main())


def test_urgent_call_offer_wakes_the_phone_even_if_connected():
    async def main():
        srv, url, relay = await start_server()
        alice, bob = await new_client(url, "alice"), await new_client(url, "bob")
        calls = []

        async def fake_notify(account, subs, call=False):
            calls.append((account, call))
            return subs
        relay.pusher.notify = fake_notify
        relay.registry["bob"]["push"] = [{"endpoint": "https://push.example/x", "keys": {"p256dh": "a", "auth": "b"}}]

        # Un mensaje normal a alguien conectado no avisa por push
        ack = await alice._request(type="send", to="bob", device=bob.device, payload={"x": 1})
        assert ack["status"] == "delivered"
        await asyncio.sleep(0.1)
        assert calls == []

        # Una oferta de llamada (urgente) sí, aunque bob parezca conectado (Android congela la app)
        ack = await alice._request(type="send", to="bob", device=bob.device, payload={"x": 2}, urgent=True)
        assert ack["status"] == "delivered"
        await asyncio.sleep(0.1)
        assert calls == [("bob", True)]
        await alice.close(); await bob.close(); srv.close()
    run(main())
