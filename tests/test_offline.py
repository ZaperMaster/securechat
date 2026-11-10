"""Mensajes a usuarios desconectados, presencia y código de acceso."""

import asyncio
import json

import pytest
from nacl.signing import SigningKey
from websockets.asyncio.server import serve

from securechat.client import ChatClient, ClientError
from securechat.contacts import Contacts
from securechat.server import MAX_FRAME, RelayServer, serve_static

from test_integration import http_get, next_event, run


async def start(relay):
    srv = await serve(relay.handler, "127.0.0.1", 0, max_size=MAX_FRAME, process_request=serve_static)
    srv.relay = relay
    return srv, f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}"


async def client(url, name, key, tmp_path, code=None):
    c = ChatClient(name, key, Contacts(None), prekeys_path=tmp_path / f"{name}-prekeys.json", code=code)
    await c.connect(url)
    return c


def test_message_to_offline_user_survives_server_restart(tmp_path):
    async def main():
        db, queue = tmp_path / "users.json", tmp_path / "queue"
        ka, kb = SigningKey.generate(), SigningKey.generate()
        srv, url = await start(RelayServer(db, queue))
        bob = await client(url, "bob", kb, tmp_path)
        await bob.close()  # Bob publicó su prekey y se fue

        alice = await client(url, "alice", ka, tmp_path)
        assert await alice.send_text("bob", "¿estás?") == "queued"
        assert await alice.send_text("bob", "te escribo en diferido 🕓") == "queued"
        await alice.close()
        srv.close()
        await srv.wait_closed()

        # El servidor se reinicia: la cola (cifrada) sigue en disco
        assert list(queue.glob("*.json"))
        assert "diferido" not in (queue / "bob.json").read_text(encoding="utf-8")
        srv, url = await start(RelayServer(db, queue))
        bob = await client(url, "bob", kb, tmp_path)
        assert (await next_event(bob, "message")).text == "¿estás?"
        assert (await next_event(bob, "message")).text == "te escribo en diferido 🕓"
        assert not list(queue.glob("*.json"))  # entregados: la cola se vacía
        await bob.close()
        srv.close()
    run(main())


def test_presence_renews_sessions_after_reload(tmp_path):
    async def main():
        ka, kb = SigningKey.generate(), SigningKey.generate()
        srv, url = await start(RelayServer())
        alice, bob = await client(url, "alice", ka, tmp_path), await client(url, "bob", kb, tmp_path)
        assert await alice.send_text("bob", "uno") == "delivered"
        assert (await next_event(bob, "message")).text == "uno"
        assert "bob" in alice.sessions

        await bob.close()  # Bob recarga la página: pierde su sesión
        assert (await next_event(alice, "presence")).text == "desconectado"
        assert "bob" not in alice.sessions
        bob = await client(url, "bob", kb, tmp_path)
        assert (await next_event(alice, "presence")).text == "en línea"
        assert await alice.send_text("bob", "dos") == "delivered"  # sesión nueva, sin errores
        assert (await next_event(bob, "message")).text == "dos"
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_replayed_sealed_message_is_rejected(tmp_path):
    async def main():
        ka, kb = SigningKey.generate(), SigningKey.generate()
        relay = RelayServer()
        srv, url = await start(relay)
        bob = await client(url, "bob", kb, tmp_path)
        await bob.close()
        alice = await client(url, "alice", ka, tmp_path)
        await alice.send_text("bob", "una vez")
        relay.queues["bob"] *= 2  # el servidor (malicioso) duplica el sobre
        bob = await client(url, "bob", kb, tmp_path)
        assert (await next_event(bob, "message")).text == "una vez"
        assert "repetido" in (await next_event(bob, "warning")).text
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_access_code(tmp_path):
    async def main():
        srv, url = await start(RelayServer(access_code="ABCD-2345"))
        status, _, body = await http_get(url, "/config.json")
        assert status == 200 and json.loads(body) == {"code_required": True, "email_required": False}
        with pytest.raises(ClientError, match="código"):
            await client(url, "eve", SigningKey.generate(), tmp_path)
        with pytest.raises(ClientError, match="código"):
            await client(url, "eve", SigningKey.generate(), tmp_path, code="WXYZ-9999")
        ok = await client(url, "amigo", SigningKey.generate(), tmp_path, code="abcd2345")  # sin guion y en minúsculas vale
        await ok.close(); srv.close()
    run(main())


def test_email_verification_for_new_accounts(tmp_path):
    async def main():
        from securechat.email_verify import ConsoleSender
        sender = ConsoleSender()
        db = tmp_path / "users.json"
        srv, url = await start(RelayServer(db, None, None, sender))
        status, _, body = await http_get(url, "/config.json")
        assert json.loads(body)["email_required"] is True

        # Sin correo no se puede crear cuenta
        with pytest.raises(ClientError, match="correo"):
            await client(url, "bot", SigningKey.generate(), tmp_path)

        # Código incorrecto y luego el correcto
        key = SigningKey.generate()
        tries = []

        async def on_verify(to, error):
            tries.append((to, error))
            return "000000" if len(tries) == 1 and sender.sent[-1][1] != "000000" else sender.sent[-1][1]

        c = ChatClient("persona", key, Contacts(None), prekeys_path=tmp_path / "p.json")
        await c.connect(url, email="Persona.Real@Example.com", on_verify=on_verify)
        assert tries[0] == ("p**********l@example.com", None) and "incorrecto" in tries[1][1]
        assert "example.com" not in db.read_text()  # solo se guarda la huella del correo
        await c.close()

        # Las cuentas ya verificadas entran sin volver a pedirlo
        again = ChatClient("persona", key, Contacts(None), prekeys_path=tmp_path / "p.json")
        await again.connect(url)
        await again.close()

        # El mismo correo no sirve para otra cuenta
        other = ChatClient("otra", SigningKey.generate(), Contacts(None), prekeys_path=tmp_path / "o.json")
        with pytest.raises(ClientError, match="ya tiene una cuenta"):
            await other.connect(url, email="persona.real@example.com", on_verify=on_verify)
        srv.close()
    run(main())


def test_keystore_backup_allows_login_from_another_device(tmp_path):
    async def main():
        import nacl.pwhash
        from securechat.crypto import load_identity, save_identity
        srv, url = await start(RelayServer(tmp_path / "u.json", None, "CODE-1234"))
        key = SigningKey.generate()
        save_identity(tmp_path / "id.json", key, "contraseña larga", opslimit=2, memlimit=64 * 1024 * 1024)
        blob = json.loads((tmp_path / "id.json").read_text(encoding="utf-8"))
        c = await client(url, "Movil", key, tmp_path, code="CODE-1234")
        await c._send(type="keystore", blob={**blob, "username": "Movil"})
        await c._send(type="keystore", blob={**blob, "public_key": blob["salt"]})  # ajena: se rechaza
        await asyncio.sleep(0.2)
        assert c.ws.state.name == "OPEN"  # una copia mala no corta la conexión
        await c.close()

        assert (await http_get(url, "/keystore?user=movil"))[0] == 403  # sin código de acceso
        status, _, body = await http_get(url, "/keystore?user=movil&code=CODE-1234")
        assert status == 200
        got = json.loads(body)
        assert got["user"] == "Movil" and got["blob"]["public_key"] == blob["public_key"]
        # Otro dispositivo: con la copia y la contraseña recupera la misma identidad
        (tmp_path / "otro.json").write_text(json.dumps(got["blob"]), encoding="utf-8")
        assert bytes(load_identity(tmp_path / "otro.json", "contraseña larga")) == bytes(key)
        assert (await http_get(url, "/keystore?user=nadie&code=CODE-1234"))[0] == 404
        for _ in range(12):
            last = (await http_get(url, "/keystore?user=movil&code=CODE-1234"))[0]
        assert last == 429  # límite de descargas por minuto
        srv.close()
    run(main())
