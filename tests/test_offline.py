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


def stored_bytes(db):
    """Todo lo que el servidor ha escrito en disco (base de datos y su diario WAL)."""
    return b"".join(p.read_bytes() for p in (db.with_suffix(".db"), db.with_suffix(".db-wal")) if p.exists())


def srv_relay_queue_empty(db, prefix):
    from securechat.storage import Store
    st = Store(db.with_suffix(".db"))
    try:
        return st.queued_count(prefix) == 0
    finally:
        st.close()


def test_message_to_offline_user_survives_server_restart(tmp_path):
    async def main():
        db, queue = tmp_path / "users.json", tmp_path / "queue"
        ka, kb = SigningKey.generate(), SigningKey.generate()
        srv, url = await start(RelayServer(db, queue))
        bob = await client(url, "bob", kb, tmp_path)
        await bob.close()  # Bob publicó sus prekeys y se fue

        alice = await client(url, "alice", ka, tmp_path)
        assert await alice.send_text("bob", "¿estás?") == "queued"
        assert await alice.send_text("bob", "te escribo en diferido 🕓") == "queued"
        await alice.close()
        srv.close()
        await srv.wait_closed()

        # El servidor se reinicia: la cola (cifrada) sigue en disco
        stored = stored_bytes(db)
        assert b"bob|" in stored and "diferido".encode() not in stored
        srv, url = await start(RelayServer(db, queue))
        bob = await client(url, "bob", kb, tmp_path)
        assert (await next_event(bob, "message")).text == "¿estás?"
        assert (await next_event(bob, "message")).text == "te escribo en diferido 🕓"
        await asyncio.sleep(0.1)
        assert srv_relay_queue_empty(db, "bob|")  # entregados: la cola se vacía
        await bob.close()
        srv.close()
    run(main())


def test_one_time_prekeys_are_consumed_and_replenished(tmp_path):
    async def main():
        relay = RelayServer()
        srv, url = await start(relay)
        kb = SigningKey.generate()
        bob = await client(url, "bob", kb, tmp_path)
        dev = bob.device
        assert len(relay.registry["bob"]["devices"][dev]["opks"]) == 20
        await bob.close()
        for i in range(12):  # 12 personas distintas le escriben por primera vez
            other = await client(url, f"amigo{i}", SigningKey.generate(), tmp_path)
            await other.send_text("bob", "hola")
            await other.close()
        assert len(relay.registry["bob"]["devices"][dev]["opks"]) == 8  # una por cada inicio
        bob = await client(url, "bob", kb, tmp_path)  # al volver, repone (quedaban pocas)
        await asyncio.sleep(0.1)
        assert len(relay.registry["bob"]["devices"][dev]["opks"]) == 28
        for _ in range(12):
            assert (await next_event(bob, "message")).text == "hola"
        await bob.close(); srv.close()
    run(main())


def test_replayed_message_is_rejected(tmp_path):
    async def main():
        ka, kb = SigningKey.generate(), SigningKey.generate()
        relay = RelayServer()
        srv, url = await start(relay)
        bob = await client(url, "bob", kb, tmp_path)
        await bob.close()
        alice = await client(url, "alice", ka, tmp_path)
        await alice.send_text("bob", "una vez")
        qk = next(k for k in relay.queues if k.startswith("bob|"))
        relay.queues[qk] *= 2  # el servidor (malicioso) duplica el sobre
        bob = await client(url, "bob", kb, tmp_path)
        assert (await next_event(bob, "message")).text == "una vez"
        assert "No se pudo leer" in (await next_event(bob, "warning")).text
        await alice.close(); await bob.close(); srv.close()
    run(main())


def test_access_code(tmp_path):
    async def main():
        srv, url = await start(RelayServer(access_code="ABCD-2345"))
        status, _, body = await http_get(url, "/config.json")
        cfg = json.loads(body)
        assert status == 200 and cfg["code_required"] is True and cfg["email_required"] is False
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
        assert b"example.com" not in stored_bytes(db)  # solo se guarda la huella del correo
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


def test_push_notification_only_for_real_messages(tmp_path):
    async def main():
        relay = RelayServer(tmp_path / "u.json")
        calls = []

        async def fake_notify(account, subs, call=False):
            calls.append(account)
            return subs
        relay.pusher.notify = fake_notify
        srv, url = await start(relay)
        kb = SigningKey.generate()
        bob = await client(url, "bob", kb, tmp_path)
        sub = {"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": {"p256dh": "x", "auth": "y"}}
        await bob._send(type="push-sub", sub=sub)
        await bob._send(type="push-sub", sub={"endpoint": "http://inseguro", "keys": {}})  # se ignora
        await asyncio.sleep(0.1)
        await bob.close()
        assert relay.registry["bob"]["push"] == [sub]

        alice = await client(url, "alice", SigningKey.generate(), tmp_path)
        assert await alice.send_text("bob", "¿estás?") == "queued"
        await asyncio.sleep(0.1)
        assert calls == ["bob"]  # mensaje real: aviso
        await alice.send_content("bob", '{"t":"receipt","ids":[],"s":"read"}', silent=True)
        await alice.send_content("bob", '{"t":"typing","on":true}', ephemeral=True)
        await asyncio.sleep(0.1)
        assert calls == ["bob"]  # confirmación silenciosa y "escribiendo…": sin aviso
        assert relay.pusher.public_key  # clave pública VAPID para el navegador
        await alice.close(); srv.close()
    run(main())


def test_away_and_invisible_status(tmp_path):
    async def main():
        srv, url = await start(RelayServer())
        alice = await client(url, "alice", SigningKey.generate(), tmp_path)
        bob = await client(url, "bob", SigningKey.generate(), tmp_path)
        assert (await alice.lookup("bob"))["online"] is True

        await bob._send(type="privacy", last_seen=True, status="away")
        await asyncio.sleep(0.05)
        info = await alice.lookup("bob")
        assert info["online"] is True and info["away"] is True

        # Invisible: conectado, pero los demás lo ven desconectado
        await bob._send(type="privacy", last_seen=True, status="invisible")
        await asyncio.sleep(0.05)
        info = await alice.lookup("bob")
        assert info["online"] is False and info["away"] is False
        seen = info["last_seen"]

        # Al salir siendo invisible, su última conexión no se mueve
        await asyncio.sleep(1.1)
        await bob.close()
        await asyncio.sleep(0.05)
        assert (await alice.lookup("bob"))["last_seen"] == seen
        await alice.close()
        srv.close()
    run(main())


def test_login_with_email_and_change_it(tmp_path):
    async def main():
        from securechat.crypto import save_identity
        from securechat.email_verify import ConsoleSender
        sender = ConsoleSender()
        db = tmp_path / "users.json"
        srv, url = await start(RelayServer(db, None, None, sender))
        async def last_code(to, err):
            return sender.sent[-1][1]

        key = SigningKey.generate()
        c = ChatClient("Laura", key, Contacts(None), prekeys_path=tmp_path / "l.json")
        await c.connect(url, email="laura@example.com", on_verify=last_code)
        save_identity(tmp_path / "id.json", key, "contraseña larga", opslimit=2, memlimit=64 * 1024 * 1024)
        blob = json.loads((tmp_path / "id.json").read_text(encoding="utf-8"))
        await c._send(type="keystore", blob={**blob, "username": "Laura"})
        await asyncio.sleep(0.1)

        # Se encuentra la cuenta por el correo (sin distinguir mayúsculas), nunca por otro
        status, _, body = await http_get(url, "/keystore?user=Laura%40Example.com")
        assert status == 200 and json.loads(body)["user"] == "Laura"
        assert (await http_get(url, "/keystore?user=otra%40example.com"))[0] == 404

        # Cambiar el correo: código al correo nuevo; uno incorrecto no vale
        r = await c._request(type="set-email", email="laura.nueva@example.com")
        assert r["type"] == "email-code-sent" and sender.sent[-1][0] == "laura.nueva@example.com"
        with pytest.raises(ClientError, match="incorrecto"):
            await c._request(type="confirm-email", code="999999" if sender.sent[-1][1] != "999999" else "111111")
        assert (await c._request(type="confirm-email", code=sender.sent[-1][1]))["type"] == "email-ok"
        assert (await http_get(url, "/keystore?user=laura.nueva%40example.com"))[0] == 200
        assert (await http_get(url, "/keystore?user=laura%40example.com"))[0] == 404
        assert b"example.com" not in stored_bytes(db)

        # Otro usuario no puede quedarse con un correo ya usado
        other = ChatClient("Pablo", SigningKey.generate(), Contacts(None), prekeys_path=tmp_path / "p.json")
        await other.connect(url, email="pablo@example.com", on_verify=last_code)
        with pytest.raises(ClientError, match="ya tiene una cuenta"):
            await other._request(type="set-email", email="laura.nueva@example.com")
        await other.close()
        await c.close()
        srv.close()
    run(main())
