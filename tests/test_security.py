"""Pruebas de las protecciones del servidor (revisión de seguridad)."""

import asyncio
import base64
import hashlib
import json

import pytest
from nacl.signing import SigningKey
from websockets.datastructures import Headers

from securechat.push import valid_push_endpoint, valid_subscription
from securechat.server import KEYSTORE_AUTH_FAILS, RelayServer, real_ip

from test_integration import http_get, new_client, run, start_server


# ---------------------------------------------------------------- push (SSRF)

@pytest.mark.parametrize("endpoint", [
    "https://fcm.googleapis.com/fcm/send/abc",
    "https://updates.push.services.mozilla.com/wpush/v2/abc",
    "https://wns2-par02p.notify.windows.com/w/?token=abc",
    "https://web.push.apple.com/abc",
])
def test_real_push_services_are_accepted(endpoint):
    assert valid_push_endpoint(endpoint)


@pytest.mark.parametrize("endpoint", [
    "https://192.168.1.1/admin", "https://localhost/x", "http://fcm.googleapis.com/x",
    "https://fcm.googleapis.com.evil.com/x", "https://evilgoogleapis.com/x", "https://fcm.googleapis.com:8443/x",
    "https://user:pw@fcm.googleapis.com/x", "https://[::1]/x", 42, None,
])
def test_other_push_endpoints_are_rejected(endpoint):
    assert not valid_push_endpoint(endpoint)
    assert not valid_subscription({"endpoint": endpoint, "keys": {"p256dh": "a", "auth": "b"}})


# ---------------------------------------------------------------- IP real

def test_real_ip_uses_the_proxy_address_not_the_client_one():
    h = Headers({"X-Forwarded-For": "1.2.3.4, 203.0.113.7"})  # el cliente puso 1.2.3.4
    assert real_ip(("127.0.0.1", 5555), h) == "203.0.113.7"
    assert real_ip(("127.0.0.1", 5555), Headers({"CF-Connecting-IP": "198.51.100.2", "X-Forwarded-For": "9.9.9.9"})) == "198.51.100.2"
    # Si la conexión no viene del túnel local, las cabeceras no cuentan
    assert real_ip(("203.0.113.9", 5555), h) == "203.0.113.9"


# ---------------------------------------------------------------- copia de la clave con prueba de contraseña

def test_keystore_needs_password_proof_and_locks_after_failures():
    async def main():
        srv, url, relay = await start_server()
        srv.relay = relay
        key = SigningKey.generate()
        c = await new_client(url, "movil", key)
        blob = {"version": 1, "kdf": "argon2id", "opslimit": 2, "memlimit": 64 * 1024 * 1024,
                "salt": base64.b64encode(b"s" * 16).decode(), "public_key": base64.b64encode(bytes(key.verify_key)).decode(),
                "ciphertext": base64.b64encode(b"c" * 72).decode(), "username": "movil"}
        proof = b"p" * 32
        await c._send(type="keystore", blob=blob, auth=base64.b64encode(proof).decode())
        await asyncio.sleep(0.2)
        assert relay.registry["movil"]["keystore_auth"] == hashlib.sha256(proof).hexdigest()

        # Sin la prueba: solo los parámetros de Argon2id, nunca el texto cifrado
        status, _, body = await http_get(url, "/keystore?user=movil")
        got = json.loads(body)
        assert status == 200 and got["auth_required"] and "ciphertext" not in json.dumps(got)
        assert got["params"]["salt"] == blob["salt"]

        # Con la prueba correcta: la copia
        ok = {"X-SC-Keystore-Auth": base64.b64encode(proof).decode()}
        status, _, body = await http_get(url, "/keystore?user=movil", ok)
        assert status == 200 and json.loads(body)["blob"]["ciphertext"] == blob["ciphertext"]

        # Contraseñas incorrectas: 403 y, tras varias, bloqueo aunque luego acierte
        bad = {"X-SC-Keystore-Auth": base64.b64encode(b"x" * 32).decode()}
        relay._keystore_hits.clear()
        for _ in range(KEYSTORE_AUTH_FAILS):
            assert (await http_get(url, "/keystore?user=movil", bad))[0] == 403
            relay._keystore_hits.clear()  # (el límite por IP es aparte)
        assert (await http_get(url, "/keystore?user=movil", ok))[0] == 429
        await c.close(); srv.close()
    run(main())


def test_new_keystore_drops_the_old_proof():
    async def main():
        srv, url, relay = await start_server()
        key = SigningKey.generate()
        c = await new_client(url, "ana", key)
        base = {"version": 1, "kdf": "argon2id", "opslimit": 2, "memlimit": 64 * 1024 * 1024,
                "public_key": base64.b64encode(bytes(key.verify_key)).decode(), "ciphertext": "AAAA"}
        await c._send(type="keystore", blob={**base, "salt": "c2FsMQ=="}, auth=base64.b64encode(b"a" * 32).decode())
        await asyncio.sleep(0.1)
        await c._send(type="keystore", blob={**base, "salt": "c2FsMg=="})  # contraseña cambiada, sin prueba aún
        await asyncio.sleep(0.1)
        assert "keystore_auth" not in relay.registry["ana"]
        await c.close(); srv.close()
    run(main())


# ---------------------------------------------------------------- correos de verificación

class CountingSender:
    def __init__(self):
        self.sent = []

    async def send(self, to, code, purpose="signup"):
        self.sent.append(to)


def test_verification_emails_are_rate_limited_per_address():
    async def main():
        sender = CountingSender()
        srv, url, relay = await start_server(RelayServer(email_sender=sender))
        for i in range(5):
            c = await asyncio.wait_for(_try_register(url, f"user{i}", "victima@example.com"), 5)
        assert len(sender.sent) == 3  # el resto se rechaza: nadie puede llenar el correo de otro
        srv.close()
    run(main())


async def _try_register(url, name, email):
    from securechat.client import ChatClient, ClientError
    from securechat.contacts import Contacts
    c = ChatClient(name, SigningKey.generate(), Contacts(None))

    async def give_up(*_):
        raise ClientError("cancelado")
    try:
        await c.connect(url, email=email, on_verify=give_up)
    except (ClientError, Exception):  # noqa: BLE001 - aquí solo cuenta cuántos correos salieron
        pass
    finally:
        try:
            await c.close()
        except Exception:  # noqa: BLE001
            pass
    return c


# ---------------------------------------------------------------- código de recuperación

def test_recovery_copy_needs_the_code_proof():
    async def main():
        srv, url, relay = await start_server()
        srv.relay = relay
        key = SigningKey.generate()
        c = await new_client(url, "olvidadiza", key)
        blob = {"version": 1, "public_key": base64.b64encode(bytes(key.verify_key)).decode(),
                "ciphertext": base64.b64encode(b"r" * 72).decode()}
        proof = b"k" * 32
        await c._send(type="recovery", blob=blob, auth=base64.b64encode(proof).decode())
        await asyncio.sleep(0.2)
        assert relay.registry["olvidadiza"]["recovery_auth"] == hashlib.sha256(proof).hexdigest()
        ok = {"X-SC-Recovery-Auth": base64.b64encode(proof).decode()}
        status, _, body = await http_get(url, "/keystore?user=olvidadiza&recovery=1", ok)
        assert status == 200 and json.loads(body)["recovery"]["ciphertext"] == blob["ciphertext"]
        # Sin prueba o con una falsa: nada (y cuenta como intento fallido)
        assert (await http_get(url, "/keystore?user=olvidadiza&recovery=1"))[0] == 403
        bad = {"X-SC-Recovery-Auth": base64.b64encode(b"x" * 32).decode()}
        assert (await http_get(url, "/keystore?user=olvidadiza&recovery=1", bad))[0] == 403
        assert len(relay._keystore_fails["olvidadiza"]) == 2
        # Una copia de OTRA clave se rechaza
        other = {**blob, "public_key": base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()}
        await c._send(type="recovery", blob=other, auth=base64.b64encode(b"z" * 32).decode())
        await asyncio.sleep(0.2)
        assert relay.registry["olvidadiza"]["recovery_auth"] == hashlib.sha256(proof).hexdigest()
        # Quitar el código
        await c._send(type="recovery-delete")
        await asyncio.sleep(0.2)
        assert "recovery" not in relay.registry["olvidadiza"]
        await c.close(); srv.close()
    run(main())


# ---------------------------------------------------------------- bloqueos y denuncias

def test_block_hides_presence_and_report_is_stored(tmp_path):
    async def main():
        srv, url, relay = await start_server(RelayServer(tmp_path / "users.json"))
        ana, troll = await new_client(url, "ana"), await new_client(url, "troll")
        await ana._send(type="block", user="TROLL", on=True)
        await asyncio.sleep(0.2)
        assert relay.registry["ana"]["blocked"] == ["troll"]
        assert relay._lookup("ana", "troll")["online"] is False
        await ana._send(type="report", user="troll", reason="acoso", note="me insulta",
                        messages=[{"at": 1700000000, "text": "eres tonta"}, "basura"])
        await asyncio.sleep(0.2)
        lines = (tmp_path / "users_denuncias.jsonl").read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        assert entry["by"] == "ana" and entry["user"] == "troll" and entry["reason"] == "acoso"
        assert entry["messages"] == [{"at": 1700000000, "text": "eres tonta"}]
        # Persiste al reiniciar
        assert RelayServer(tmp_path / "users.json").registry["ana"]["blocked"] == ["troll"]
        await ana.close(); await troll.close(); srv.close()
    run(main())


# ---------------------------------------------------------------- base de datos

def test_old_json_database_is_migrated_to_sqlite(tmp_path):
    key = SigningKey.generate()
    old = {"ana": {"name": "Ana", "key": base64.b64encode(bytes(key.verify_key)).decode(), "blocked": ["luis"]}}
    (tmp_path / "users.json").write_text(json.dumps(old), encoding="utf-8")
    q = tmp_path / "queue"
    q.mkdir()
    (q / "ana__dev123456.json").write_text(json.dumps([{"from": "luis", "payload": {"x": 1}, "at": 1}]), encoding="utf-8")
    relay = RelayServer(tmp_path / "users.json", q)
    assert relay.registry["ana"]["name"] == "Ana" and relay.registry["ana"]["blocked"] == ["luis"]
    assert relay.queues["ana|dev123456"][0]["payload"] == {"x": 1}
    # Los ficheros viejos quedan como copia y no se vuelven a importar
    assert (tmp_path / "users.json.migrado").exists() and not (tmp_path / "users.json").exists()
    assert (tmp_path / "queue.migrado").exists()
    relay.registry["ana"]["status"] = "away"
    relay._save()
    relay.store.close()
    again = RelayServer(tmp_path / "users.json", q)
    assert again.registry["ana"]["status"] == "away" and "ana|dev123456" in again.queues


def test_database_works_from_another_thread(tmp_path):
    """El servidor de la bandeja crea el servidor en un hilo y lo ejecuta en otro."""
    import threading
    key = SigningKey.generate()
    relay = RelayServer(tmp_path / "users.json")
    errors = []

    def worker():
        try:
            relay.registry["ana"] = {"name": "ana", "key": bytes(key.verify_key), "devices": {}}
            relay._save()
            relay.queues["ana|dev123456"] = [{"from": None, "payload": {}, "at": 1}]
            relay._save_queue("ana|dev123456")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert not errors
    relay.store.close()
    assert RelayServer(tmp_path / "users.json").registry["ana"]["name"] == "ana"


# ---------------------------------------------------------------- copia cifrada en el servidor

def test_cloud_backup_only_for_its_own_account(tmp_path):
    async def main():
        srv, url, relay = await start_server(RelayServer(tmp_path / "users.json"))
        ana, luis = await new_client(url, "ana"), await new_client(url, "luis")
        await ana._send(type="backup-put", id=1, data=base64.b64encode(b"cifrado-de-ana").decode())
        await asyncio.sleep(0.2)
        assert relay.store.cloud_get("ana")[0] == base64.b64encode(b"cifrado-de-ana").decode()
        assert relay.store.cloud_get("luis") is None  # cada cuenta solo ve (y pide) la suya
        # Demasiado seguido: se rechaza
        await ana._send(type="backup-put", id=2, data=base64.b64encode(b"otra").decode())
        await asyncio.sleep(0.2)
        assert relay.store.cloud_get("ana")[0] == base64.b64encode(b"cifrado-de-ana").decode()
        # Al borrar la cuenta, la copia también
        await relay._delete_account("ana")
        assert relay.store.cloud_get("ana") is None
        await luis.close(); srv.close()
    run(main())
