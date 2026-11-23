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
