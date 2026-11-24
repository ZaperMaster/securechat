"""Avisos a la app de Android por Firebase (sin red: se simulan las respuestas de Google)."""

import base64
import io
import json
import urllib.error

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from securechat import fcm as fcm_mod
from securechat.push import Pusher, valid_subscription

TOKEN = "dQw4w9WgXcQ:APA91bH" + "x" * 140


@pytest.fixture
def account(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    path = tmp_path / "usuarios_fcm.json"
    path.write_text(json.dumps({"type": "service_account", "project_id": "securechat-prueba",
                                "client_email": "push@securechat-prueba.iam.gserviceaccount.com",
                                "private_key": pem, "token_uri": "https://oauth2.googleapis.com/token"}))
    return path, key.public_key()


class FakeGoogle:
    def __init__(self, fail=None):
        self.requests = []
        self.fail = fail

    def __call__(self, req, timeout=10):
        self.requests.append(req)
        if "oauth2" in req.full_url:
            return io.BytesIO(json.dumps({"access_token": "tok-123", "expires_in": 3600}).encode())
        if self.fail:
            raise urllib.error.HTTPError(req.full_url, self.fail[0], "x", {}, io.BytesIO(self.fail[1].encode()))
        return io.BytesIO(b"{}")


def test_fcm_subscriptions_are_validated():
    assert valid_subscription({"fcm": TOKEN, "endpoint": f"fcm:{TOKEN}", "lang": "en"})
    assert not valid_subscription({"fcm": TOKEN, "endpoint": "fcm:otro"})
    assert not valid_subscription({"fcm": "corto", "endpoint": "fcm:corto"})
    assert not valid_subscription({"fcm": TOKEN + "/../x", "endpoint": f"fcm:{TOKEN}/../x"})
    assert not valid_subscription({"fcm": TOKEN, "endpoint": f"fcm:{TOKEN}", "url": "https://evil"})


def test_fcm_message_has_no_content_and_jwt_is_signed(account, monkeypatch):
    path, public = account
    google = FakeGoogle()
    monkeypatch.setattr(fcm_mod.urllib.request, "urlopen", google)
    f = fcm_mod.Fcm(path)
    assert f.send(TOKEN, call=False, lang="en") is True
    assert f.send(TOKEN, call=True) is True
    # Un solo token OAuth para los dos avisos
    oauth = [r for r in google.requests if "oauth2" in r.full_url]
    assert len(oauth) == 1
    assertion = dict(x.split("=", 1) for x in oauth[0].data.decode().split("&"))["assertion"]
    head, claims, sig = assertion.split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    public.verify(pad(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert json.loads(pad(claims))["scope"].endswith("firebase.messaging")
    sends = [r for r in google.requests if "fcm.googleapis.com" in r.full_url]
    assert sends[0].full_url.endswith("/projects/securechat-prueba/messages:send")
    assert sends[0].headers["Authorization"] == "Bearer tok-123"
    msg, call = json.loads(sends[0].data)["message"], json.loads(sends[1].data)["message"]
    assert msg["android"]["notification"]["body"] == "You have a new message 🔒"
    assert call["android"]["notification"]["channel_id"] == "llamadas" and call["android"]["ttl"] == "60s"
    # Nada del mensaje ni de quién lo envía
    assert set(msg) == {"token", "android"} and "data" not in msg


def test_dead_fcm_tokens_are_forgotten(account, monkeypatch):
    path, _ = account
    monkeypatch.setattr(fcm_mod.urllib.request, "urlopen", FakeGoogle(fail=(404, '{"error":{"status":"NOT_FOUND"}}')))
    assert fcm_mod.Fcm(path).send(TOKEN) is False
    monkeypatch.setattr(fcm_mod.urllib.request, "urlopen", FakeGoogle(fail=(500, "boom")))
    assert fcm_mod.Fcm(path).send(TOKEN) is True  # fallo temporal: se conserva


def test_pusher_uses_fcm_for_android_and_drops_dead_tokens(account, monkeypatch, tmp_path):
    import asyncio
    path, _ = account
    monkeypatch.setattr(fcm_mod.urllib.request, "urlopen", FakeGoogle(fail=(404, "UNREGISTERED")))
    pusher = Pusher(tmp_path / "v.pem", fcm_path=path)
    sub = {"fcm": TOKEN, "endpoint": f"fcm:{TOKEN}", "lang": "es"}
    assert asyncio.run(pusher.notify("ana", [sub])) == []
