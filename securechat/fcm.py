"""Avisos a la app de Android por Firebase Cloud Messaging (FCM, API HTTP v1).

La app de Android lleva el código dentro (no es una web), así que no puede usar Web Push:
recibe los avisos por FCM. Como con Web Push, el aviso NO lleva contenido: solo "tienes un
mensaje nuevo" o "te están llamando". Ni Google ni nadie ve el texto ni quién lo envía.

Hace falta la clave de una cuenta de servicio de tu proyecto de Firebase (un JSON). Se pone
junto a la base de datos con el nombre <base>_fcm.json (por ejemplo usuarios_fcm.json) y
NUNCA se sube a git. Sin ese fichero, simplemente no hay avisos para la app de Android.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("securechat.fcm")

SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
TOKEN_RE_MAX = 4096

TEXTS = {
    "es": {"msg": "Tienes un mensaje nuevo 🔒", "call": "📞 Te están llamando. Toca para abrir y contestar."},
    "en": {"msg": "You have a new message 🔒", "call": "📞 Someone is calling you. Tap to open and answer."},
}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def valid_fcm_token(token) -> bool:
    return isinstance(token, str) and 20 <= len(token) <= TOKEN_RE_MAX and all(
        c.isalnum() or c in "-_:." for c in token)


class Fcm:
    def __init__(self, credentials: Path):
        info = json.loads(credentials.read_text(encoding="utf-8"))
        if info.get("type") != "service_account":
            raise ValueError("el fichero de Firebase no es una cuenta de servicio")
        from cryptography.hazmat.primitives import serialization
        self.project = info["project_id"]
        self.email = info["client_email"]
        self.token_uri = info.get("token_uri", "https://oauth2.googleapis.com/token")
        self.key = serialization.load_pem_private_key(info["private_key"].encode(), password=None)
        self._access: tuple[str, float] | None = None
        self._lock = threading.Lock()

    def _access_token(self) -> str:
        """Token OAuth2 de la cuenta de servicio (JWT firmado con RS256), reutilizado ~55 min."""
        with self._lock:
            if self._access and time.time() < self._access[1]:
                return self._access[0]
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            now = int(time.time())
            head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
            claims = _b64(json.dumps({"iss": self.email, "scope": SCOPE, "aud": self.token_uri,
                                      "iat": now, "exp": now + 3600}).encode())
            sig = self.key.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                           "assertion": f"{head}.{claims}.{_b64(sig)}"}).encode()
            req = urllib.request.Request(self.token_uri, data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            self._access = (data["access_token"], time.time() + min(3300, int(data.get("expires_in", 3600)) - 60))
            return self._access[0]

    def send(self, token: str, call: bool = False, lang: str = "es") -> bool:
        """Manda el aviso. Devuelve False si el token ya no vale (hay que olvidarlo)."""
        t = TEXTS.get(lang, TEXTS["es"])
        message = {"message": {"token": token, "android": {
            "priority": "HIGH",
            "ttl": "60s" if call else "86400s",
            "collapse_key": "call" if call else "msg",
            "notification": {
                "title": "SecureChat", "body": t["call"] if call else t["msg"],
                "channel_id": "llamadas" if call else "mensajes",
                "tag": "call" if call else "securechat-new",
                "notification_priority": "PRIORITY_MAX" if call else "PRIORITY_HIGH",
                "default_sound": True, "default_vibrate_timings": True,
            }}}}
        try:
            req = urllib.request.Request(
                f"https://fcm.googleapis.com/v1/projects/{self.project}/messages:send",
                data=json.dumps(message).encode(),
                headers={"Authorization": f"Bearer {self._access_token()}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10):
                return True
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            if exc.code == 404 or "UNREGISTERED" in detail or ("INVALID_ARGUMENT" in detail and "token" in detail.lower()):
                return False
            log.warning("aviso FCM fallido (%s)", exc.code)
            return True
        except Exception:  # noqa: BLE001 - red, etc.
            log.warning("aviso FCM fallido", exc_info=True)
            return True


import urllib.parse  # noqa: E402  (se usa dentro de _access_token)
