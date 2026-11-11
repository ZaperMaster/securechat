"""Notificaciones con la app cerrada (Web Push con claves VAPID).

Cuando a alguien le llega un mensaje y no tiene la app abierta, el servidor manda
un aviso a través del servicio de notificaciones de su navegador (Google, Mozilla
o Apple). El aviso va cifrado para su dispositivo y solo dice "tienes un mensaje
nuevo": ni el texto ni quién lo envía (el servidor tampoco lo sabe leer).

Es opcional: si la librería pywebpush no está instalada, simplemente no hay avisos.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from pathlib import Path

log = logging.getLogger("securechat.push")

try:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from py_vapid import Vapid01
    from pywebpush import WebPushException, webpush
    AVAILABLE = True
except ImportError:  # pragma: no cover - sin dependencias opcionales
    AVAILABLE = False

MIN_INTERVAL = 20      # segundos mínimos entre avisos a la misma cuenta
MAX_SUBS = 5           # dispositivos con avisos por cuenta


def valid_subscription(sub) -> bool:
    if not isinstance(sub, dict) or len(json.dumps(sub)) > 2000:
        return False
    keys = sub.get("keys") or {}
    endpoint = sub.get("endpoint", "")
    return (isinstance(endpoint, str) and endpoint.startswith("https://")
            and isinstance(keys.get("p256dh"), str) and isinstance(keys.get("auth"), str))


class Pusher:
    def __init__(self, key_path: Path | None, contact: str = "mailto:securechat@localhost"):
        self.enabled = AVAILABLE
        self.contact = contact
        self._last: dict[str, float] = {}
        self.public_key = None
        if not self.enabled:
            return
        if key_path and key_path.exists():
            self.vapid = Vapid01.from_file(str(key_path))
        else:
            self.vapid = Vapid01()
            self.vapid.generate_keys()
            if key_path:
                self.vapid.save_key(str(key_path))
        raw = self.vapid.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self.public_key = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def _send_sync(self, sub: dict) -> bool:
        """Devuelve False si la suscripción ya no vale (hay que borrarla)."""
        try:
            webpush(sub, json.dumps({"title": "SecureChat", "body": "Tienes un mensaje nuevo 🔒"}),
                    vapid_private_key=self.vapid, vapid_claims={"sub": self.contact}, ttl=86400,
                    timeout=10)
            return True
        except WebPushException as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (404, 410):
                return False
            log.warning("aviso push fallido (%s)", status)
            return True
        except Exception:  # noqa: BLE001 - red, etc.
            log.warning("aviso push fallido", exc_info=True)
            return True

    async def notify(self, account: str, subs: list[dict]) -> list[dict]:
        """Envía el aviso a todos los dispositivos. Devuelve las suscripciones que siguen vivas."""
        if not self.enabled or not subs:
            return subs
        now = time.monotonic()
        if now - self._last.get(account, 0) < MIN_INTERVAL:
            return subs
        self._last[account] = now
        alive = await asyncio.gather(*(asyncio.to_thread(self._send_sync, s) for s in subs))
        return [s for s, ok in zip(subs, alive) if ok]
