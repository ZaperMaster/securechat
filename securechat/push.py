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
CALL_INTERVAL = 5      # los de llamada no esperan a los de mensaje, pero tampoco se repiten sin fin
CALL_TTL = 60          # un aviso de llamada que llega tarde ya no sirve
MAX_SUBS = 5           # dispositivos con avisos por cuenta


# Servicios de avisos de los navegadores. Solo a estos se les manda nada: si se aceptara
# cualquier https://, un usuario podría hacer que el servidor enviara peticiones a
# direcciones internas de su red (SSRF).
PUSH_HOSTS = ("fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com")
PUSH_SUFFIXES = (".push.services.mozilla.com", ".notify.windows.com", ".push.apple.com", ".googleapis.com")


def valid_push_endpoint(endpoint) -> bool:
    from urllib.parse import urlsplit
    if not isinstance(endpoint, str) or len(endpoint) > 1000:
        return False
    try:
        u = urlsplit(endpoint)
        port = u.port
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    return (u.scheme == "https" and port in (None, 443) and not u.username and not u.password
            and (host in PUSH_HOSTS or host.endswith(PUSH_SUFFIXES)))


def valid_subscription(sub) -> bool:
    if not isinstance(sub, dict) or len(json.dumps(sub)) > 5000:
        return False
    if "fcm" in sub:  # app de Android: token de Firebase (la "dirección" es fcm:<token>)
        from .fcm import valid_fcm_token
        return (valid_fcm_token(sub["fcm"]) and sub.get("endpoint") == f"fcm:{sub['fcm']}"
                and sub.get("lang", "es") in ("es", "en") and set(sub) <= {"fcm", "endpoint", "lang"})
    if len(json.dumps(sub)) > 2000:
        return False
    keys = sub.get("keys") or {}
    return (valid_push_endpoint(sub.get("endpoint"))
            and isinstance(keys.get("p256dh"), str) and isinstance(keys.get("auth"), str))


class Pusher:
    def __init__(self, key_path: Path | None, contact: str = "mailto:securechat@localhost", fcm_path: Path | None = None):
        self.enabled = AVAILABLE
        self.fcm = None
        if fcm_path and fcm_path.exists():
            try:
                from .fcm import Fcm
                self.fcm = Fcm(fcm_path)
                log.info("avisos para la app de Android (Firebase) activados")
            except Exception:  # noqa: BLE001 - fichero mal copiado, etc.
                log.exception("no se pudo cargar %s", fcm_path)
        self.contact = contact
        self._last: dict[str, float] = {}
        self._last_call: dict[str, float] = {}
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

    def _send_sync(self, sub: dict, call: bool = False) -> bool:
        """Devuelve False si la suscripción ya no vale (hay que borrarla)."""
        if "fcm" in sub:
            return self.fcm.send(sub["fcm"], call, sub.get("lang", "es")) if self.fcm else True
        if not self.enabled:
            return True
        body = {"title": "SecureChat", "kind": "call", "body": "📞 Te están llamando"} if call \
            else {"title": "SecureChat", "body": "Tienes un mensaje nuevo 🔒"}
        try:
            # Urgency: high hace que Android lo entregue al momento aunque el móvil esté en reposo
            webpush(sub, json.dumps(body), vapid_private_key=self.vapid, vapid_claims={"sub": self.contact},
                    ttl=CALL_TTL if call else 86400, timeout=10,
                    headers={"Urgency": "high" if call else "normal"})
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

    async def notify(self, account: str, subs: list[dict], call: bool = False) -> list[dict]:
        """Envía el aviso a todos los dispositivos. Devuelve las suscripciones que siguen vivas.
        call=True: aviso de llamada entrante (prioridad alta y caduca en un minuto)."""
        if not subs or (not self.enabled and not self.fcm):
            return subs
        now = time.monotonic()
        last, gap = (self._last_call, CALL_INTERVAL) if call else (self._last, MIN_INTERVAL)
        if now - last.get(account, 0) < gap:
            return subs
        last[account] = now
        alive = await asyncio.gather(*(asyncio.to_thread(self._send_sync, s, call) for s in subs))
        return [s for s, ok in zip(subs, alive) if ok]
