"""Verificación por correo al crear una cuenta (para frenar bots).

El servidor envía un código de 6 dígitos al correo. Del correo solo guarda una
huella (HMAC con un secreto del servidor) para impedir varias cuentas con el
mismo correo; la dirección en sí no se almacena ni se comparte con nadie.

Envío:
  * SmtpSender: un servidor SMTP real (por ejemplo Gmail con "contraseña de
    aplicación"). Se configura con variables de entorno o un fichero JSON.
  * ConsoleSender: escribe el código en la consola del servidor (pruebas).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from hashlib import sha256
from pathlib import Path

log = logging.getLogger("securechat.email")

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")
CODE_TTL = 10 * 60
MAX_TRIES = 5


def normalize_email(email: str) -> str:
    return email.strip().lower()


def valid_email(email) -> bool:
    return isinstance(email, str) and len(email) <= 254 and bool(EMAIL_RE.match(email.strip()))


def mask(email: str) -> str:
    """alejandro@gmail.com -> a*******o@gmail.com"""
    user, _, domain = email.partition("@")
    hidden = user[0] + "*" * max(1, len(user) - 2) + (user[-1] if len(user) > 1 else "")
    return f"{hidden}@{domain}"


def new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


class EmailHasher:
    """Huella del correo con un secreto del servidor (no reversible sin el secreto)."""

    def __init__(self, secret_path: Path | None):
        if secret_path and secret_path.exists():
            self.secret = bytes.fromhex(secret_path.read_text().strip())
        else:
            self.secret = secrets.token_bytes(32)
            if secret_path:
                secret_path.write_text(self.secret.hex())

    def __call__(self, email: str) -> str:
        return hmac.new(self.secret, normalize_email(email).encode(), sha256).hexdigest()


class ConsoleSender:
    """Modo pruebas: el código aparece en la consola del servidor."""

    def __init__(self):
        self.sent: list[tuple[str, str]] = []  # para los tests

    async def send(self, to: str, code: str) -> None:
        self.sent.append((to, code))
        print(f"\n  [correo de prueba] código para {to}: {code}\n", flush=True)


class SmtpSender:
    def __init__(self, host: str, port: int, user: str, password: str, sender: str):
        self.host, self.port, self.user, self.password, self.sender = host, port, user, password, sender

    @classmethod
    def from_env(cls) -> "SmtpSender | None":
        host = os.environ.get("SECURECHAT_SMTP_HOST")
        if not host:
            return None
        user = os.environ.get("SECURECHAT_SMTP_USER", "")
        return cls(host, int(os.environ.get("SECURECHAT_SMTP_PORT", "587")), user,
                   os.environ.get("SECURECHAT_SMTP_PASSWORD", ""), os.environ.get("SECURECHAT_SMTP_FROM", user))

    @classmethod
    def from_file(cls, path: Path) -> "SmtpSender | None":
        """Fichero JSON: {"host", "port", "user", "password", "from"}"""
        if not path.exists():
            return None
        c = json.loads(path.read_text(encoding="utf-8"))
        if not c.get("host") or not c.get("user") or not c.get("password"):
            return None
        return cls(c["host"], int(c.get("port", 587)), c["user"], c["password"], c.get("from") or c["user"])

    def _send_sync(self, to: str, code: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"{code} es tu código de SecureChat"
        msg["From"] = self.sender
        msg["To"] = to
        msg.set_content(f"Tu código para crear la cuenta de SecureChat es:\n\n    {code}\n\n"
                        "Caduca en 10 minutos. Si no has sido tú, ignora este correo.")
        context = ssl.create_default_context()
        if self.port == 465:
            with smtplib.SMTP_SSL(self.host, self.port, context=context, timeout=20) as s:
                s.login(self.user, self.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(self.host, self.port, timeout=20) as s:
                s.starttls(context=context)
                s.login(self.user, self.password)
                s.send_message(msg)

    async def send(self, to: str, code: str) -> None:
        await asyncio.to_thread(self._send_sync, to, code)
        log.info("código de verificación enviado a %s", mask(to))
