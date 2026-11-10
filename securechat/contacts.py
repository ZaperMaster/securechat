"""Libreta de contactos local: claves fijadas (TOFU) y estado de verificación."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .crypto import b64d, b64e


@dataclass
class Contact:
    name: str
    identity_key: bytes
    verified: bool = False


class Contacts:
    def __init__(self, path: Path | None):
        self.path = path
        self._items: dict[str, Contact] = {}
        if path and path.exists():
            for name, c in json.loads(path.read_text(encoding="utf-8")).items():
                self._items[name] = Contact(name, b64d(c["identity_key"]), c["verified"])

    def get(self, name: str) -> Contact | None:
        return self._items.get(name)

    def pinned_key(self, name: str) -> bytes | None:
        c = self._items.get(name)
        return c.identity_key if c else None

    def pin(self, name: str, identity_key: bytes) -> Contact:
        """Trust On First Use: la primera clave vista para un nombre queda fijada."""
        existing = self._items.get(name)
        if existing:
            if existing.identity_key != identity_key:
                raise ValueError("la clave no coincide con la fijada")
            return existing
        c = self._items[name] = Contact(name, identity_key)
        self._save()
        return c

    def set_verified(self, name: str, verified: bool = True) -> None:
        self._items[name].verified = verified
        self._save()

    def forget(self, name: str) -> None:
        """Olvida la clave fijada (p. ej. el contacto reinstaló y generó una nueva)."""
        self._items.pop(name, None)
        self._save()

    def all(self) -> list[Contact]:
        return sorted(self._items.values(), key=lambda c: c.name)

    def _save(self) -> None:
        if not self.path:
            return
        data = {c.name: {"identity_key": b64e(c.identity_key), "verified": c.verified}
                for c in self._items.values()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
