"""Mensajes para usuarios desconectados ("sobres sellados" con prekey firmada).

Cuando Bob no está conectado no puede responder al handshake, así que Alice no
puede negociar una sesión. Para eso cada usuario publica en el servidor una
*signed prekey* (SPK): una clave X25519 firmada con su identidad Ed25519, igual
que en X3DH de Signal (sin las one-time prekeys).

    bundle(B) = { idB, SPK_B, Sig_B("spk" | B | SPK_B | fecha) }

Alice cifra cada mensaje con una clave efímera nueva contra esa SPK:

    th  = BLAKE2b("sealed" | A | B | idA | idB | SPK_B | eph | id_mensaje)
    sig = Sig_A(th)                         # Bob sabe que lo envía Alice
    k   = KDF(X25519(eph, SPK_B), th)
    ct  = XChaCha20-Poly1305(k, nonce, aad = th)

El servidor guarda el sobre cifrado y se lo entrega a Bob al conectarse.

Diferencia con las sesiones en vivo: si alguien robase la SPK privada de Bob,
podría leer los mensajes sellados dirigidos a ella. Por eso la SPK se renueva cada
7 días y las antiguas se borran (secreto hacia adelante "por semanas").
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import nacl.bindings as sodium
import nacl.exceptions
import nacl.secret
import nacl.utils
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.signing import SigningKey

from .crypto import CryptoError, b64d, b64e, encode_fields, kdf, verify_signature
from .session import PROTOCOL, IdentityMismatch

SPK_LIFETIME = 7 * 24 * 3600
SPK_KEEP = 3  # SPK antiguas que guardamos para abrir mensajes en cola


def spk_message(user: str, spk_pub: bytes, created: int) -> bytes:
    return encode_fields(PROTOCOL, b"spk", user.encode(), spk_pub, created.to_bytes(8, "big"))


def verify_bundle(bundle: dict, pinned: bytes | None) -> tuple[bytes, bytes]:
    """Comprueba la firma de la prekey. Devuelve (clave de identidad, SPK)."""
    ident, spk = b64d(bundle["identity_key"]), b64d(bundle["spk"])
    if pinned is not None and pinned != ident:
        raise IdentityMismatch(bundle["user"], pinned, ident)
    if len(spk) != 32:
        raise CryptoError("prekey con longitud inválida")
    verify_signature(ident, spk_message(bundle["user"], spk, int(bundle["created"])),
                     b64d(bundle["sig"]))
    return ident, spk


def _transcript(sender: str, recipient: str, id_s: bytes, id_r: bytes, spk: bytes,
                eph: bytes, msg_id: bytes) -> bytes:
    return blake2b(encode_fields(PROTOCOL, b"sealed", sender.encode(), recipient.encode(),
                                 id_s, id_r, spk, eph, msg_id), digest_size=32, encoder=RawEncoder)


def _dh(priv: bytes, pub: bytes) -> bytes:
    try:
        shared = sodium.crypto_scalarmult(priv, pub)
    except nacl.exceptions.RuntimeError as exc:
        raise CryptoError("clave inválida") from exc
    if shared == bytes(32):
        raise CryptoError("clave inválida")
    return shared


def seal(me: str, identity: SigningKey, peer: str, peer_identity: bytes, spk: bytes,
         plaintext: str) -> dict:
    eph_priv = nacl.utils.random(32)
    eph = sodium.crypto_scalarmult_base(eph_priv)
    msg_id = nacl.utils.random(16)
    id_me = bytes(identity.verify_key)
    th = _transcript(me, peer, id_me, peer_identity, spk, eph, msg_id)
    key = kdf(_dh(eph_priv, spk), b"sc-sealed", th)
    nonce = nacl.utils.random(24)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext.encode("utf-8"), th, nonce, key)
    return {"kind": "sealed", "identity_key": b64e(id_me), "spk": b64e(spk), "eph": b64e(eph),
            "id": b64e(msg_id), "sig": b64e(identity.sign(th).signature),
            "nonce": b64e(nonce), "ct": b64e(ct)}


def open_sealed(me: str, identity: SigningKey, sender: str, payload: dict,
                prekeys: "PrekeyStore", pinned: bytes | None) -> tuple[str, bytes]:
    """Abre un sobre. Devuelve (texto, clave de identidad del remitente)."""
    id_s = b64d(payload["identity_key"])
    if pinned is not None and pinned != id_s:
        raise IdentityMismatch(sender, pinned, id_s)
    spk, eph, msg_id = b64d(payload["spk"]), b64d(payload["eph"]), b64d(payload["id"])
    spk_priv = prekeys.private_for(spk)
    if spk_priv is None:
        raise CryptoError("mensaje para una prekey que ya no existe")
    th = _transcript(sender, me, id_s, bytes(identity.verify_key), spk, eph, msg_id)
    verify_signature(id_s, th, b64d(payload["sig"]))
    if not prekeys.first_time(msg_id):
        raise CryptoError("mensaje repetido")
    key = kdf(_dh(spk_priv, eph), b"sc-sealed", th)
    try:
        pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            b64d(payload["ct"]), th, b64d(payload["nonce"]), key)
    except nacl.exceptions.CryptoError as exc:
        raise CryptoError("mensaje manipulado") from exc
    return pt.decode("utf-8"), id_s


class PrekeyStore:
    """Mis prekeys firmadas. Las privadas se guardan cifradas con una clave
    derivada de mi identidad (que a su vez está protegida con mi contraseña)."""

    def __init__(self, user: str, identity: SigningKey, path: Path | None):
        self.user, self.identity, self.path = user, identity, path
        self._box = nacl.secret.SecretBox(kdf(bytes(identity), b"sc-storage"))
        self.keys: list[dict] = []  # {pub, priv, created}
        self._seen: set[bytes] = set()
        if path and path.exists():
            for k in json.loads(path.read_text(encoding="utf-8")):
                self.keys.append({"pub": b64d(k["pub"]), "created": k["created"],
                                  "priv": self._box.decrypt(b64d(k["priv"]))})

    def current(self) -> dict:
        """Prekey vigente; genera una nueva si no hay o si caducó."""
        now = int(time.time())
        if not self.keys or now - self.keys[-1]["created"] > SPK_LIFETIME:
            priv = nacl.utils.random(32)
            self.keys.append({"priv": priv, "pub": sodium.crypto_scalarmult_base(priv), "created": now})
            self.keys = self.keys[-SPK_KEEP:]
            self._save()
        return self.keys[-1]

    def bundle(self) -> dict:
        k = self.current()
        sig = self.identity.sign(spk_message(self.user, k["pub"], k["created"])).signature
        return {"spk": b64e(k["pub"]), "sig": b64e(sig), "created": k["created"]}

    def private_for(self, pub: bytes) -> bytes | None:
        return next((k["priv"] for k in self.keys if k["pub"] == pub), None)

    def first_time(self, msg_id: bytes) -> bool:
        if msg_id in self._seen:
            return False
        self._seen.add(msg_id)
        return True

    def _save(self) -> None:
        if not self.path:
            return
        data = [{"pub": b64e(k["pub"]), "created": k["created"],
                 "priv": b64e(bytes(self._box.encrypt(k["priv"])))} for k in self.keys]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
