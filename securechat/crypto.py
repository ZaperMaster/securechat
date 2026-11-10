"""Primitivas criptográficas de alto nivel.

Nada de esto implementa algoritmos propios: todo delega en libsodium (PyNaCl).
Aquí solo se decide *cómo* se combinan las primitivas.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.signing import SigningKey, VerifyKey

KEYSTORE_VERSION = 1


class CryptoError(Exception):
    """Fallo criptográfico: firma inválida, MAC incorrecto, contraseña errónea..."""


# ---------------------------------------------------------------- utilidades

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoError("base64 inválido") from exc


def kdf(key: bytes, label: bytes, data: bytes = b"", size: int = 32) -> bytes:
    """Derivación de claves con BLAKE2b en modo keyed.

    La etiqueta va dentro del mensaje (con longitud prefijada) para separar dominios.
    No usamos el parámetro 'personalization' de BLAKE2b porque libsodium.js no lo
    expone junto con un mensaje, y el cliente web debe derivar exactamente lo mismo.
    """
    return blake2b(encode_fields(b"securechat-kdf", label, data), digest_size=size, key=key,
                   encoder=RawEncoder)


def encode_fields(*fields: bytes) -> bytes:
    """Serialización sin ambigüedad: cada campo va precedido de su longitud.

    Evita que ("ab", "c") y ("a", "bc") produzcan los mismos bytes firmados.
    """
    out = bytearray()
    for f in fields:
        out += len(f).to_bytes(4, "big") + f
    return bytes(out)


# ------------------------------------------------- almacén de claves (disco)

def save_identity(path: Path, signing_key: SigningKey, password: str, *,
                  opslimit: int = nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
                  memlimit: int = nacl.pwhash.argon2id.MEMLIMIT_MODERATE) -> None:
    """Guarda la semilla Ed25519 cifrada con una clave derivada de la contraseña (Argon2id)."""
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode("utf-8"),
                                   salt, opslimit=opslimit, memlimit=memlimit)
    box = nacl.secret.SecretBox(key)
    blob = {
        "version": KEYSTORE_VERSION,
        "kdf": "argon2id",
        "opslimit": opslimit,
        "memlimit": memlimit,
        "salt": b64e(salt),
        "public_key": b64e(bytes(signing_key.verify_key)),
        "ciphertext": b64e(bytes(box.encrypt(bytes(signing_key)))),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load_identity(path: Path, password: str) -> SigningKey:
    blob = json.loads(path.read_text(encoding="utf-8"))
    if blob.get("version") != KEYSTORE_VERSION or blob.get("kdf") != "argon2id":
        raise CryptoError("formato de almacén de claves no soportado")
    key = nacl.pwhash.argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode("utf-8"),
                                   b64d(blob["salt"]), opslimit=blob["opslimit"],
                                   memlimit=blob["memlimit"])
    try:
        seed = nacl.secret.SecretBox(key).decrypt(b64d(blob["ciphertext"]))
    except nacl.exceptions.CryptoError as exc:
        raise CryptoError("contraseña incorrecta o almacén corrupto") from exc
    sk = SigningKey(seed)
    if bytes(sk.verify_key) != b64d(blob["public_key"]):
        raise CryptoError("la clave pública almacenada no coincide")
    return sk


# --------------------------------------------- huellas y números de seguridad

def _digits(name: str, identity_key: bytes) -> str:
    """30 dígitos derivados de (nombre, clave). Iteramos el hash para encarecer colisiones."""
    h = encode_fields(b"securechat-fp-v1", name.encode("utf-8"), identity_key)
    for _ in range(5200):
        h = blake2b(h + identity_key, digest_size=64, encoder=RawEncoder)
    return "".join(f"{int.from_bytes(h[i:i + 5], 'big') % 100000:05d}" for i in range(0, 30, 5))


def fingerprint(identity_key: bytes) -> str:
    """Huella corta de una clave pública, para mostrarla junto a un contacto."""
    digest = blake2b(identity_key, digest_size=16, encoder=RawEncoder).hex()
    return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


def safety_number(name_a: str, key_a: bytes, name_b: str, key_b: bytes) -> str:
    """Número de seguridad de 60 dígitos, idéntico para ambos interlocutores.

    Si los dos usuarios lo comparan por un canal independiente (en persona, llamada)
    y coincide, nadie ha sustituido claves en medio (MITM).
    """
    parts = sorted([_digits(name_a, key_a), _digits(name_b, key_b)])
    full = parts[0] + parts[1]
    return " ".join(full[i:i + 5] for i in range(0, 60, 5))


def verify_signature(identity_key: bytes, message: bytes, signature: bytes) -> None:
    try:
        VerifyKey(identity_key).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError) as exc:
        raise CryptoError("firma inválida") from exc
