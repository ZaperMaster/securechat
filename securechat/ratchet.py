"""Protocolo v2: X3DH con one-time prekeys + Double Ratchet, por dispositivo.

Es el diseño de Signal, simplificado:

* Cada cuenta puede tener varios dispositivos. Todos comparten la identidad
  Ed25519 de la cuenta, pero cada dispositivo tiene sus propias prekeys:
    - SPK  (signed prekey): X25519 firmada con la identidad, se renueva cada 7 días.
    - OPK  (one-time prekeys): X25519 de un solo uso. El servidor entrega una por
      petición y la borra; el dispositivo borra la privada al usarla.

* X3DH: para escribir a un dispositivo que nunca nos ha hablado, sin que esté
  conectado:
        DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)
        DH3 = DH(EK_A, SPK_B)   DH4 = DH(EK_A, OPK_B)   (si hay OPK)
        SK  = KDF(DH1 | DH2 | DH3 | DH4, AD)
  donde IK son las identidades Ed25519 convertidas a X25519 y
  AD = (A, dispositivo de A, B, dispositivo de B, IK_A, IK_B).

* Double Ratchet: cada mensaje usa una clave nueva (ratchet simétrico) y cada
  vez que cambia el turno de quién escribe se hace un DH nuevo (ratchet DH).
  Así hay secreto hacia adelante y "curación" tras un compromiso: si alguien
  roba el estado actual, deja de poder leer en cuanto llega el siguiente DH.

Este fichero y web/js/ratchet.js deben producir los mismos bytes (lo comprueban
los tests de interoperabilidad).
"""

from __future__ import annotations

import json
import os
import re
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

PROTO = b"securechat-v2"
MAX_SKIP = 1000
MAX_SKIPPED_STORED = 2000
SPK_LIFETIME = 7 * 24 * 3600
OPK_BATCH = 20
DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{6,24}$")


class IdentityMismatch(CryptoError):
    """La clave de identidad recibida no coincide con la que teníamos fijada."""

    def __init__(self, peer: str, expected: bytes, received: bytes):
        super().__init__(f"¡La clave de identidad de '{peer}' ha cambiado!")
        self.peer, self.expected, self.received = peer, expected, received


# --------------------------------------------------------------- utilidades

def new_device_id() -> str:
    return b64e(nacl.utils.random(9)).replace("+", "-").replace("/", "_").rstrip("=")


def dh(priv: bytes, pub: bytes) -> bytes:
    if len(pub) != 32:
        raise CryptoError("clave pública con longitud inválida")
    try:
        out = sodium.crypto_scalarmult(priv, pub)
    except nacl.exceptions.RuntimeError as exc:
        raise CryptoError("clave inválida") from exc
    if out == bytes(32):
        raise CryptoError("clave inválida")
    return out


def keypair() -> tuple[bytes, bytes]:
    priv = nacl.utils.random(32)
    return priv, sodium.crypto_scalarmult_base(priv)


def ik_x25519_priv(identity: SigningKey) -> bytes:
    return bytes(identity.to_curve25519_private_key())


def ik_x25519_pub(ed_pub: bytes) -> bytes:
    return sodium.crypto_sign_ed25519_pk_to_curve25519(ed_pub)


KEM_PUB_BYTES = 1184  # ML-KEM-768 (la usa el cliente web para PQXDH)


def kem_message(user: str, device: str, kem: bytes, created: int) -> bytes:
    """Lo que firma la identidad para publicar una prekey poscuántica (igual que en ratchet.js)."""
    return encode_fields(PROTO, b"kem", user.encode(), device.encode(), kem, created.to_bytes(8, "big"))


def spk_message(user: str, device: str, spk: bytes, created: int) -> bytes:
    return encode_fields(PROTO, b"spk", user.encode(), device.encode(), spk, created.to_bytes(8, "big"))


def x3dh_ad(a: str, a_dev: str, b: str, b_dev: str, ik_a: bytes, ik_b: bytes) -> bytes:
    return encode_fields(PROTO, b"ad", a.encode(), a_dev.encode(), b.encode(), b_dev.encode(), ik_a, ik_b)


def x3dh_secret(dhs: list[bytes], ad: bytes) -> bytes:
    ikm = blake2b(encode_fields(*dhs), digest_size=32, encoder=RawEncoder)
    return kdf(ikm, b"sc-x3dh", ad)


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    out = kdf(rk, b"sc-rk", dh_out, size=64)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return kdf(ck, b"sc-ck"), kdf(ck, b"sc-mk")


def header_bytes(dh_pub: bytes, pn: int, n: int) -> bytes:
    return encode_fields(dh_pub, pn.to_bytes(4, "big"), n.to_bytes(4, "big"))


def aead_encrypt(mk: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = nacl.utils.random(24)
    return nonce, sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, mk)


def aead_decrypt(mk: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, mk)
    except nacl.exceptions.CryptoError as exc:
        raise CryptoError("mensaje manipulado o clave incorrecta") from exc


# ------------------------------------------------------------ Double Ratchet

class Ratchet:
    """Estado de una sesión con UN dispositivo. Se guarda como JSON."""

    def __init__(self, st: dict):
        self.st = st

    # -- creación
    @classmethod
    def as_initiator(cls, sk: bytes, ad: bytes, their_spk: bytes, x3dh: dict) -> "Ratchet":
        dhs_priv, dhs_pub = keypair()
        rk, cks = kdf_rk(sk, dh(dhs_priv, their_spk))
        return cls({"ad": b64e(ad), "dhs": [b64e(dhs_priv), b64e(dhs_pub)], "dhr": b64e(their_spk),
                    "rk": b64e(rk), "cks": b64e(cks), "ckr": None, "ns": 0, "nr": 0, "pn": 0,
                    "skipped": {}, "x3dh": x3dh})

    @classmethod
    def as_responder(cls, sk: bytes, ad: bytes, spk_priv: bytes, spk_pub: bytes) -> "Ratchet":
        return cls({"ad": b64e(ad), "dhs": [b64e(spk_priv), b64e(spk_pub)], "dhr": None,
                    "rk": b64e(sk), "cks": None, "ckr": None, "ns": 0, "nr": 0, "pn": 0,
                    "skipped": {}, "x3dh": None})

    # -- cifrar / descifrar
    def encrypt(self, plaintext: bytes) -> dict:
        st = self.st
        ck, mk = kdf_ck(b64d(st["cks"]))
        st["cks"] = b64e(ck)
        dh_pub = b64d(st["dhs"][1])
        hdr = {"dh": st["dhs"][1], "pn": st["pn"], "n": st["ns"]}
        aad = encode_fields(b64d(st["ad"]), header_bytes(dh_pub, st["pn"], st["ns"]))
        st["ns"] += 1
        nonce, ct = aead_encrypt(mk, plaintext, aad)
        out = {"header": hdr, "nonce": b64e(nonce), "ct": b64e(ct)}
        if st.get("x3dh"):
            out["x3dh"] = st["x3dh"]  # hasta que nos respondan, repetimos el inicio X3DH
        return out

    def decrypt(self, msg: dict) -> bytes:
        backup = json.loads(json.dumps(self.st))
        try:
            return self._decrypt(msg)
        except Exception:
            self.st = backup  # un mensaje malo no estropea la sesión
            raise

    def _decrypt(self, msg: dict) -> bytes:
        st = self.st
        hdr = msg["header"]
        dh_pub, pn, n = b64d(hdr["dh"]), int(hdr["pn"]), int(hdr["n"])
        aad = encode_fields(b64d(st["ad"]), header_bytes(dh_pub, pn, n))
        nonce, ct = b64d(msg["nonce"]), b64d(msg["ct"])
        key = f"{hdr['dh']}:{n}"
        if key in st["skipped"]:
            mk = b64d(st["skipped"].pop(key))
            return aead_decrypt(mk, nonce, ct, aad)
        if hdr["dh"] != st["dhr"]:
            if st["dhr"] is not None:
                self._skip(pn)
            self._dh_ratchet(dh_pub)
        self._skip(n)
        ck, mk = kdf_ck(b64d(st["ckr"]))
        st["ckr"] = b64e(ck)
        st["nr"] += 1
        pt = aead_decrypt(mk, nonce, ct, aad)
        st["x3dh"] = None  # nos han respondido: ya no hace falta repetir el inicio
        return pt

    def _skip(self, until: int) -> None:
        st = self.st
        if st["ckr"] is None:
            return
        if until - st["nr"] > MAX_SKIP:
            raise CryptoError("demasiados mensajes saltados")
        ck = b64d(st["ckr"])
        while st["nr"] < until:
            ck, mk = kdf_ck(ck)
            st["skipped"][f"{st['dhr']}:{st['nr']}"] = b64e(mk)
            st["nr"] += 1
        st["ckr"] = b64e(ck)
        while len(st["skipped"]) > MAX_SKIPPED_STORED:
            st["skipped"].pop(next(iter(st["skipped"])))

    def _dh_ratchet(self, their_pub: bytes) -> None:
        st = self.st
        st["pn"], st["ns"], st["nr"] = st["ns"], 0, 0
        st["dhr"] = b64e(their_pub)
        rk, ckr = kdf_rk(b64d(st["rk"]), dh(b64d(st["dhs"][0]), their_pub))
        priv, pub = keypair()
        st["dhs"] = [b64e(priv), b64e(pub)]
        rk, cks = kdf_rk(rk, dh(priv, their_pub))
        st["rk"], st["ckr"], st["cks"] = b64e(rk), b64e(ckr), b64e(cks)


# ----------------------------------------------------------------- X3DH

def initiate(me: str, my_dev: str, identity: SigningKey, peer: str, peer_dev: str,
             peer_ik: bytes, bundle: dict, pinned: bytes | None) -> Ratchet:
    """Empieza una sesión con un dispositivo a partir de su bundle (puede estar desconectado)."""
    if pinned is not None and pinned != peer_ik:
        raise IdentityMismatch(peer, pinned, peer_ik)
    spk = b64d(bundle["spk"])
    verify_signature(peer_ik, spk_message(peer, peer_dev, spk, int(bundle["created"])), b64d(bundle["sig"]))
    opk = b64d(bundle["opk"]) if bundle.get("opk") else None
    ek_priv, ek_pub = keypair()
    my_ik = bytes(identity.verify_key)
    dhs = [dh(ik_x25519_priv(identity), spk), dh(ek_priv, ik_x25519_pub(peer_ik)), dh(ek_priv, spk)]
    if opk:
        dhs.append(dh(ek_priv, opk))
    ad = x3dh_ad(me, my_dev, peer, peer_dev, my_ik, peer_ik)
    sk = x3dh_secret(dhs, ad)
    x3dh = {"ik": b64e(my_ik), "ek": b64e(ek_pub), "spk": bundle["spk"], "opk": bundle.get("opk")}
    return Ratchet.as_initiator(sk, ad, spk, x3dh)


def accept(me: str, my_dev: str, identity: SigningKey, peer: str, peer_dev: str,
           x3dh: dict, prekeys: "DeviceKeys", pinned: bytes | None) -> tuple[Ratchet, bytes]:
    """Crea la sesión al recibir el primer mensaje de un dispositivo. Devuelve (sesión, IK)."""
    peer_ik = b64d(x3dh["ik"])
    if pinned is not None and pinned != peer_ik:
        raise IdentityMismatch(peer, pinned, peer_ik)
    spk = b64d(x3dh["spk"])
    spk_priv = prekeys.spk_private(spk)
    if spk_priv is None:
        raise CryptoError("mensaje para una prekey que ya no existe")
    opk_priv = None
    if x3dh.get("opk"):
        opk_priv = prekeys.opk_private(b64d(x3dh["opk"]))
        if opk_priv is None:
            raise CryptoError("prekey de un solo uso ya usada (¿mensaje repetido?)")
    ek = b64d(x3dh["ek"])
    dhs = [dh(spk_priv, ik_x25519_pub(peer_ik)), dh(ik_x25519_priv(identity), ek), dh(spk_priv, ek)]
    if opk_priv:
        dhs.append(dh(opk_priv, ek))
    ad = x3dh_ad(peer, peer_dev, me, my_dev, peer_ik, bytes(identity.verify_key))
    return Ratchet.as_responder(x3dh_secret(dhs, ad), ad, spk_priv, spk), peer_ik


# --------------------------------------------- claves de este dispositivo

class DeviceKeys:
    """Prekeys de ESTE dispositivo (SPK y OPK) y sus sesiones, guardadas cifradas."""

    def __init__(self, user: str, identity: SigningKey, path: Path | None, device: str | None = None):
        self.user, self.identity, self.path = user, identity, path
        self._box = nacl.secret.SecretBox(kdf(bytes(identity), b"sc-storage-v2"))
        data = {}
        if path and path.exists():
            data = json.loads(self._box.decrypt(b64d(path.read_text(encoding="utf-8").strip())))
        self.device = data.get("device") or device or new_device_id()
        self.spks: list[dict] = data.get("spks", [])      # {pub, priv, created}
        self.opks: dict[str, str] = data.get("opks", {})  # pub -> priv
        self.sessions: dict[str, dict] = data.get("sessions", {})  # "user|device" -> estado
        self.seen: list[str] = data.get("seen", [])       # mids ya vistos (repeticiones)

    def save(self) -> None:
        if not self.path:
            return
        data = {"device": self.device, "spks": self.spks, "opks": self.opks,
                "sessions": self.sessions, "seen": self.seen[-2000:]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(b64e(bytes(self._box.encrypt(json.dumps(data).encode()))), encoding="utf-8")
        os.replace(tmp, self.path)

    # prekeys
    def current_spk(self) -> dict:
        now = int(time.time())
        if not self.spks or now - self.spks[-1]["created"] > SPK_LIFETIME:
            priv, pub = keypair()
            self.spks = (self.spks + [{"priv": b64e(priv), "pub": b64e(pub), "created": now}])[-3:]
            self.save()
        return self.spks[-1]

    def spk_private(self, pub: bytes) -> bytes | None:
        return next((b64d(k["priv"]) for k in self.spks if k["pub"] == b64e(pub)), None)

    def opk_private(self, pub: bytes) -> bytes | None:
        priv = self.opks.pop(b64e(pub), None)  # de un solo uso: se borra al usarla
        if priv is not None:
            self.save()
        return b64d(priv) if priv else None

    def new_opks(self, n: int = OPK_BATCH) -> list[str]:
        pubs = []
        for _ in range(n):
            priv, pub = keypair()
            self.opks[b64e(pub)] = b64e(priv)
            pubs.append(b64e(pub))
        self.save()
        return pubs

    def upload_message(self, opks_on_server: int) -> dict:
        """Mensaje "prekeys" para el servidor: SPK firmada y OPK nuevas si quedan pocas."""
        spk = self.current_spk()
        sig = self.identity.sign(spk_message(self.user, self.device, b64d(spk["pub"]), spk["created"])).signature
        opks = self.new_opks() if opks_on_server < OPK_BATCH // 2 else []
        return {"type": "prekeys", "spk": spk["pub"], "sig": b64e(sig), "created": spk["created"], "opks": opks}

    # sesiones: por dispositivo guardamos la actual y hasta 3 anteriores (como Signal),
    # para resolver el caso de que los dos empiecen a escribirse a la vez
    def _key(self, user: str, device: str) -> str:
        return f"{user.lower()}|{device}"

    def states(self, user: str, device: str) -> list[dict]:
        v = self.sessions.get(self._key(user, device)) or []
        return v if isinstance(v, list) else [v]

    def session(self, user: str, device: str) -> Ratchet | None:
        st = self.states(user, device)
        return Ratchet(st[0]) if st else None

    def store(self, user: str, device: str, r: Ratchet, index: int = 0) -> None:
        """Guarda la sesión usada y la deja como actual."""
        st = self.states(user, device)
        if index < len(st):
            st.pop(index)
        self.sessions[self._key(user, device)] = ([r.st] + st)[:4]
        self.save()

    def push_new(self, user: str, device: str, r: Ratchet) -> None:
        self.sessions[self._key(user, device)] = ([r.st] + self.states(user, device))[:4]
        self.save()

    def drop(self, user: str, device: str) -> None:
        self.sessions.pop(self._key(user, device), None)
        self.save()

    def first_time(self, mid: str | None) -> bool:
        if not mid:
            return True
        if mid in self.seen:
            return False
        self.seen.append(mid)
        return True


def encrypt_for(me: str, my_dev: str, r: Ratchet, plaintext: str) -> dict:
    return {"kind": "dr", "dev": my_dev, **r.encrypt(plaintext.encode("utf-8"))}


def decrypt_from(me: str, keys: DeviceKeys, sender: str, payload: dict,
                 pinned: bytes | None) -> tuple[str, bytes | None]:
    """Descifra un mensaje "dr". Crea la sesión si es el primero de ese dispositivo.

    Devuelve (texto, IK del remitente si se acaba de conocer por X3DH).
    """
    dev = payload.get("dev", "")
    if not isinstance(dev, str) or not DEVICE_RE.match(dev):
        raise CryptoError("dispositivo de origen inválido")
    states = keys.states(sender, dev)
    x3dh = payload.get("x3dh")
    known = x3dh and any(st.get("x3dh_seen") == x3dh.get("ek") or (st.get("x3dh") or {}).get("ek") == x3dh.get("ek")
                         for st in states)
    if x3dh and not known:
        # Primer mensaje de esa sesión: creamos la sesión de respuesta
        fresh, ik = accept(me, keys.device, keys.identity, sender, dev, x3dh, keys, pinned)
        pt = fresh.decrypt(payload)
        fresh.st["x3dh_seen"] = x3dh["ek"]
        keys.push_new(sender, dev, fresh)
        return pt.decode("utf-8"), ik
    for i, st in enumerate(states):
        r = Ratchet(json.loads(json.dumps(st)))
        try:
            pt = r.decrypt(payload)
        except (CryptoError, KeyError, ValueError, TypeError):
            continue
        keys.store(sender, dev, r, i)  # la que ha funcionado pasa a ser la actual
        return pt.decode("utf-8"), None
    raise CryptoError("no se pudo descifrar (sesión desconocida o mensaje manipulado)")
