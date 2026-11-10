"""Sesiones cifradas extremo a extremo entre dos usuarios.

Protocolo (inspirado en SIGMA / Noise XX, simplificado — ver README):

    A -> B  hs1 = { idA, ephA, Sig_A("hs1" | A | B | idA | ephA) }
    B -> A  hs2 = { idB, ephB, Sig_B("hs2" | A | B | idA | idB | ephA | ephB) }

    th    = BLAKE2b(A | B | idA | idB | ephA | ephB)          (hash de la transcripción)
    root  = KDF(X25519(eph, eph_peer), th)
    ck    = KDF(root, "i2r") / KDF(root, "r2i")               (una cadena por dirección)

Cada mensaje usa una clave nueva derivada de la cadena (ratchet simétrico):

    mk_n = KDF(ck_n, "msg");  ck_{n+1} = KDF(ck_n, "chain")
    ct   = XChaCha20-Poly1305(mk_n, nonce aleatorio, aad = th | emisor | n)

Las claves efímeras X25519 solo viven en memoria durante la sesión y las claves
de mensaje se descartan tras usarse: robar la clave de identidad después no
permite descifrar conversaciones pasadas (secreto perfecto hacia adelante).
"""

from __future__ import annotations

import nacl.bindings as sodium
import nacl.exceptions
import nacl.utils
from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from nacl.public import PrivateKey
from nacl.signing import SigningKey

from .crypto import CryptoError, b64d, b64e, encode_fields, kdf, verify_signature

PROTOCOL = b"securechat-v1"
MAX_PLAINTEXT = 12 * 1024 * 1024  # cabe una imagen o vídeo de hasta 8 MB en base64
MAX_SKIP = 1000


class IdentityMismatch(CryptoError):
    """La clave de identidad recibida no coincide con la que teníamos fijada."""

    def __init__(self, peer: str, expected: bytes, received: bytes):
        super().__init__(f"¡La clave de identidad de '{peer}' ha cambiado!")
        self.peer, self.expected, self.received = peer, expected, received


class Session:
    def __init__(self, me: str, identity: SigningKey, peer: str, initiator: bool):
        self.me = me
        self.peer = peer
        self.initiator = initiator
        self._identity = identity
        self._eph: PrivateKey | None = PrivateKey.generate()
        self._eph_peer: bytes | None = None
        self.peer_identity: bytes | None = None
        self.established = False
        self._send_ck = self._recv_ck = b""
        self._th = b""
        self.send_n = 0
        self.recv_n = 0
        self.lost = 0  # mensajes que nunca llegaron o llegaron manipulados

    # ----------------------------------------------------------- handshake

    @property
    def _a(self) -> str:  # nombre del iniciador
        return self.me if self.initiator else self.peer

    @property
    def _b(self) -> str:  # nombre del respondedor
        return self.peer if self.initiator else self.me

    @classmethod
    def initiate(cls, me: str, identity: SigningKey, peer: str) -> tuple["Session", dict]:
        s = cls(me, identity, peer, initiator=True)
        eph = bytes(s._eph.public_key)
        id_a = bytes(identity.verify_key)
        sig = identity.sign(encode_fields(PROTOCOL, b"hs1", me.encode(), peer.encode(),
                                          id_a, eph)).signature
        return s, {"kind": "hs1", "identity_key": b64e(id_a), "eph": b64e(eph),
                   "sig": b64e(sig)}

    @classmethod
    def accept(cls, me: str, identity: SigningKey, peer: str, hs1: dict,
               pinned: bytes | None) -> tuple["Session", dict]:
        if hs1.get("kind") != "hs1":
            raise CryptoError("se esperaba hs1")
        id_a, eph_a = b64d(hs1["identity_key"]), b64d(hs1["eph"])
        _check_pinned(peer, pinned, id_a)
        verify_signature(id_a, encode_fields(PROTOCOL, b"hs1", peer.encode(), me.encode(),
                                             id_a, eph_a), b64d(hs1["sig"]))
        s = cls(me, identity, peer, initiator=False)
        s.peer_identity, s._eph_peer = id_a, eph_a
        id_b, eph_b = bytes(identity.verify_key), bytes(s._eph.public_key)
        sig = identity.sign(encode_fields(PROTOCOL, b"hs2", peer.encode(), me.encode(),
                                          id_a, id_b, eph_a, eph_b)).signature
        s._derive(id_a, id_b, eph_a, eph_b)
        return s, {"kind": "hs2", "identity_key": b64e(id_b), "eph": b64e(eph_b),
                   "sig": b64e(sig)}

    def complete(self, hs2: dict, pinned: bytes | None) -> None:
        if not self.initiator or self.established or hs2.get("kind") != "hs2":
            raise CryptoError("hs2 inesperado")
        id_b, eph_b = b64d(hs2["identity_key"]), b64d(hs2["eph"])
        _check_pinned(self.peer, pinned, id_b)
        id_a, eph_a = bytes(self._identity.verify_key), bytes(self._eph.public_key)
        verify_signature(id_b, encode_fields(PROTOCOL, b"hs2", self.me.encode(),
                                             self.peer.encode(), id_a, id_b, eph_a, eph_b),
                         b64d(hs2["sig"]))
        self.peer_identity, self._eph_peer = id_b, eph_b
        self._derive(id_a, id_b, eph_a, eph_b)

    def _derive(self, id_a: bytes, id_b: bytes, eph_a: bytes, eph_b: bytes) -> None:
        if len(self._eph_peer) != 32:
            raise CryptoError("clave efímera con longitud inválida")
        try:
            shared = sodium.crypto_scalarmult(bytes(self._eph), self._eph_peer)
        except nacl.exceptions.RuntimeError as exc:  # punto de orden bajo
            raise CryptoError("clave efímera inválida") from exc
        if shared == bytes(32):
            raise CryptoError("clave efímera inválida")
        self._th = blake2b(encode_fields(PROTOCOL, self._a.encode(), self._b.encode(),
                                         id_a, id_b, eph_a, eph_b),
                           digest_size=32, encoder=RawEncoder)
        root = kdf(shared, b"sc-root", self._th)
        i2r, r2i = kdf(root, b"sc-chain-i2r"), kdf(root, b"sc-chain-r2i")
        self._send_ck, self._recv_ck = (i2r, r2i) if self.initiator else (r2i, i2r)
        # Python no permite borrar memoria de forma fiable, pero al menos soltamos las
        # referencias para que la clave efímera no sobreviva a la sesión.
        self._eph = None
        self.established = True

    # ------------------------------------------------------------ mensajes

    def encrypt(self, text: str) -> dict:
        if not self.established:
            raise CryptoError("la sesión no está establecida")
        data = text.encode("utf-8")
        if len(data) > MAX_PLAINTEXT:
            raise ValueError("mensaje demasiado largo")
        mk = kdf(self._send_ck, b"sc-msg")
        self._send_ck = kdf(self._send_ck, b"sc-chain")
        n = self.send_n
        self.send_n += 1
        nonce = nacl.utils.random(24)
        ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            data, self._aad(self.me, n), nonce, mk)
        return {"kind": "msg", "n": n, "nonce": b64e(nonce), "ct": b64e(ct)}

    def decrypt(self, payload: dict) -> str:
        if not self.established:
            raise CryptoError("la sesión no está establecida")
        n = payload.get("n")
        # Nunca aceptamos un contador ya visto (repetición). Sí aceptamos saltos hacia
        # delante limitados: si un atacante destruye un mensaje, la sesión sigue viva
        # y el hueco queda registrado en `self.lost`. No guardamos claves saltadas
        # (a diferencia de Signal): un mensaje que llegue tarde se pierde.
        if not isinstance(n, int) or isinstance(n, bool) or n < self.recv_n:
            raise CryptoError("mensaje repetido o antiguo")
        if n - self.recv_n > MAX_SKIP:
            raise CryptoError("salto de contador demasiado grande")
        ck = self._recv_ck
        for _ in range(n - self.recv_n):
            ck = kdf(ck, b"sc-chain")
        mk = kdf(ck, b"sc-msg")
        try:
            pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                b64d(payload["ct"]), self._aad(self.peer, n), b64d(payload["nonce"]), mk)
        except (nacl.exceptions.CryptoError, KeyError, TypeError) as exc:
            raise CryptoError("mensaje manipulado o clave incorrecta") from exc
        # Solo avanzamos el ratchet si el mensaje era auténtico.
        self.lost += n - self.recv_n
        self._recv_ck = kdf(ck, b"sc-chain")
        self.recv_n = n + 1
        return pt.decode("utf-8")

    def _aad(self, sender: str, n: int) -> bytes:
        return encode_fields(self._th, sender.encode(), n.to_bytes(8, "big"))


def _check_pinned(peer: str, pinned: bytes | None, received: bytes) -> None:
    if pinned is not None and pinned != received:
        raise IdentityMismatch(peer, pinned, received)
