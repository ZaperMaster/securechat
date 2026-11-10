import nacl.pwhash
import pytest
from nacl.signing import SigningKey

from securechat.crypto import (CryptoError, fingerprint, load_identity, safety_number,
                               save_identity)
from securechat.session import IdentityMismatch, Session

FAST = dict(opslimit=nacl.pwhash.argon2id.OPSLIMIT_MIN, memlimit=nacl.pwhash.argon2id.MEMLIMIT_MIN)


def test_keystore_roundtrip(tmp_path):
    sk = SigningKey.generate()
    save_identity(tmp_path / "id.json", sk, "correct horse", **FAST)
    assert bytes(load_identity(tmp_path / "id.json", "correct horse")) == bytes(sk)
    assert bytes(sk) not in (tmp_path / "id.json").read_bytes()


def test_keystore_wrong_password(tmp_path):
    save_identity(tmp_path / "id.json", SigningKey.generate(), "correct horse", **FAST)
    with pytest.raises(CryptoError):
        load_identity(tmp_path / "id.json", "wrong")


def test_safety_number_is_symmetric_and_key_dependent():
    a, b, c = (bytes(SigningKey.generate().verify_key) for _ in range(3))
    assert safety_number("alice", a, "bob", b) == safety_number("bob", b, "alice", a)
    assert safety_number("alice", a, "bob", b) != safety_number("alice", a, "bob", c)
    assert len(safety_number("alice", a, "bob", b).replace(" ", "")) == 60
    assert fingerprint(a) != fingerprint(b)


def handshake():
    ka, kb = SigningKey.generate(), SigningKey.generate()
    a, hs1 = Session.initiate("alice", ka, "bob")
    b, hs2 = Session.accept("bob", kb, "alice", hs1, pinned=None)
    a.complete(hs2, pinned=None)
    return a, b, ka, kb


def test_roundtrip_both_directions():
    a, b, ka, kb = handshake()
    assert a.peer_identity == bytes(kb.verify_key) and b.peer_identity == bytes(ka.verify_key)
    for i in range(5):
        assert b.decrypt(a.encrypt(f"hola {i}")) == f"hola {i}"
        assert a.decrypt(b.encrypt(f"adiós {i}")) == f"adiós {i}"


def test_each_message_uses_a_new_key():
    a, b, *_ = handshake()
    m1, m2 = a.encrypt("mismo texto"), a.encrypt("mismo texto")
    assert m1["ct"] != m2["ct"]
    assert b.decrypt(m1) == b.decrypt(m2) == "mismo texto"


def test_tampered_message_rejected():
    a, b, *_ = handshake()
    m = a.encrypt("transfiere 10€")
    ct = bytearray(__import__("base64").b64decode(m["ct"]))
    ct[0] ^= 1
    m["ct"] = __import__("base64").b64encode(bytes(ct)).decode()
    with pytest.raises(CryptoError):
        b.decrypt(m)
    # Un mensaje manipulado no debe romper la sesión.
    assert b.decrypt(a.encrypt("siguiente")) == "siguiente"


def test_replay_and_reorder_rejected():
    a, b, *_ = handshake()
    m0, m1, m2 = a.encrypt("uno"), a.encrypt("dos"), a.encrypt("tres")
    assert b.decrypt(m0) == "uno"
    with pytest.raises(CryptoError):
        b.decrypt(m0)  # repetición
    assert b.decrypt(m2) == "tres"  # m1 se perdió: se acepta el salto...
    assert b.lost == 1
    with pytest.raises(CryptoError):
        b.decrypt(m1)  # ...pero m1 ya no se acepta si llega tarde
    big = dict(a.encrypt("x"), n=10_000)
    with pytest.raises(CryptoError):
        b.decrypt(big)


def test_reflection_rejected():
    """Un mensaje de Alice reenviado a la propia Alice no se acepta."""
    a, b, *_ = handshake()
    with pytest.raises(CryptoError):
        a.decrypt(a.encrypt("eco"))


def test_mitm_key_substitution_detected_by_signature():
    ka, kb, mallory = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    _, hs1 = Session.initiate("alice", ka, "bob")
    # El atacante cambia la clave efímera pero no puede volver a firmar como Alice.
    _, forged = Session.initiate("alice", mallory, "bob")
    hs1_bad = dict(hs1, eph=forged["eph"])
    with pytest.raises(CryptoError):
        Session.accept("bob", kb, "alice", hs1_bad, pinned=None)


def test_mitm_with_own_identity_detected_by_pinning():
    ka, kb, mallory = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    _, forged = Session.initiate("alice", mallory, "bob")
    with pytest.raises(IdentityMismatch):
        Session.accept("bob", kb, "alice", forged, pinned=bytes(ka.verify_key))


def test_wrong_recipient_rejected():
    """Un hs1 dirigido a Bob no sirve para abrir sesión con Carol."""
    ka, kc = SigningKey.generate(), SigningKey.generate()
    _, hs1 = Session.initiate("alice", ka, "bob")
    with pytest.raises(CryptoError):
        Session.accept("carol", kc, "alice", hs1, pinned=None)


def test_low_order_ephemeral_rejected():
    ka, kb = SigningKey.generate(), SigningKey.generate()
    eph = bytes(32)
    from securechat.crypto import b64e, encode_fields
    from securechat.session import PROTOCOL
    id_a = bytes(ka.verify_key)
    sig = ka.sign(encode_fields(PROTOCOL, b"hs1", b"alice", b"bob", id_a, eph)).signature
    hs1 = {"kind": "hs1", "identity_key": b64e(id_a), "eph": b64e(eph), "sig": b64e(sig)}
    with pytest.raises(CryptoError):
        Session.accept("bob", kb, "alice", hs1, pinned=None)
