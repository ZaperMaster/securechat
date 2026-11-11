import nacl.pwhash
import pytest
from nacl.signing import SigningKey

from securechat.crypto import (CryptoError, fingerprint, load_identity, safety_number,
                               save_identity)

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
