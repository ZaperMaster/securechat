"""Protocolo v2: X3DH con one-time prekeys + Double Ratchet."""

import random

import pytest
from nacl.signing import SigningKey

from securechat.crypto import CryptoError, b64e
from securechat.ratchet import DeviceKeys, IdentityMismatch, decrypt_from, encrypt_for, initiate


class Device:
    def __init__(self, user, identity, path=None):
        self.user, self.identity = user, identity
        self.keys = DeviceKeys(user, identity, path)
        up = self.keys.upload_message(0)
        self.bundle = {"spk": up["spk"], "sig": up["sig"], "created": up["created"]}
        self.opks = list(up["opks"])  # lo que tendría el servidor

    def bundle_for_peer(self, with_opk=True):
        b = dict(self.bundle)
        b["opk"] = self.opks.pop(0) if with_opk and self.opks else None
        return b

    def send(self, peer, text, pinned=None):
        r = self.keys.session(peer.user, peer.keys.device)
        if r is None:
            r = initiate(self.user, self.keys.device, self.identity, peer.user, peer.keys.device,
                         bytes(peer.identity.verify_key), peer.bundle_for_peer(), pinned)
            self.keys.push_new(peer.user, peer.keys.device, r)
        payload = encrypt_for(self.user, self.keys.device, r, text)
        self.keys.store(peer.user, peer.keys.device, r)
        return payload

    def recv(self, sender, payload, pinned=None):
        return decrypt_from(self.user, self.keys, sender.user, payload, pinned)[0]


def pair():
    return Device("alice", SigningKey.generate()), Device("bob", SigningKey.generate())


def test_offline_first_message_and_conversation():
    a, b = pair()
    m1 = a.send(b, "hola, aunque no estés")      # Bob puede estar desconectado: solo hace falta su bundle
    assert "x3dh" in m1 and m1["x3dh"]["opk"]
    assert b.recv(a, m1) == "hola, aunque no estés"
    for i in range(3):
        assert a.recv(b, b.send(a, f"respuesta {i}")) == f"respuesta {i}"
        assert b.recv(a, a.send(b, f"vuelta {i}")) == f"vuelta {i}"
    assert "x3dh" not in a.send(b, "ya sin cabecera X3DH")  # tras la respuesta no se repite


def test_each_message_new_key_and_dh_ratchet_advances():
    a, b = pair()
    b.recv(a, a.send(b, "1"))
    dh_before = a.keys.session("bob", b.keys.device).st["dhs"][1]
    a.recv(b, b.send(a, "2"))
    m = a.send(b, "3")
    assert m["header"]["dh"] != dh_before  # nueva clave DH al cambiar el turno (curación)
    x, y = a.send(b, "mismo"), a.send(b, "mismo")
    assert x["ct"] != y["ct"]


def test_out_of_order_and_lost_messages():
    a, b = pair()
    b.recv(a, a.send(b, "inicio"))
    a.recv(b, b.send(a, "ok"))
    msgs = [a.send(b, f"m{i}") for i in range(6)]
    order = [3, 0, 5, 1]
    for i in order:
        assert b.recv(a, msgs[i]) == f"m{i}"
    with pytest.raises(CryptoError):
        b.recv(a, msgs[3])  # repetido: su clave ya se usó y se borró


def test_tampered_message_does_not_break_session():
    a, b = pair()
    b.recv(a, a.send(b, "inicio"))
    m = a.send(b, "secreto")
    bad = dict(m, ct=b64e(b"\x00" * 40))
    with pytest.raises(CryptoError):
        b.recv(a, bad)
    assert b.recv(a, m) == "secreto"


def test_one_time_prekey_cannot_be_replayed():
    a, b = pair()
    first = a.send(b, "hola")
    assert b.recv(a, first) == "hola"
    b.keys.drop("alice", a.keys.device)  # aunque Bob perdiera la sesión…
    with pytest.raises(CryptoError):
        b.recv(a, first)  # …la OPK ya se usó: repetir el primer mensaje no sirve


def test_works_without_one_time_prekeys():
    a, b = pair()
    b.opks.clear()  # el servidor se quedó sin OPK
    m = a.send(b, "sin opk")
    assert m["x3dh"]["opk"] is None
    assert b.recv(a, m) == "sin opk"


def test_simultaneous_first_messages_converge():
    a, b = pair()
    ma = a.send(b, "de alice")
    mb = b.send(a, "de bob")  # los dos empiezan a la vez, cada uno con su sesión
    assert b.recv(a, ma) == "de alice"
    assert a.recv(b, mb) == "de bob"
    for i in range(4):
        assert b.recv(a, a.send(b, f"a{i}")) == f"a{i}"
        assert a.recv(b, b.send(a, f"b{i}")) == f"b{i}"


def test_identity_pinning_and_spk_signature():
    a, b = pair()
    mallory = SigningKey.generate()
    with pytest.raises(IdentityMismatch):
        a.send(b, "x", pinned=bytes(mallory.verify_key))
    b.bundle["sig"] = b64e(bytes(64))  # prekey sin firma válida
    with pytest.raises(CryptoError):
        a.send(b, "x")


def test_state_persists_encrypted(tmp_path):
    ka, kb = SigningKey.generate(), SigningKey.generate()
    a = Device("alice", ka, tmp_path / "a.keys")
    b = Device("bob", kb, tmp_path / "b.keys")
    b.recv(a, a.send(b, "antes de reiniciar"))
    raw = (tmp_path / "b.keys").read_text()
    # Buscamos los nombres como cadenas JSON: dentro del base64 cifrado podría salir "bob" por azar
    assert "antes" not in raw and "\"bob\"" not in raw and "\"alice\"" not in raw  # cifrado en disco
    b2 = DeviceKeys("bob", kb, tmp_path / "b.keys")  # "reinicio" del dispositivo
    assert b2.device == b.keys.device
    b.keys = b2
    assert b.recv(a, a.send(b, "después")) == "después"


def test_random_conversation_fuzz():
    a, b = pair()
    rnd = random.Random(7)
    b.recv(a, a.send(b, "start"))
    pending = {"a": [], "b": []}
    for i in range(200):
        who = rnd.choice("ab")
        if who == "a":
            pending["b"].append((a.send(b, f"a{i}"), f"a{i}"))
        else:
            pending["a"].append((b.send(a, f"b{i}"), f"b{i}"))
        for target, sender, recv in (("a", b, a), ("b", a, b)):
            if pending[target] and rnd.random() < 0.6:
                j = rnd.randrange(len(pending[target]))
                msg, text = pending[target].pop(j)
                assert recv.recv(sender, msg) == text
