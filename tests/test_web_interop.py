"""El cliente web (JS) y el de terminal (Python) deben entenderse byte a byte."""

import asyncio
import json
import shutil
import subprocess
from pathlib import Path

import nacl.pwhash
import nacl.utils
import pytest
from nacl.signing import SigningKey

from securechat.crypto import (b64d, b64e, fingerprint, kdf, load_identity, safety_number,
                               save_identity)

from test_integration import new_client, next_event, run, start_server

NODE = shutil.which("node")
SCRIPT = str(Path(__file__).with_name("interop.mjs"))
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js no está instalado")


def js(*args, stdin=""):
    r = subprocess.run([NODE, SCRIPT, *args], input=stdin, capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_kdf_matches():
    key, data = nacl.utils.random(32), nacl.utils.random(40)
    assert js("kdf", b64e(key), "sc-root", b64e(data)) == b64e(kdf(key, b"sc-root", data))


def test_safety_number_and_fingerprint_match():
    a, b = bytes(SigningKey.generate().verify_key), bytes(SigningKey.generate().verify_key)
    sn, fp = js("safety", "alice", b64e(a), "bob", b64e(b)).split("\n")
    assert sn == safety_number("alice", a, "bob", b)
    assert fp == fingerprint(a)


def test_keystore_js_to_python(tmp_path):
    blob = js("keystore", "contraseña segura")
    (tmp_path / "id.json").write_text(blob, encoding="utf-8")
    sk = load_identity(tmp_path / "id.json", "contraseña segura")
    assert b64e(bytes(sk.verify_key)) == json.loads(blob)["public_key"]


def test_keystore_python_to_js(tmp_path):
    sk = SigningKey.generate()
    save_identity(tmp_path / "id.json", sk, "otra contraseña",
                  opslimit=nacl.pwhash.argon2id.OPSLIMIT_MIN,
                  memlimit=nacl.pwhash.argon2id.MEMLIMIT_MIN)
    pub = js("loadkey", "otra contraseña", stdin=(tmp_path / "id.json").read_text(encoding="utf-8"))
    assert pub == b64e(bytes(sk.verify_key))


async def _spawn(*args):
    p = await asyncio.create_subprocess_exec(NODE, SCRIPT, *args, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
    assert (await asyncio.wait_for(p.stderr.readline(), 15)).strip() == b"ready"
    return p


def test_web_initiates_python_replies():
    async def main():
        srv, url, _ = await start_server()
        bob = await new_client(url, "bob")
        web = await _spawn("chat", url, "webalice", "bob")
        ev = await next_event(bob, "message", timeout=15)
        assert (ev.peer, ev.text) == ("webalice", "hola desde la web ñ😀")
        await bob.send_text("webalice", "hola desde python")
        out, _ = await asyncio.wait_for(web.communicate(), 15)
        assert out.decode() == "hola desde python"
        await bob.close(); srv.close()
    run(main())


def test_python_initiates_web_replies():
    async def main():
        srv, url, _ = await start_server()
        web = await _spawn("listen", url, "webbob")
        alice = await new_client(url, "alice")
        await alice.send_text("webbob", "¿me oyes?")
        assert (await next_event(alice, "message", timeout=15)).text == "eco: ¿me oyes?"
        await asyncio.wait_for(web.wait(), 15)
        await alice.close(); srv.close()
    run(main())


def test_python_sends_image_to_web():
    async def main():
        srv, url, _ = await start_server()
        web = await _spawn("listen", url, "WebBob")
        alice = await new_client(url, "alice")
        data = b64e(nacl.utils.random(2_000_000))
        await alice.send_content("webbob", json.dumps(
            {"t": "image", "mime": "image/gif", "name": "gato.gif", "data": data}))
        out, _ = await asyncio.wait_for(web.communicate(), 20)
        assert json.loads(out) == {"t": "image", "mime": "image/gif", "len": len(data)}
        await alice.close(); srv.close()
    run(main())


def test_web_receives_while_it_was_offline():
    """Python escribe a un usuario web desconectado; al conectarse, la web lo lee."""
    async def main():
        srv, url, _ = await start_server()
        web = await _spawn("listen", url, "webdave")
        alice = await new_client(url, "alice")
        await alice.send_text("webdave", "primero")  # crea la sesión (la web está conectada)
        assert (await next_event(alice, "message", timeout=15)).text == "eco: primero"
        await asyncio.wait_for(web.wait(), 15)
        srv.close()
    run(main())


def test_double_ratchet_between_python_and_javascript():
    from test_ratchet import Device
    proc = subprocess.Popen([NODE, SCRIPT, "dr-peer"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8")

    def js_cmd(**c):
        proc.stdin.write(json.dumps(c) + "\n")
        proc.stdin.flush()
        out = json.loads(proc.stdout.readline())
        assert "error" not in out, out
        return out

    try:
        info = js_cmd(cmd="init", user="webbob")
        py = Device("alice", SigningKey.generate())

        class JsPeer:  # lo que Python necesita saber del dispositivo JS
            user = "webbob"
            identity = type("I", (), {"verify_key": b64d(info["ik"])})()
            keys = type("K", (), {"device": info["device"]})()
            opks = list(info["opks"])

            def bundle_for_peer(self):
                return {**info["bundle"], "opk": self.opks.pop(0)}

        peer = JsPeer()
        # Python empieza (X3DH con OPK) aunque "webbob" estuviera desconectado
        r = py.keys.session("webbob", info["device"])
        from securechat.ratchet import encrypt_for, initiate
        r = initiate("alice", py.keys.device, py.identity, "webbob", info["device"], b64d(info["ik"]),
                     peer.bundle_for_peer(), None)
        py.keys.push_new("webbob", info["device"], r)
        for i in range(3):
            payload = encrypt_for("alice", py.keys.device, r, f"py→js {i} ñ😀")
            py.keys.store("webbob", info["device"], r)
            assert js_cmd(cmd="recv", sender="alice", payload=payload)["text"] == f"py→js {i} ñ😀"
        # JS responde (ratchet DH) y siguen alternando
        for i in range(3):
            out = js_cmd(cmd="send", peer="alice", peerDev=py.keys.device, peerIk=b64e(bytes(py.identity.verify_key)), text=f"js→py {i}")
            from securechat.ratchet import decrypt_from
            assert decrypt_from("alice", py.keys, "webbob", out["payload"], None)[0] == f"js→py {i}"
            r = py.keys.session("webbob", info["device"])
            payload = encrypt_for("alice", py.keys.device, r, f"otra {i}")
            py.keys.store("webbob", info["device"], r)
            assert js_cmd(cmd="recv", sender="alice", payload=payload)["text"] == f"otra {i}"

        # Y al revés: JS inicia una sesión nueva con un dispositivo Python
        py2 = Device("carol", SigningKey.generate())
        b = py2.bundle_for_peer()
        out = js_cmd(cmd="send", peer="carol", peerDev=py2.keys.device, peerIk=b64e(bytes(py2.identity.verify_key)),
                     bundle=b, text="hola desde JS")
        assert out["payload"]["x3dh"]["opk"] == b["opk"]
        from securechat.ratchet import decrypt_from
        assert decrypt_from("carol", py2.keys, "webbob", out["payload"], None)[0] == "hola desde JS"
    finally:
        proc.stdin.write('{"cmd": "quit"}\n')
        proc.stdin.flush()
        proc.wait(timeout=10)


def test_padding_matches_python_and_hides_length():
    from securechat.content import pad_json
    samples = [{"t": "text", "body": "ok", "mid": "abcdefgh12"},
               {"t": "text", "body": "un mensaje bastante más largo con tildes y ñ " * 6, "mid": "abcdefgh12"},
               {"t": "text", "body": "x" * 5000},
               {"t": "image", "mime": "image/png", "data": "A" * 70000}]
    lines = [json.dumps(s, ensure_ascii=False) for s in samples]
    web = js("pad", stdin="\n".join(lines)).split("\n")
    py = [pad_json(line) for line in lines]
    assert web == py
    sizes = [len(x.encode("utf-8")) for x in py]
    assert sizes == [256, 1024, 16384, 131072]
    # Los dos mensajes de texto cortos miden lo mismo aunque el contenido sea distinto
    assert len(pad_json(json.dumps({"t": "text", "body": "sí"})).encode()) == len(pad_json(json.dumps({"t": "text", "body": "hola, ¿qué tal?"})).encode())
    # El relleno no cambia lo que se lee
    assert json.loads(js("decode", stdin=web[0]))["body"] == "ok"


def test_new_content_types_are_validated():
    poll = json.loads(js("decode", stdin=json.dumps({"t": "poll", "q": "¿Pizza?", "opts": ["sí", "no", 3], "multi": True})))
    assert poll == {"t": "poll", "q": "¿Pizza?", "opts": ["sí", "no"], "multi": True}
    assert json.loads(js("decode", stdin=json.dumps({"t": "poll", "q": "x", "opts": ["solo una"]})))["t"] == "unsupported"
    f = json.loads(js("decode", stdin=json.dumps({"t": "file", "mime": "text/html", "name": "a.html", "size": 10, "data": "QQ=="})))
    assert f["t"] == "file" and f["name"] == "a.html"
    assert json.loads(js("decode", stdin=json.dumps({"t": "timer", "secs": 123})))["t"] == "ignore"
    assert json.loads(js("decode", stdin=json.dumps({"t": "text", "body": "hola", "exp": 86400})))["exp"] == 86400
    assert "exp" not in json.loads(js("decode", stdin=json.dumps({"t": "text", "body": "hola", "exp": 5})))
    call = json.loads(js("decode", stdin=json.dumps({"t": "call", "kind": "offer", "id": "abcdefgh12", "sdp": "v=0", "video": True})))
    assert call["kind"] == "offer" and call["video"] is True
    assert json.loads(js("decode", stdin=json.dumps({"t": "call", "kind": "hack", "id": "abcdefgh12"})))["t"] == "ignore"
