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
