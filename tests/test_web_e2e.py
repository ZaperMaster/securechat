"""Clientes web reales (Node) contra el servidor: remitente oculto, bloqueos y PQXDH."""

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from test_integration import start_server

NODE = shutil.which("node")
SCRIPT = str(Path(__file__).with_name("web_clients.mjs"))
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js no está instalado")


def scenario(name, spy=None):
    async def main():
        srv, url, relay = await start_server()
        seen = {"sealed": [], "identified": []}
        orig_sealed, orig_relay = relay._relay_sealed, relay._relay

        async def sealed(ws, msg):
            seen["sealed"].append(msg)
            await orig_sealed(ws, msg)

        async def identified(ws, sender, dev, msg):
            seen["identified"].append((sender, msg))
            await orig_relay(ws, sender, dev, msg)

        relay._relay_sealed, relay._relay = sealed, identified
        proc = await asyncio.create_subprocess_exec(NODE, SCRIPT, name, url, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 40)
        srv.close()
        assert proc.returncode == 0, err.decode()
        return json.loads(out), seen, relay

    return asyncio.run(main())


def test_sealed_sender_hides_who_writes_and_block_stops_it():
    log, seen, relay = scenario("sealed")
    assert log["aliceHasAk"]
    assert not log["bobKnowsAliceAk"]           # antes de que Alice le escriba, no tiene su clave
    assert log["aliceKnowsBobAk"] and log["bobKnowsAliceAkAfter"]
    # Hubo envíos sellados, y en ellos no aparece el remitente por ninguna parte
    assert seen["sealed"]
    for m in seen["sealed"]:
        assert set(m["payload"]) == {"kind", "box"}
        # Solo el destinatario, su dispositivo y su clave de entrega: nada que diga quién lo envía
        assert set(m) <= {"type", "to", "device", "uak", "payload", "id", "silent", "ephemeral", "urgent"}
    # "hola 3" fue sellado: hay sobres para Alice que no dicen que son de Bob
    assert "hola 3" in log["aliceInbox"]
    assert any(m["to"] == "alice" for m in seen["sealed"])
    # Bloqueado: el servidor lo descarta sin decírselo y la clave vieja deja de valer
    assert log["epochAfterBlock"] == 2
    assert log["bobStatusWhenBlocked"] == "queued"
    assert "hola 4" not in log["aliceInbox"]
    assert log["bobAkDroppedAfterBlock"]
    assert "hola 5" in log["aliceInbox"]
    assert relay.registry["alice"]["blocked"] == []


def test_web_clients_use_pqxdh():
    log, seen, relay = scenario("pq")
    assert log["bobInbox"] == ["cuántico"]
    assert log["alicePq"] and log["bobPq"]
    assert all("kem" in d["bundle"] for d in relay.registry["bob"]["devices"].values())
