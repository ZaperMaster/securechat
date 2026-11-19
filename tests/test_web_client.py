"""Ejecuta las pruebas del cliente web (tests/web/*.test.mjs) con Node, si está instalado."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("node") is None, reason="hace falta Node.js")
def test_web_client_suite():
    files = [str(p) for p in sorted((ROOT / "tests" / "web").glob("*.test.mjs"))]
    r = subprocess.run(["node", "--test", *files], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
