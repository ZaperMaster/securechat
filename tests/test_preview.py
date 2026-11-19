"""Vista previa de enlaces: lectura de metadatos y protección contra SSRF."""

import pytest

from securechat.preview import PreviewError, check_url, link_preview, parse_meta, public_ips


def test_parse_meta_prefers_open_graph():
    page = """<html><head><title>Título normal</title>
    <meta property="og:title" content="Título &amp; OG">
    <meta name='description' content='Descripción corta'>
    <meta property="og:site_name" content="Ejemplo">
    <meta property="og:image" content="/foto.jpg"></head></html>"""
    m = parse_meta(page)
    assert m == {"title": "Título & OG", "desc": "Descripción corta", "site": "Ejemplo", "image": "/foto.jpg"}


def test_parse_meta_falls_back_to_title():
    assert parse_meta("<title>\n  Hola   mundo </title>")["title"] == "Hola mundo"


@pytest.mark.parametrize("url", [
    "ftp://example.com/", "javascript:alert(1)", "http://example.com:8080/", "http://user:pw@example.com/",
    "file:///etc/passwd", "http:///nada", 123,
])
def test_check_url_rejects(url):
    with pytest.raises(PreviewError):
        check_url(url)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.19", "169.254.169.254", "::1", "0.0.0.0"])
def test_private_addresses_are_blocked(host):
    with pytest.raises(PreviewError):
        public_ips(host, 80)


def test_preview_never_reaches_the_local_server():
    with pytest.raises(PreviewError):
        link_preview("http://127.0.0.1/")
    with pytest.raises(PreviewError):
        link_preview("http://localhost:443/")
