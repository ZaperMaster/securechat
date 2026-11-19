"""Vista previa de enlaces (título, descripción e imagen de una página).

La genera el servidor a petición de quien ENVÍA el enlace, y el resultado viaja
cifrado dentro del mensaje: quien lo recibe no visita la web (no se filtra su IP).
El servidor sí ve la dirección, pero no a quién se manda.

Como el servidor descarga páginas que le pide un usuario, se protege contra SSRF
(usarlo para llegar a la red interna):
  * solo http/https a los puertos 80 y 443;
  * el nombre se resuelve una vez y se rechaza si alguna IP no es pública
    (privadas, loopback, link-local, multicast, reservadas…);
  * la conexión va a esa IP ya comprobada (no se vuelve a resolver: evita el
    DNS rebinding) y el certificado se valida con el nombre original;
  * cada redirección se vuelve a comprobar (máximo 3);
  * tiempo y tamaño limitados.
"""

from __future__ import annotations

import base64
import html
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit

TIMEOUT = 5
MAX_HTML = 512 * 1024
MAX_IMAGE = 1024 * 1024
MAX_REDIRECTS = 3
USER_AGENT = "Mozilla/5.0 (compatible; SecureChatPreview/1.0)"


class PreviewError(Exception):
    pass


def public_ips(host: str, port: int) -> list[str]:
    """Resuelve el nombre y devuelve sus IP, solo si TODAS son públicas."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PreviewError("no existe esa dirección") from exc
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise PreviewError("no existe esa dirección")
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise PreviewError("dirección no permitida")
    return ips


def check_url(url: str) -> tuple[str, str, int, str]:
    if not isinstance(url, str) or len(url) > 2000:
        raise PreviewError("enlace no válido")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise PreviewError("enlace no válido")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in (80, 443):
        raise PreviewError("puerto no permitido")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, parts.hostname, port, path


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Conecta a una IP concreta pero valida el certificado con el nombre del sitio."""

    def __init__(self, ip: str, host: str, port: int):
        super().__init__(ip, port, timeout=TIMEOUT, context=ssl.create_default_context())
        self._sni = host

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


def fetch(url: str, max_bytes: int, accept: str) -> tuple[str, str, bytes]:
    """Descarga siguiendo como mucho MAX_REDIRECTS. Devuelve (url_final, content-type, cuerpo)."""
    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port, path = check_url(url)
        ip = public_ips(host, port)[0]
        conn = (_PinnedHTTPS(ip, host, port) if scheme == "https"
                else http.client.HTTPConnection(ip, port, timeout=TIMEOUT))
        try:
            conn.request("GET", path, headers={
                "Host": host if port in (80, 443) else f"{host}:{port}",
                "User-Agent": USER_AGENT, "Accept": accept, "Accept-Language": "es,en;q=0.8",
            })
            res = conn.getresponse()
            if res.status in (301, 302, 303, 307, 308):
                loc = res.getheader("Location")
                if not loc:
                    raise PreviewError("redirección sin destino")
                url = urljoin(url, loc)
                continue
            if res.status != 200:
                raise PreviewError(f"la página respondió {res.status}")
            body = res.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]
            return url, (res.getheader("Content-Type") or "").lower(), body
        except (OSError, http.client.HTTPException) as exc:
            raise PreviewError("no se pudo abrir la página") from exc
        finally:
            conn.close()
    raise PreviewError("demasiadas redirecciones")


_META = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r'([a-zA-Z_:.-]+)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s>]+))')
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def parse_meta(page: str) -> dict:
    found: dict[str, str] = {}
    for tag in _META.findall(page):
        attrs = {m.group(1).lower(): (m.group(3) or m.group(4) or m.group(5) or "") for m in _ATTR.finditer(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key and "content" in attrs and key not in found:
            found[key] = html.unescape(attrs["content"]).strip()
    title = found.get("og:title") or found.get("twitter:title")
    if not title:
        m = _TITLE.search(page)
        title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else ""
    return {
        "title": title[:200],
        "desc": (found.get("og:description") or found.get("twitter:description") or found.get("description") or "")[:300],
        "site": (found.get("og:site_name") or "")[:80],
        "image": found.get("og:image") or found.get("twitter:image") or "",
    }


def link_preview(url: str) -> dict:
    """Título, descripción, sitio e imagen (en base64) de una página. Lanza PreviewError."""
    final, ctype, body = fetch(url, MAX_HTML, "text/html,application/xhtml+xml")
    if "html" not in ctype:
        raise PreviewError("no es una página web")
    charset = re.search(r"charset=([\w-]+)", ctype)
    try:
        page = body.decode(charset.group(1) if charset else "utf-8", errors="replace")
    except LookupError:
        page = body.decode("utf-8", errors="replace")
    meta = parse_meta(page)
    if not meta["title"] and not meta["desc"]:
        raise PreviewError("la página no tiene título")
    out = {"url": url, "title": meta["title"], "desc": meta["desc"],
           "site": meta["site"] or (urlsplit(final).hostname or "").removeprefix("www."), "image": None, "mime": None}
    if meta["image"]:
        try:
            _, itype, img = fetch(urljoin(final, meta["image"]), MAX_IMAGE, "image/*")
            mime = itype.split(";")[0].strip()
            if mime in ("image/jpeg", "image/png", "image/webp", "image/gif") and len(img) < MAX_IMAGE:
                out["image"] = base64.b64encode(img).decode()
                out["mime"] = mime
        except PreviewError:
            pass
    return out
