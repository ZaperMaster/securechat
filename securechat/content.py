"""Formato del contenido que va DENTRO del cifrado.

Cada mensaje cifrado es un JSON con un campo "t" (tipo):

    {"t": "text",    "body": "hola"}
    {"t": "image",   "mime": "image/png", "name": "foto.png", "data": "<base64>"}
    {"t": "video",   "mime": "video/mp4", "name": "clip.mp4", "data": "<base64>"}
    {"t": "sticker", "id": "🔥"}
    {"t": "profile", "name": "Alejandro", "avatar": "<base64 jpeg>" | null}

Como el tipo viaja cifrado, el servidor no sabe si envías texto, una foto o tu
perfil; solo ve el tamaño aproximado.
"""

from __future__ import annotations

import json

IMAGE_MIME = {"image/png", "image/jpeg", "image/gif", "image/webp"}
VIDEO_MIME = {"video/mp4", "video/webm", "video/quicktime"}
MAX_MEDIA = 8 * 1024 * 1024
MAX_NAME = 64


def text(body: str) -> str:
    return json.dumps({"t": "text", "body": body}, ensure_ascii=False)


def decode(plaintext: str) -> dict:
    """Interpreta un mensaje descifrado. Si no es JSON válido, se trata como texto."""
    try:
        c = json.loads(plaintext)
    except ValueError:
        return {"t": "text", "body": plaintext}
    if not isinstance(c, dict) or not isinstance(c.get("t"), str):
        return {"t": "text", "body": plaintext}
    return c


def describe(c: dict) -> str:
    """Resumen legible para la terminal, que no puede mostrar imágenes."""
    t = c.get("t")
    if t == "text":
        return str(c.get("body", ""))
    if t == "sticker":
        return f"[sticker {c.get('id', '')}]"
    if t in ("image", "video"):
        kind = "GIF" if c.get("mime") == "image/gif" else ("imagen" if t == "image" else "vídeo")
        return f"[{kind}: {c.get('name') or 'sin nombre'}]"
    return f"[contenido no soportado: {t}]"
