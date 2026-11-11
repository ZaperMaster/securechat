"""Formato del contenido que va DENTRO del cifrado.

Cada mensaje cifrado es un JSON con un campo "t" (tipo):

    {"t": "text",    "body": "hola"}
    {"t": "image",   "mime": "image/png", "name": "foto.png", "data": "<base64>"}
    {"t": "video",   "mime": "video/mp4", "name": "clip.mp4", "data": "<base64>"}
    {"t": "sticker", "id": "🔥"}
    {"t": "profile", "name": "Alejandro", "bio": "…", "avatar": "<base64 jpeg>" | null}
    {"t": "receipt", "ids": ["<mid>", …], "s": "delivered" | "read"}
    {"t": "audio",   "mime": "audio/webm", "data": "<base64>", "dur": 12.5}  (nota de voz)
    {"t": "react",   "target": "<mid>", "emoji": "👍"}       (vacío = quitar)
    {"t": "edit",    "target": "<mid>", "body": "texto nuevo"}
    {"t": "delete",  "target": "<mid>"}                      (borrar para todos)
    {"t": "typing",  "on": true}                             (solo en vivo, nunca en cola)
    {"t": "group",   "g": "<id>", "name", "members", "admin", "v"}   (estado de un grupo)
    {"t": "group-leave", "g": "<id>"}

Cualquier mensaje visible puede llevar "g" (es de un grupo) y "reply" (responde a otro).

Los mensajes visibles llevan además "mid", un identificador aleatorio que el
destinatario usa para confirmar la entrega o la lectura (los dos checks).

Como el tipo viaja cifrado, el servidor no sabe si envías texto, una foto o tu
perfil; solo ve el tamaño aproximado.
"""

from __future__ import annotations

import json
import secrets

IMAGE_MIME = {"image/png", "image/jpeg", "image/gif", "image/webp"}
VIDEO_MIME = {"video/mp4", "video/webm", "video/quicktime"}
AUDIO_MIME = {"audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/aac"}
# Tipos que no se muestran como mensaje (acciones o señales)
SILENT = {"react", "edit", "delete", "typing", "group", "group-leave", "receipt", "profile"}
MAX_MEDIA = 8 * 1024 * 1024
MAX_NAME = 64


def new_mid() -> str:
    return secrets.token_urlsafe(12)


def text(body: str) -> str:
    return json.dumps({"t": "text", "body": body, "mid": new_mid()}, ensure_ascii=False)


def receipt(ids: list[str], status: str) -> str:
    return json.dumps({"t": "receipt", "ids": ids, "s": status})


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
    if t == "audio":
        return f"[nota de voz {int(c.get('dur') or 0)} s]"
    if t in ("image", "video"):
        kind = "GIF" if c.get("mime") == "image/gif" else ("imagen" if t == "image" else "vídeo")
        return f"[{kind}: {c.get('name') or 'sin nombre'}]"
    return f"[contenido no soportado: {t}]"
