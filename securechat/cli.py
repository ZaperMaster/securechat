"""Interfaz de línea de comandos.

    python -m securechat init --name alice
    python -m securechat chat --name alice --server ws://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path

from nacl.signing import SigningKey

from .client import ChatClient, ClientError
from .contacts import Contacts
from .crypto import CryptoError, fingerprint, load_identity, safety_number, save_identity
from .server import USERNAME_HELP, USERNAME_RE

HELP = """Comandos:
  /open <usuario>     abre una sesión cifrada y la deja como conversación activa
  /to <usuario>       cambia la conversación activa
  /who                usuarios conectados
  /fp [usuario]       muestra tu huella o el número de seguridad con <usuario>
  /verify <usuario>   marca el contacto como verificado (tras comparar el número)
  /forget <usuario>   olvida la clave fijada de un contacto
  /contacts           lista de contactos
  /help               esta ayuda
  /quit               salir
Cualquier otro texto se envía cifrado a la conversación activa."""


def profile_dir(args) -> Path:
    return (args.home or Path.home() / ".securechat") / args.name


def cmd_init(args) -> None:
    path = profile_dir(args) / "identity.json"
    if path.exists():
        sys.exit(f"Ya existe una identidad en {path}")
    pw = getpass.getpass("Contraseña para proteger tu clave privada: ")
    if len(pw) < 8:
        sys.exit("Usa al menos 8 caracteres.")
    if getpass.getpass("Repite la contraseña: ") != pw:
        sys.exit("Las contraseñas no coinciden.")
    sk = SigningKey.generate()
    print("Derivando clave con Argon2id (tarda un poco a propósito)...")
    save_identity(path, sk, pw)
    print(f"Identidad creada en {path}")
    print(f"Tu huella: {fingerprint(bytes(sk.verify_key))}")


def _print(line: str) -> None:
    # \r limpia el prompt actual para que los mensajes entrantes no se mezclen.
    print(f"\r{line}\n> ", end="", flush=True)


async def _show_events(client: ChatClient) -> None:
    while True:
        ev = await client.events.get()
        c = client.contacts.get(ev.peer)
        badge = "✔" if c and c.verified else "?"
        if ev.kind == "message":
            _print(f"[{ev.peer} {badge}] {ev.text}")
        elif ev.kind == "session":
            hint = "" if c and c.verified else f"  (sin verificar: compara /fp {ev.peer})"
            _print(f"* {ev.peer}: {ev.text}{hint}")
        elif ev.kind == "identity_changed":
            _print(f"!!! AVISO DE SEGURIDAD: {ev.text}\n"
                   f"!!! Puede ser un ataque man-in-the-middle o que {ev.peer} reinstaló.\n"
                   f"!!! Confírmalo por otro canal antes de usar /forget {ev.peer}.")
        elif ev.kind == "profile":
            _print(f"* {ev.peer} se muestra como «{ev.text}»")
        elif ev.kind == "warning":
            _print(f"! {ev.text}")
        elif ev.kind == "disconnected":
            _print("* Desconectado del servidor.")
            return


async def _repl(client: ChatClient) -> None:
    active: str | None = None
    print(HELP)
    while True:
        line = (await asyncio.to_thread(input, "> ")).strip()
        if not line:
            continue
        try:
            if not line.startswith("/"):
                if not active:
                    print("No hay conversación activa. Usa /open <usuario>.")
                else:
                    await client.send_text(active, line)
                continue
            cmd, _, arg = line.partition(" ")
            arg = arg.strip()
            if cmd == "/quit":
                return
            elif cmd == "/help":
                print(HELP)
            elif cmd in ("/open", "/to"):
                if not USERNAME_RE.match(arg):
                    print("Nombre de usuario inválido.")
                    continue
                if cmd == "/open" or arg not in client.sessions:
                    arg = (await client.open_session(arg)).peer  # grafía oficial
                active = arg
                print(f"Conversación activa: {active}")
            elif cmd == "/who":
                print("Conectados:", ", ".join(await client.who()))
            elif cmd == "/fp":
                mine = bytes(client.identity.verify_key)
                if not arg:
                    print(f"Tu huella: {fingerprint(mine)}")
                elif (c := client.contacts.get(arg)) is None:
                    print(f"No conoces la clave de {arg}. Abre antes una sesión.")
                else:
                    print(f"Número de seguridad con {arg} "
                          f"({'verificado' if c.verified else 'SIN verificar'}):\n  "
                          + safety_number(client.name, mine, arg, c.identity_key))
                    print("Debe coincidir exactamente con el que ve tu contacto.")
            elif cmd == "/verify":
                if client.contacts.get(arg) is None:
                    print(f"No conoces la clave de {arg}.")
                    continue
                ok = await asyncio.to_thread(
                    input, f"¿Habéis comparado el número de seguridad con {arg} por otro canal? [s/N] ")
                if ok.strip().lower() in ("s", "si", "sí", "y", "yes"):
                    client.contacts.set_verified(arg)
                    print(f"{arg} marcado como verificado ✔")
            elif cmd == "/forget":
                client.contacts.forget(arg)
                client.sessions.pop(arg, None)
                print(f"Clave de {arg} olvidada. La próxima se fijará de nuevo (TOFU).")
            elif cmd == "/contacts":
                for c in client.contacts.all():
                    print(f"  {c.name:<20} {'✔' if c.verified else '?'}  {fingerprint(c.identity_key)}")
            else:
                print("Comando desconocido. /help para ver la ayuda.")
        except (ClientError, CryptoError, ValueError, TimeoutError) as exc:
            print(f"Error: {exc}")


async def _chat(args, identity: SigningKey) -> None:
    contacts = Contacts(profile_dir(args) / "contacts.json")
    client = ChatClient(args.name, identity, contacts)
    await client.connect(args.server)
    print(f"Conectado a {args.server} como {args.name}.")
    events = asyncio.create_task(_show_events(client))
    repl = asyncio.create_task(_repl(client))
    await asyncio.wait({events, repl}, return_when=asyncio.FIRST_COMPLETED)
    await client.close()


def cmd_chat(args) -> None:
    path = profile_dir(args) / "identity.json"
    if not path.exists():
        sys.exit(f"No hay identidad para {args.name}. Ejecuta antes: init --name {args.name}")
    try:
        identity = load_identity(path, getpass.getpass("Contraseña: "))
    except CryptoError as exc:
        sys.exit(str(exc))
    if args.server.startswith("ws://") and not args.server.startswith(("ws://127.", "ws://localhost")):
        print("Aviso: conexión sin TLS. El contenido va cifrado E2E, pero los metadatos no.")
    try:
        asyncio.run(_chat(args, identity))
    except (ClientError, OSError) as exc:
        sys.exit(f"No se pudo conectar: {exc}")
    except (KeyboardInterrupt, EOFError):
        pass


def main() -> None:
    p = argparse.ArgumentParser(prog="securechat", description="Mensajería cifrada E2E (proyecto educativo)")
    p.add_argument("--home", type=Path, help="carpeta de perfiles (por defecto ~/.securechat)")
    sub = p.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("init", help="crea tu identidad")
    pi.add_argument("--name", required=True)
    pc = sub.add_parser("chat", help="conecta al relay y chatea")
    pc.add_argument("--name", required=True)
    pc.add_argument("--server", default="ws://127.0.0.1:8765")
    args = p.parse_args()
    if not USERNAME_RE.match(args.name):
        sys.exit(f"Nombre inválido: {USERNAME_HELP}.")
    {"init": cmd_init, "chat": cmd_chat}[args.cmd](args)


if __name__ == "__main__":
    main()
