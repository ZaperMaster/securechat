"""Pruebas en un navegador de verdad (Playwright): la app completa, como la usa una persona.

Arranca un servidor de prueba y abre varias "personas" (contextos de navegador separados,
cada uno con su almacenamiento). Comprueba crear cuenta, el código de recuperación, las
solicitudes de mensajes de desconocidos, bloquear y recuperar la cuenta con el código.

En GitHub Actions usa Chromium; en tu equipo, si no hay Chromium de Playwright, Edge o Chrome.
Se salta si Playwright no está instalado (pip install -r requirements-e2e.txt).
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "Caballo-Bateria-Grapa-77"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("srv")
    port = free_port()
    proc = subprocess.Popen([sys.executable, "-m", "securechat.server", "--port", str(port), "--no-code",
                             "--db", str(tmp / "users.json"), "--queue", str(tmp / "queue")],
                            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            break
        except OSError:
            time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(10)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        last = None
        # Micrófono y cámara falsos (las llamadas funcionan sin hardware ni ventanas de permiso)
        media = ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"]
        for opts in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
            try:
                b = p.chromium.launch(args=media, **opts)
                break
            except Exception as exc:  # noqa: BLE001 - probamos el siguiente navegador
                last = exc
        else:
            pytest.skip(f"no hay ningún navegador Chromium disponible: {last}")
        yield b
        b.close()


class Person:
    """Una persona con su propio navegador (almacenamiento separado)."""

    def __init__(self, browser, url):
        self.ctx = browser.new_context(locale="es-ES", permissions=["microphone", "camera"])
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(20000)
        self.page.on("dialog", lambda d: d.accept())  # confirm() de bloquear, etc.
        self.page.goto(url)
        self.page.wait_for_selector("#login-form")

    def register(self, name) -> str:
        """Crea la cuenta y devuelve el código de recuperación que enseña la app."""
        p = self.page
        p.click("#to-register")
        p.fill("#login-name", name)
        p.fill("#login-pass", PASSWORD)
        p.fill("#login-pass2", PASSWORD)
        p.click("#login-btn")
        code = p.wait_for_selector(".recovery-code").inner_text().strip()
        p.check("#dlg-body input[type=checkbox]")
        p.click("#dlg-actions button:has-text('Listo')")
        p.click("#dlg-actions button:has-text('Ahora no')")  # perfil de bienvenida
        p.wait_for_selector("#app:not([hidden])")
        return code

    def open_chat(self, peer, nickname=None):
        self.page.fill("#new-chat-name", peer)
        self.page.press("#new-chat-name", "Enter")
        self.page.wait_for_selector("#peer-name", state="visible")
        # Chat nuevo: pregunta con qué nombre guardarle
        ask = self.page.locator("#dlg-actions button:has-text('Omitir')")
        ask.wait_for(timeout=5000)
        if nickname:
            self.page.fill("#dlg-body input", nickname)
            self.page.click("#dlg-actions button:has-text('Guardar')")
        else:
            ask.click()

    def send(self, text):
        self.page.fill("#text", text)
        self.page.press("#text", "Enter")

    def bubble(self, text):
        return self.page.locator("#messages li.msg", has_text=text)

    def row(self, conv):
        return self.page.locator(f"#contacts li[data-conv='{conv}']")


def test_register_request_accept_and_reply(server, browser):
    alice, bob = Person(browser, server), Person(browser, server)
    code = alice.register("alice")
    assert len(code.replace("-", "")) == 24
    bob.register("bob")

    alice.open_chat("bob")
    alice.send("hola bob, soy alice")
    # Para Bob, alice es una desconocida: le llega como solicitud y no puede contestar hasta aceptar
    bob.row("alice").wait_for()
    assert "Solicitud" in bob.row("alice").inner_text()
    bob.row("alice").locator("button").click()
    bob.page.wait_for_selector("#request-bar:not([hidden])")
    assert bob.page.locator("#composer").is_hidden()
    bob.bubble("hola bob, soy alice").wait_for()
    bob.page.click("#request-bar button:has-text('Aceptar')")
    bob.page.wait_for_selector("#composer", state="visible")
    bob.send("hola alice")
    alice.bubble("hola alice").wait_for()
    # Y ya no es una solicitud
    assert "Solicitud" not in bob.row("alice").inner_text()
    alice.ctx.close(); bob.ctx.close()


def test_block_stops_messages(server, browser):
    dani, troll = Person(browser, server), Person(browser, server)
    dani.register("dani")
    troll.register("troll")
    troll.open_chat("dani")
    troll.send("primer mensaje")
    dani.row("troll").wait_for()
    dani.row("troll").locator("button").click()
    dani.page.click("#request-bar button:has-text('Bloquear')")
    dani.page.wait_for_selector("#request-bar button:has-text('Desbloquear')")
    troll.send("segundo mensaje")
    time.sleep(2)
    assert dani.bubble("segundo mensaje").count() == 0
    dani.ctx.close(); troll.ctx.close()


def test_forgotten_password_with_recovery_code(server, browser):
    eva = Person(browser, server)
    code = eva.register("eva")
    eva.ctx.close()
    # Otro dispositivo, sin la contraseña: con el código y una contraseña nueva
    new = Person(browser, server)
    p = new.page
    p.click("#to-recover")
    p.fill("#login-name", "eva")
    p.fill("#login-recovery", code.lower().replace("-", " "))
    p.fill("#login-pass", "Otra-Clave-Distinta-2025")
    p.fill("#login-pass2", "Otra-Clave-Distinta-2025")
    p.click("#login-btn")
    p.wait_for_selector("#app:not([hidden])")
    new.ctx.close()
    # Y la contraseña nueva ya vale para entrar desde un tercer dispositivo
    third = Person(browser, server)
    p = third.page
    p.fill("#login-name", "eva")
    p.fill("#login-pass", "Otra-Clave-Distinta-2025")
    p.click("#login-btn")
    p.wait_for_selector("#app:not([hidden])")
    third.ctx.close()


def test_wrong_recovery_code_is_rejected(server, browser):
    eve = Person(browser, server)
    p = eve.page
    p.click("#to-recover")
    p.fill("#login-name", "eva")
    p.fill("#login-recovery", "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ")
    p.fill("#login-pass", "Otra-Clave-Distinta-2025")
    p.fill("#login-pass2", "Otra-Clave-Distinta-2025")
    p.click("#login-btn")
    p.locator("#login-error", has_text="incorrecto").wait_for()  # (la CSP no deja evaluar texto como JS)
    eve.ctx.close()


def test_voice_call_between_contacts(server, browser):
    ana, luis = Person(browser, server), Person(browser, server)
    ana.register("ana")
    luis.register("luis")
    ana.open_chat("luis")
    ana.send("¿te llamo?")
    luis.row("ana").wait_for()
    luis.row("ana").locator("button").click()
    luis.page.click("#request-bar button:has-text('Aceptar')")
    luis.send("vale")
    ana.bubble("vale").wait_for()
    ana.page.click("#call-btn")
    luis.page.click("#call-buttons button[aria-label='Contestar']")
    # Los dos llegan a "en llamada" (WebRTC cifrado de punto a punto)
    for p in (ana.page, luis.page):
        p.wait_for_selector("[data-state='active'] #call-info")
    ana.page.click("#call-buttons button[aria-label='Colgar']")
    luis.page.wait_for_selector("#call-info", state="detached")
    ana.ctx.close(); luis.ctx.close()


def test_logout_without_service_worker(server, browser):
    """Como en la app de Windows (sin service worker): cerrar sesión no se puede quedar colgado."""
    ctx = browser.new_context(locale="es-ES", service_workers="block")
    page = ctx.new_page()
    page.on("dialog", lambda d: d.accept())
    page.goto(server)
    page.click("#to-register")
    page.fill("#login-name", "sinsw")
    page.fill("#login-pass", PASSWORD)
    page.fill("#login-pass2", PASSWORD)
    page.click("#login-btn")
    page.wait_for_selector(".recovery-code")
    page.check("#dlg-body input[type=checkbox]")
    page.click("#dlg-actions button:has-text('Listo')")
    page.click("#dlg-actions button:has-text('Ahora no')")
    page.wait_for_selector("#app:not([hidden])")
    page.click("#menu-btn")
    page.click("[data-action=logout]")
    page.wait_for_selector("#login:not([hidden])", timeout=8000)
    ctx.close()


def test_new_device_gets_chats_from_encrypted_server_backup(server, browser):
    """Al iniciar sesión en un dispositivo nuevo se recuperan solos los chats (copia cifrada del servidor)."""
    marta, juan = Person(browser, server), Person(browser, server)
    marta.register("marta")
    juan.register("juan")
    marta.open_chat("juan")
    marta.send("mensaje que debe volver")
    # Una foto: también tiene que volver (cifrada aparte en el servidor)
    marta.page.set_input_files("#file-input", str(ROOT / "web" / "icon-192.png"))
    marta.page.click("#dlg-actions button:has-text('Enviar')")
    marta.page.locator("#messages li.msg.media img").first.wait_for()
    juan.row("marta").wait_for()
    juan.row("marta").locator("button").click()
    juan.page.click("#request-bar button:has-text('Aceptar')")
    juan.send("y este también")
    marta.bubble("y este también").wait_for()
    # Fuerza la copia en el servidor (desactivar y activar el ajuste la sube al momento)
    p = marta.page
    p.click("#menu-btn")
    p.click("[data-action=options]")
    p.locator(".option-row", has_text="Copia de seguridad").click()
    sw = p.locator("#dlg-body label.switch", has_text="Copia automática").locator("input")
    sw.click()
    sw.click()
    p.locator("#dlg-body small", has_text="Última copia en el servidor").wait_for()
    marta.ctx.close()
    # Otro dispositivo, sin nada guardado: entra con la contraseña
    nuevo = Person(browser, server)
    q = nuevo.page
    q.fill("#login-name", "marta")
    q.fill("#login-pass", PASSWORD)
    q.click("#login-btn")
    q.wait_for_selector("#app:not([hidden])")
    nuevo.row("juan").wait_for(timeout=15000)
    nuevo.row("juan").locator("button").click()
    nuevo.bubble("mensaje que debe volver").wait_for()
    nuevo.bubble("y este también").wait_for()
    foto = nuevo.page.locator("#messages li.msg.media img").first
    foto.wait_for()
    nuevo.page.wait_for_function("(el) => el.naturalWidth > 0", arg=foto.element_handle(), timeout=20000)
    # Y sigue pudiendo hablar con juan (no es una solicitud)
    assert nuevo.page.locator("#request-bar").is_hidden()
    nuevo.ctx.close(); juan.ctx.close()


def test_contact_nickname_on_new_chat_and_from_menu(server, browser):
    eli, raul = Person(browser, server), Person(browser, server)
    eli.register("eli")
    raul.register("raul")
    eli.open_chat("raul", nickname="Mi primo")
    assert "Mi primo" in eli.page.inner_text("#peer-name")
    eli.send("hola")
    assert "Mi primo" in eli.row("raul").inner_text()
    # Desde los tres puntos del chat
    eli.page.click("#chat-menu-btn")
    eli.page.click(".msg-menu button:has-text('Cambiar nombre')")
    eli.page.fill("#dlg-body input", "Raúl del gym")
    eli.page.press("#dlg-body input", "Enter")
    eli.page.locator("#peer-name", has_text="Raúl del gym").wait_for()
    assert "Raúl del gym" in eli.row("raul").inner_text()
    eli.ctx.close(); raul.ctx.close()


def test_search_in_all_chats(server, browser):
    sara, tomas, unai = Person(browser, server), Person(browser, server), Person(browser, server)
    sara.register("sara")
    tomas.register("tomas")
    unai.register("unai")
    sara.open_chat("tomas")
    sara.send("La reunión es el jueves en la biblioteca")
    sara.page.fill("#new-chat-name", "unai")
    sara.page.press("#new-chat-name", "Enter")
    sara.page.click("#dlg-actions button:has-text('Omitir')")
    sara.send("Nos vemos en la BIBLIOTECA central")
    sara.send("otra cosa")
    sara.page.click("#search-all-btn")
    sara.page.fill("#dlg-body input", "biblioteca")  # sin tilde ni mayúsculas, encuentra las dos
    hits = sara.page.locator(".search-all-hit")
    hits.nth(1).wait_for()
    assert hits.count() == 2
    hits.filter(has_text="tomas").click()
    sara.page.locator("#peer-name", has_text="tomas").wait_for()
    for ctx in (sara, tomas, unai):
        ctx.ctx.close()
