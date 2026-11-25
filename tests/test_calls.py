"""Llamadas en navegadores de verdad, en todas las combinaciones que se usan:

* "web": la web abierta en el navegador. La app de Windows lleva exactamente el mismo código y
  se abre en el mismo origen, así que estas pruebas valen también para ella.
* "app": el código tal como va dentro del APK de Android (otro origen, la dirección del servidor
  fija y sin service worker). La pantalla de llamada NATIVA de Android no se puede probar aquí.

Casos: todas las parejas (quién llama y quién contesta), rechazar, colgar antes de que contesten,
dos dispositivos de la misma cuenta (contesta uno y el otro deja de sonar), comunicando y vídeo.
"""

import functools
import http.server
import re
import shutil
import threading
import time

import pytest

from test_browser import PASSWORD, browser, free_port, server, server_db_path, sync_api  # noqa: F401 (fixtures)

CORS = {"access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "GET"}
_n = iter(range(10_000))


def uniq(base):
    return f"{base}{next(_n)}"


ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def app_url(server, tmp_path_factory):
    """La web empaquetada EXACTAMENTE como en el APK (movil/scripts/copiar-web.js), servida aparte.
    Necesita las dependencias de movil/ (npm ci): ahí viene la parte JavaScript de Capacitor."""
    if not (ROOT_DIR / "movil" / "node_modules" / "@capacitor" / "core").is_dir():
        pytest.skip("falta npm ci en movil/ (parte JavaScript de Capacitor)")
    www = tmp_path_factory.mktemp("apk") / "www"
    import os
    import subprocess
    subprocess.run(["node", str(ROOT_DIR / "movil" / "scripts" / "copiar-web.js")], check=True, capture_output=True,
                   env={**os.environ, "SECURECHAT_SERVER": server, "SECURECHAT_WWW": str(www)})
    port = free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(www))
    handler.log_message = lambda *a: None
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/index.html"
    httpd.shutdown()


# Puente nativo de Capacitor simulado: lo que inyecta Android en la página. Los complementos
# responden como en un móvil y apuntan cada llamada en window.__nativo; los eventos nativos
# (token de Firebase, botones de la pantalla de llamada) se lanzan con window.__evento().
NATIVE_BRIDGE = """
window.__nativo = []; window.__oyentes = {};
window.androidBridge = { postMessage() {} };
const M = (n, extra = []) => ({ name: n, methods: [...extra.map((m) => ({ name: m, rtype: "promise" })), { name: "addListener", rtype: "callback" }, { name: "removeListener", rtype: "promise" }] });
window.Capacitor = {
  Plugins: {},
  PluginHeaders: [
    M("PushNotifications", ["checkPermissions", "requestPermissions", "register", "unregister", "createChannel"]),
    M("Llamadas", ["pendiente", "quitar", "fin", "minimizar"]),
    M("Huella", ["disponible", "verificar"]),
    M("Filesystem", ["writeFile"]),
    M("Share", ["share"]),
  ],
  nativePromise(plugin, method, opts) {
    window.__nativo.push(plugin + "." + method);
    if (plugin === "PushNotifications" && method === "checkPermissions") return Promise.resolve({ receive: "granted" });
    if (plugin === "PushNotifications" && method === "register") {
      setTimeout(() => window.__evento("PushNotifications", "registration", { value: "tokenFirebaseDePrueba1234567890" }), 50);
    }
    if (plugin === "Huella" && method === "disponible") return Promise.resolve({ disponible: true });
    if (plugin === "Huella" && method === "verificar") return Promise.resolve({ ok: true });
    if (plugin === "Filesystem") return Promise.resolve({ uri: "file:///cache/x" });
    return Promise.resolve({});
  },
  nativeCallback(plugin, method, opts, cb) {
    window.__nativo.push(plugin + ".addListener:" + opts.eventName);
    window.__oyentes[plugin + ":" + opts.eventName] = cb;
    return Promise.resolve("oyente");
  },
};
window.__evento = (plugin, name, data) => window.__oyentes[plugin + ":" + name]?.(data);
"""


class Device:
    """Un dispositivo: la web ("web") o la app de Android ("app")."""

    def __init__(self, browser, server, app_url, kind):
        self.kind = kind
        self.ctx = browser.new_context(locale="es-ES", permissions=["microphone", "camera"])
        if kind == "app":
            # Como en Capacitor: es una app nativa y sus peticiones al servidor no tienen CORS
            self.ctx.add_init_script(NATIVE_BRIDGE)

            def handle(route):
                if route.request.method == "OPTIONS":
                    return route.fulfill(status=204, headers=CORS)
                r = route.fetch()
                route.fulfill(response=r, headers={**r.headers, **CORS})
            self.ctx.route(re.compile("^" + re.escape(server) + "/"), handle)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(20000)
        self.page.on("dialog", lambda d: d.accept())
        self.page.goto(app_url if kind == "app" else server)
        self.page.wait_for_selector("#login-form")

    def register(self, name):
        p = self.page
        p.click("#to-register")
        p.fill("#login-name", name)
        p.fill("#login-pass", PASSWORD)
        p.fill("#login-pass2", PASSWORD)
        p.click("#login-btn")
        p.wait_for_selector(".recovery-code")
        p.check("#dlg-body input[type=checkbox]")
        p.click("#dlg-actions button:has-text('Listo')")
        p.click("#dlg-actions button:has-text('Ahora no')")
        p.wait_for_selector("#app:not([hidden])")
        return self

    def login(self, name):
        p = self.page
        p.fill("#login-name", name)
        p.fill("#login-pass", PASSWORD)
        p.click("#login-btn")
        p.wait_for_selector("#app:not([hidden])")
        return self

    def chat_with(self, peer):
        self.page.fill("#new-chat-name", peer)
        self.page.press("#new-chat-name", "Enter")
        self.page.wait_for_selector("#peer-name", state="visible")
        self.page.locator("#dlg-actions button:has-text('Omitir')").click(timeout=5000)

    def open(self, peer):
        self.page.locator(f"#contacts li[data-conv='{peer}'] button").click()

    def say(self, text):
        self.page.fill("#text", text)
        self.page.press("#text", "Enter")

    def sees(self, text, timeout=15000):
        self.page.locator("#messages li", has_text=text).first.wait_for(timeout=timeout)

    def close_dialog(self):
        self.page.evaluate("() => document.querySelector('#dialog')?.open && document.querySelector('#dialog').close()")

    # ------------------------------------------------------------ llamada
    def call(self, video=False):
        self.close_dialog()
        self.page.click("#video-btn" if video else "#call-btn")
        self.page.wait_for_selector("#call-screen")

    def rings(self, timeout=15000):
        self.page.wait_for_selector("#call-buttons button[aria-label='Contestar']", timeout=timeout)

    def answer(self):
        self.page.click("#call-buttons button[aria-label='Contestar']")

    def reject(self):
        self.page.click("#call-buttons button[aria-label='Rechazar']")

    def hang_up(self):
        self.page.click("#call-buttons button[aria-label='Colgar']")

    def in_call(self, timeout=20000):
        self.page.wait_for_selector("#call-screen[data-state='active']", timeout=timeout)

    def no_call(self, timeout=10000):
        self.page.wait_for_selector("#call-screen", state="detached", timeout=timeout)

    def status(self):
        return self.page.evaluate("() => document.querySelector('#call-screen')?.dataset.state || 'sin llamada'")


def friends(browser, server, app_url, kind_a, kind_b):
    na, nb = uniq("ana"), uniq("beto")
    a = Device(browser, server, app_url, kind_a).register(na)
    b = Device(browser, server, app_url, kind_b).register(nb)
    a.name, b.name = na, nb
    a.chat_with(nb)
    a.say("hola")
    b.open(na)
    b.page.click("#request-bar button:has-text('Aceptar')")
    b.say("hola!")
    a.sees("hola!")
    return a, b


def close(*devices):
    for d in devices:
        d.ctx.close()


@pytest.mark.parametrize("kind_a,kind_b", [("web", "app"), ("app", "web"), ("app", "app"), ("web", "web")])
def test_call_answer_and_hang_up_every_pair(browser, server, app_url, kind_a, kind_b):
    a, b = friends(browser, server, app_url, kind_a, kind_b)
    a.call()
    b.rings()
    b.answer()
    a.in_call()
    b.in_call()
    a.hang_up()
    a.no_call()
    b.no_call()  # al colgar uno, al otro se le quita la llamada
    # Y al revés: llama el otro y cuelga quien contesta
    b.open(a.name)
    b.call()
    a.rings()
    a.answer()
    a.in_call()
    b.in_call()
    a.hang_up()
    b.no_call()
    close(a, b)


@pytest.mark.parametrize("kind_a,kind_b", [("web", "app"), ("app", "web")])
def test_reject_shows_call_rejected_to_the_caller(browser, server, app_url, kind_a, kind_b):
    a, b = friends(browser, server, app_url, kind_a, kind_b)
    a.call()
    b.rings()
    b.reject()
    a.no_call()
    a.sees("Llamada rechazada")
    b.no_call()
    close(a, b)


def test_caller_cancels_before_answer(browser, server, app_url):
    a, b = friends(browser, server, app_url, "web", "app")
    a.call()
    b.rings()
    a.hang_up()
    b.no_call()
    b.sees("Llamada perdida")
    a.sees("Llamada cancelada")
    close(a, b)


def two_devices(browser, server, app_url):
    """Beto con la web (PC) y la app (móvil), y Ana que les llama."""
    a, b1 = friends(browser, server, app_url, "web", "web")
    b2 = Device(browser, server, app_url, "app").login(b1.name)
    # El PC le pasa los chats al móvil nuevo (si no, Ana sería una desconocida para el móvil)
    b1.page.locator("#dlg-actions button:has-text('Enviar mis chats')").click(timeout=20000)
    b2.page.locator(f"#contacts li[data-conv='{a.name}']").wait_for(timeout=20000)
    b2.close_dialog()
    return a, b1, b2


def test_two_devices_whoever_answers_first_keeps_the_call(browser, server, app_url):
    a, b1, b2 = two_devices(browser, server, app_url)
    # Contesta el móvil: el PC deja de sonar
    a.call()
    b1.rings()
    b2.rings()
    b2.answer()
    b2.in_call()
    a.in_call()
    b1.no_call()
    a.hang_up()
    b2.no_call()
    time.sleep(1)
    # Ahora contesta el PC: el móvil deja de sonar
    a.call()
    b1.rings()
    b2.rings()
    b1.answer()
    b1.in_call()
    a.in_call()
    b2.no_call()
    a.hang_up()
    b1.no_call()
    close(a, b1, b2)


def test_two_devices_reject_on_one_stops_the_other(browser, server, app_url):
    a, b1, b2 = two_devices(browser, server, app_url)
    a.call()
    b1.rings()
    b2.rings()
    b2.reject()
    a.no_call()
    a.sees("Llamada rechazada")
    b1.no_call()  # el otro dispositivo deja de sonar
    close(a, b1, b2)


@pytest.mark.parametrize("kind_a,kind_b", [("web", "app"), ("app", "web")])
def test_video_call(browser, server, app_url, kind_a, kind_b):
    a, b = friends(browser, server, app_url, kind_a, kind_b)
    a.call(video=True)
    b.rings()
    b.answer()
    a.in_call()
    b.in_call()
    assert b.page.evaluate("() => document.querySelector('#call-screen').dataset.video") == "1"
    b.hang_up()
    a.no_call()
    close(a, b)


def test_busy_when_already_in_a_call(browser, server, app_url):
    a, b = friends(browser, server, app_url, "web", "app")
    nc = uniq("carla")
    c = Device(browser, server, app_url, "web").register(nc)
    c.chat_with(b.name)
    c.say("hola beto")
    b.open(nc)
    b.page.click("#request-bar button:has-text('Aceptar')")
    b.say("hola carla")
    c.sees("hola carla")
    a.call()
    b.rings()
    b.answer()
    b.in_call()
    c.call()
    c.no_call(timeout=15000)
    c.sees("está en otra llamada")
    assert b.status() == "active"  # a Beto no le corta la llamada que tiene
    a.hang_up()
    close(a, b, c)


def test_group_call_web_and_app(browser, server, app_url):
    """Llamada de grupo: Ana (web) llama al grupo; Beto (app) y Carla (web) suenan y se unen."""
    a, b = friends(browser, server, app_url, "web", "app")
    nc = uniq("carla")
    c = Device(browser, server, app_url, "web").register(nc)
    c.name = nc
    a.page.fill("#new-chat-name", nc)
    a.page.press("#new-chat-name", "Enter")
    a.page.click("#dlg-actions button:has-text('Omitir')")
    a.say("hola carla")
    c.open(a.name)
    c.page.click("#request-bar button:has-text('Aceptar')")
    c.say("hola ana")
    a.sees("hola ana")
    # Ana crea el grupo con los dos
    a.close_dialog()
    a.page.click("#menu-btn")
    a.page.click("[data-action=group]")
    a.page.fill("#dlg-body input[placeholder='Amigos de clase']", "Llamada de prueba")
    for n in (b.name, nc):
        a.page.locator(".pick-row", has_text=n).locator("input").check()
    a.page.click("#dlg-actions button:has-text('Crear grupo')")
    for d in (b, c):
        d.page.locator("#contacts li", has_text="Llamada de prueba").first.wait_for(timeout=20000)
    a.page.locator("#contacts li", has_text="Llamada de prueba").first.locator("button").click()
    a.page.click("#call-btn")
    for d in (b, c):
        d.page.wait_for_selector("#call-buttons button[aria-label='Unirme']", timeout=20000)
    b.page.click("#call-buttons button[aria-label='Unirme']")
    c.page.click("#call-buttons button[aria-label='Unirme']")
    for d in (a, b, c):
        d.page.wait_for_selector("#call-screen[data-state='active']", timeout=30000)
    a.page.click("#call-buttons button[aria-label='Colgar']")
    close(a, b, c)


def test_app_uses_native_plugins(browser, server, app_url):
    """El APK tiene que usar de verdad sus complementos nativos (antes no los veía y no había avisos)."""
    a, b = friends(browser, server, app_url, "web", "app")
    calls = b.page.evaluate("() => window.__nativo")
    # Se apunta a los avisos de Firebase (canales, permiso, registro) y escucha la pantalla de llamada
    for c in ("PushNotifications.createChannel", "PushNotifications.register",
              "PushNotifications.addListener:registration", "Llamadas.pendiente", "Llamadas.addListener:llamada"):
        assert c in calls, f"falta {c}: {calls}"
    # El servidor tiene el token de Firebase de este móvil
    import sqlite3
    import json as _json
    db = sqlite3.connect(server_db_path(server))
    row = db.execute("SELECT data FROM accounts WHERE canon = ?", (b.name.lower(),)).fetchone()
    assert any(s.get("fcm") == "tokenFirebaseDePrueba1234567890" for s in _json.loads(row[0])["push"])
    close(a, b)


def test_answer_from_native_call_screen(browser, server, app_url):
    """Contestar en la pantalla de llamada de Android (evento nativo) descuelga la llamada en la app."""
    a, b = friends(browser, server, app_url, "web", "app")
    a.call()
    b.rings()
    b.page.evaluate("() => window.__evento('Llamadas', 'llamada', { accion: 'contestar' })")
    b.in_call()
    a.in_call()
    a.hang_up()
    b.no_call()
    # Y Rechazar: a quien llama le sale «Llamada rechazada» y la app vuelve a segundo plano
    a.call()
    b.rings()
    b.page.evaluate("() => window.__evento('Llamadas', 'llamada', { accion: 'rechazar' })")
    a.no_call()
    a.sees("Llamada rechazada")
    assert "Llamadas.minimizar" in b.page.evaluate("() => window.__nativo")
    close(a, b)
