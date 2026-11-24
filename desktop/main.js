// SecureChat para Windows (Electron).
//
// Seguridad:
//  * El código de la app (HTML, JS, CSS, libsodium) va DENTRO del programa. Aunque se abre
//    la dirección del servidor (para que cookies, almacenamiento y WebSocket sean "del
//    mismo sitio"), esas peticiones no salen a la red: se sirven desde los ficheros
//    empaquetados. Así un servidor comprometido no puede colar JavaScript que robe claves,
//    el punto débil de cualquier cifrado de extremo a extremo hecho en una web.
//  * Solo van a la red los datos: config.json, /keystore y el WebSocket (cifrado E2E).
//  * La ventana no tiene acceso a Node (sandbox + contextIsolation), no puede navegar a
//    otras webs (los enlaces se abren en el navegador) y solo tiene los permisos que
//    necesita (micrófono, cámara y notificaciones), y solo para el servidor de SecureChat.

const { app, BrowserWindow, Menu, Tray, nativeImage, net, session, shell } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const { setupUpdates } = require("./actualizaciones.js");

// En el programa instalado el servidor es fijo; SECURECHAT_URL solo sirve para probar en desarrollo
// (si no, un acceso directo manipulado podría llevar la app a un servidor falso).
const DEFAULT_SERVER = "https://securechat.dojo-massometer.ts.net";
const SERVER = ((!app.isPackaged && process.env.SECURECHAT_URL) || DEFAULT_SERVER).replace(/\/$/, "");
const ORIGIN = new URL(SERVER).origin;
const APP_DIR = path.join(__dirname, "app");
const ICON = path.join(__dirname, "icon.png");
const START_HIDDEN = process.argv.includes("--oculto");

// Mismas cabeceras de seguridad que pone el servidor
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; " +
  "img-src 'self' data: blob:; media-src blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".svg": "image/svg+xml",
  ".png": "image/png", ".ico": "image/x-icon", ".wasm": "application/wasm",
};
// Lo que SIEMPRE viene del servidor (datos, nunca código)
const FROM_NETWORK = new Set(["/config.json", "/keystore"]);

let win = null;
let tray = null;
let quitting = false;
let update = null; // {version, install}: actualización descargada y verificada
// Textos de la bandeja en español o inglés según el idioma de Windows
const L = (es, en) => (/^es/i.test(app.getLocale()) ? es : en);

// En el programa instalado no se permite abrir un puerto de depuración remota
// (permitiría a otro programa del equipo controlar la ventana y leer los mensajes).
if (app.isPackaged && process.argv.some((a) => /^--(remote-debugging|inspect)/.test(a))) {
  app.exit(1);
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => showWindow());
}

app.setAppUserModelId("es.securechat.desktop"); // notificaciones de Windows con el nombre de la app

/** Fichero empaquetado para esta ruta (o null si no es de la app). */
function bundledFile(pathname) {
  let p = decodeURIComponent(pathname);
  if (p === "/") p = "/index.html";
  const file = path.resolve(APP_DIR, "." + p);
  if (!file.startsWith(APP_DIR + path.sep)) return null; // nada de ../
  return fs.existsSync(file) && fs.statSync(file).isFile() ? file : null;
}

function setupNetwork() {
  const ses = session.defaultSession;

  // (https en uso normal; http solo para probar contra un servidor en este equipo)
  ses.protocol.handle(new URL(SERVER).protocol.replace(":", ""), async (request) => {
    const url = new URL(request.url);
    if (url.origin === ORIGIN && request.method === "GET" && !FROM_NETWORK.has(url.pathname)) {
      // El service worker no hace falta aquí (y cachearía cosas de la red): no existe
      if (url.pathname === "/sw.js") return new Response("", { status: 404 });
      const file = bundledFile(url.pathname);
      if (file) {
        return new Response(fs.readFileSync(file), {
          status: 200,
          headers: {
            "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
          },
        });
      }
      return new Response("404", { status: 404 });
    }
    // Datos (config.json, /keystore) y cualquier otra cosa: a la red, tal cual
    return net.fetch(request, { bypassCustomProtocolHandlers: true });
  });

  // Permisos: solo los necesarios y solo para el servidor de SecureChat
  const allowed = new Set(["media", "notifications", "clipboard-sanitized-write", "fullscreen"]);
  const fromApp = (url) => { try { return new URL(url).origin === ORIGIN; } catch { return false; } };
  ses.setPermissionRequestHandler((wc, permission, callback, details) => {
    callback(allowed.has(permission) && fromApp(details.requestingUrl || wc.getURL()));
  });
  ses.setPermissionCheckHandler((wc, permission, requestingOrigin) => allowed.has(permission) && requestingOrigin === ORIGIN);
}

// Sin barra de título de Windows: la app llega hasta arriba y los botones de minimizar,
// maximizar y cerrar se pintan encima con el color de fondo del tema (cambia con él).
const TITLEBAR_H = 34;
const TITLEBAR_CSS = `
  :root { --titlebar-h: ${TITLEBAR_H}px; }
  body::after { content: ""; position: fixed; top: 0; left: 0; right: 0; height: ${TITLEBAR_H}px;
    -webkit-app-region: drag; z-index: 2147483000; }
  dialog, .msg-menu, .app-menu, .call-screen button, input, button { -webkit-app-region: no-drag; }
  .app { height: calc(var(--app-h, 100vh) - ${TITLEBAR_H}px) !important; margin-top: ${TITLEBAR_H}px !important; }
  .login-card { padding-top: ${TITLEBAR_H + 8}px !important; }
`;

/** Color de los símbolos (−, □, ×) que se lee bien sobre el fondo. */
function symbolColorFor(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || "");
  if (!m) return "#888888";
  const n = parseInt(m[1], 16);
  const lum = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
  return lum > 0.55 ? "#1f2a24" : "#e8eee9";
}

function createWindow() {
  win = new BrowserWindow({
    width: 1200, height: 820, minWidth: 380, minHeight: 560,
    title: "SecureChat", icon: ICON, show: false, backgroundColor: "#e3f1e9", autoHideMenuBar: true,
    titleBarStyle: "hidden",
    titleBarOverlay: { color: "#00000000", symbolColor: symbolColorFor("#e3f1e9"), height: TITLEBAR_H },
    webPreferences: {
      sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true,
      allowRunningInsecureContent: false, spellcheck: true, devTools: !app.isPackaged,
    },
  });
  const wc = win.webContents;
  // Nada de abrir otras webs dentro de la app: los enlaces van al navegador
  const external = (url) => { if (/^https?:\/\//i.test(url)) shell.openExternal(url); };
  wc.setWindowOpenHandler(({ url }) => { external(url); return { action: "deny" }; });
  wc.on("will-navigate", (e, url) => { if (new URL(url).origin !== ORIGIN) { e.preventDefault(); external(url); } });
  wc.on("will-attach-webview", (e) => e.preventDefault());
  wc.on("dom-ready", () => wc.insertCSS(TITLEBAR_CSS).catch(() => {}));
  // Llamada entrante con la ventana escondida en la bandeja: la web pone "📞" en el título
  wc.on("page-title-updated", (_e, title) => {
    if (!title.startsWith("📞")) return;
    showWindow();
    win.flashFrame(true);
    win.setAlwaysOnTop(true);
    setTimeout(() => { if (!win.isDestroyed()) win.setAlwaysOnTop(false); }, 3000);
  });
  // La web pone en <meta name="theme-color"> el fondo del tema: la barra lo copia
  wc.on("did-change-theme-color", (_e, color) => {
    if (!color || !/^#[0-9a-f]{6}$/i.test(color)) return;
    // Transparente: debajo se ve el propio fondo de la app (con sus degradados); solo cambia el color de los símbolos
    try { win.setTitleBarOverlay({ color: "#00000000", symbolColor: symbolColorFor(color), height: TITLEBAR_H }); } catch { /* */ }
    win.setBackgroundColor(color);
  });

  // Se abre ocupando toda la pantalla (maximizada: la barra de tareas sigue a la vista).
  // Con --oculto (al iniciar Windows) espera en la bandeja hasta que la abras.
  win.once("ready-to-show", () => { if (!START_HIDDEN) { win.maximize(); win.show(); win.focus(); } });
  // Cerrar la ventana la esconde en la bandeja: así siguen llegando mensajes y llamadas
  win.on("close", (e) => {
    if (!quitting) { e.preventDefault(); win.hide(); }
  });
  win.loadURL(SERVER + "/");
}

let shownOnce = false;
function showWindow() {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  if (!shownOnce && !win.isVisible()) win.maximize();
  win.show();
  win.focus();
}
app.on("browser-window-focus", () => { shownOnce = true; });

function createTray() {
  tray = new Tray(nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 }));
  tray.setToolTip("SecureChat");
  const autostart = () => app.getLoginItemSettings().openAtLogin;
  const build = () => Menu.buildFromTemplate([
    { label: L("Abrir SecureChat", "Open SecureChat"), click: showWindow },
    ...(update ? [{ label: L(`Reiniciar para actualizar (${update.version})`, `Restart to update (${update.version})`), click: () => { quitting = true; update.install(); } }] : []),
    { type: "separator" },
    {
      label: L("Iniciar con Windows", "Start with Windows"), type: "checkbox", checked: autostart(),
      click: (item) => { app.setLoginItemSettings({ openAtLogin: item.checked, args: ["--oculto"] }); tray.setContextMenu(build()); },
    },
    { type: "separator" },
    { label: L("Salir", "Quit"), click: () => { quitting = true; app.quit(); } },
  ]);
  tray.setContextMenu(build());
  tray.on("click", showWindow);
  return () => tray.setContextMenu(build());
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null); // sin menú (ni atajos para abrir herramientas de desarrollo)
  setupNetwork();
  createWindow();
  const refreshTray = createTray();
  setupUpdates({ L, onReady: (version, install) => { update = { version, install }; refreshTray(); } });
});

app.on("before-quit", () => { quitting = true; });
app.on("window-all-closed", (e) => e.preventDefault()); // sigue en la bandeja
app.on("web-contents-created", (_e, contents) => {
  contents.on("will-navigate", (e, url) => { if (new URL(url).origin !== ORIGIN) e.preventDefault(); });
});
