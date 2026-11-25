// Actualizaciones automáticas de la app de Windows.
//
// Las versiones nuevas se publican en GitHub Releases. Antes de instalar nada, la app
// comprueba una firma Ed25519 hecha con una clave que solo tiene quien publica la app
// (privado/actualizaciones, fuera de git). Así, aunque alguien consiguiera subir un
// instalador a GitHub, la app lo rechazaría: no basta con el hash que da GitHub.
//
// La firma cubre "securechat-update-v1", la versión y el SHA-512 del instalador, así que
// tampoco se puede hacer pasar un instalador viejo (con fallos ya corregidos) por uno nuevo.

const { app, Notification, net, shell } = require("electron");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { signedMessage } = require("./actualizaciones-firma.js");

const REPO = "ZaperMaster/securechat";
const RELEASES = `https://github.com/${REPO}/releases`;
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArWiojcGlTAwnUP4tmTU3BMltZXxidG1jVq4YtluXX+k=
-----END PUBLIC KEY-----`;
const CHECK_EVERY = 6 * 3600 * 1000;

async function sha512File(file) {
  const h = crypto.createHash("sha512");
  for await (const chunk of fs.createReadStream(file)) h.update(chunk);
  return h.digest("hex");
}

/** null si la firma es buena; si no, el motivo (y la actualización se descarta). */
async function verifyInstaller(file, info) {
  try {
    const name = info.path || info.files?.[0]?.url;
    if (!name || !/^[\w.-]+\.exe$/.test(name)) return "nombre de instalador inesperado";
    const res = await net.fetch(`${RELEASES}/download/v${info.version}/${name}.sig`);
    if (!res.ok) return `sin firma (${res.status})`;
    const sig = Buffer.from((await res.text()).trim(), "base64");
    const ok = crypto.verify(null, signedMessage(info.version, await sha512File(file)), PUBLIC_KEY, sig);
    return ok ? null : "la firma no coincide";
  } catch (e) {
    return `no se pudo comprobar la firma: ${e.message}`;
  }
}

/**
 * Arranca las comprobaciones. `onReady(version)` se llama cuando hay una versión descargada
 * y verificada (para ofrecer reiniciar desde la bandeja).
 */
function setupUpdates({ onReady, L = (es) => es }) {
  if (!app.isPackaged) return;
  // Mac y Linux: sin certificado de Apple no se pueden actualizar solas (ni con nuestra firma, que
  // solo se comprueba en el instalador de Windows). Avisan de la versión nueva y abren la descarga.
  if (process.platform !== "win32") return avisarVersionNueva(L);
  const { autoUpdater } = require("electron-updater");
  const portable = !!process.env.PORTABLE_EXECUTABLE_DIR; // la portable no se puede actualizar sola
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.allowPrerelease = false;
  autoUpdater.allowDowngrade = false;
  autoUpdater.disableWebInstaller = true;
  autoUpdater.logger = null;

  let pending = null;
  // Se sustituye la comprobación de Authenticode (no tenemos certificado de pago) por la nuestra
  autoUpdater.verifySignature = (file) => verifyInstaller(file, pending);

  autoUpdater.on("update-available", (info) => {
    pending = info;
    if (portable) {
      const n = new Notification({ title: "SecureChat", body: L(`Hay una versión nueva (${info.version}). Pulsa para descargarla.`, `A new version (${info.version}) is available. Click to download it.`) });
      n.on("click", () => shell.openExternal(`${RELEASES}/latest`));
      n.show();
      return;
    }
    autoUpdater.downloadUpdate().catch(() => {});
  });
  autoUpdater.on("update-downloaded", (info) => {
    onReady(info.version, () => autoUpdater.quitAndInstall(false, true));
    new Notification({ title: "SecureChat", body: L(`Versión ${info.version} lista: se instalará al cerrar la app (o reinicia desde el icono de la bandeja).`,
      `Version ${info.version} is ready: it'll be installed when you quit the app (or restart from the tray icon).`) }).show();
  });
  autoUpdater.on("error", () => {}); // sin conexión, GitHub caído, firma mala…: se reintenta más tarde

  const check = () => autoUpdater.checkForUpdates().catch(() => {});
  setTimeout(check, 30 * 1000);
  setInterval(check, CHECK_EVERY);
}

/** Compara "1.2.3" con "1.10.0". */
function nuevaQue(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  return false;
}

function avisarVersionNueva(L) {
  let avisada = null;
  const check = async () => {
    try {
      const r = await net.fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } });
      if (!r.ok) return;
      const tag = String((await r.json()).tag_name || "").replace(/^v/, "");
      if (!/^\d+\.\d+\.\d+$/.test(tag) || !nuevaQue(tag, app.getVersion()) || avisada === tag) return;
      avisada = tag;
      const n = new Notification({ title: "SecureChat", body: L(`Hay una versión nueva (${tag}). Pulsa para descargarla.`, `A new version (${tag}) is available. Click to download it.`) });
      n.on("click", () => shell.openExternal(`${RELEASES}/latest`));
      n.show();
    } catch { /* sin conexión: se reintenta */ }
  };
  setTimeout(check, 30 * 1000);
  setInterval(check, CHECK_EVERY);
}

module.exports = { setupUpdates };
