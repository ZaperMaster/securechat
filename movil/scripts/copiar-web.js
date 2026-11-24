// Copia la web (../web) a www/ para meterla DENTRO del APK, igual que hace la app de Windows.
// Así un servidor comprometido no puede cambiar el código que cifra: del servidor solo llegan
// datos (config.json, /keystore y el WebSocket). Se le añade la dirección del servidor y una CSP.
const fs = require("node:fs");
const path = require("node:path");

const SERVER = (process.env.SECURECHAT_SERVER || "https://securechat.dojo-massometer.ts.net").replace(/\/$/, "");
const WS = SERVER.replace(/^http/, "ws");
const src = path.join(__dirname, "..", "..", "web");
const out = path.join(__dirname, "..", "www");

fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(src, out, {
  recursive: true,
  // Ni service worker (aquí no sirve) ni ficheros que solo usa la web
  filter: (f) => !/[\/](sw\.js|\.well-known)$/.test(f),
});
fs.writeFileSync(path.join(out, "js", "movil-config.js"),
  `// Generado por movil/scripts/copiar-web.js\nwindow.SC_SERVER = ${JSON.stringify(SERVER)};\n`);

const csp = `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' ${SERVER} ${WS}; ` +
  "img-src 'self' data: blob:; media-src 'self' blob:; base-uri 'none'; form-action 'none'";
const indexPath = path.join(out, "index.html");
let html = fs.readFileSync(indexPath, "utf8");
html = html.replace('<meta charset="utf-8">',
  `<meta charset="utf-8">\n  <meta http-equiv="Content-Security-Policy" content="${csp}">`);
html = html.replace('<script src="js/theme.js"></script>',
  '<script src="js/movil-config.js"></script>\n  <script src="js/theme.js"></script>');
if (!html.includes("movil-config.js")) throw new Error("no se pudo preparar index.html");
fs.writeFileSync(indexPath, html);
console.log(`web copiada a www/ (servidor: ${SERVER})`);
