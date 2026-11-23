// Copia la web (web/) dentro de la app de escritorio (app/) y el icono.
// El código de la app va empaquetado: no se descarga del servidor.
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..", "..");
const src = path.join(root, "web");
const dst = path.resolve(__dirname, "..", "app");

fs.rmSync(dst, { recursive: true, force: true });
fs.cpSync(src, dst, { recursive: true, filter: (p) => !p.includes(`${path.sep}.well-known`) });
fs.copyFileSync(path.join(src, "icon-512.png"), path.resolve(__dirname, "..", "icon.png"));
console.log("web copiada en", dst);
