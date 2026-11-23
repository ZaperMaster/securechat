// Firma el instalador recién compilado para que las apps instaladas acepten la actualización.
// Usa la clave privada de privado/actualizaciones (no está en git). Escribe dist/<instalador>.exe.sig,
// que hay que subir a la release de GitHub junto con el instalador, su .blockmap y latest.yml.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { signedMessage } = require("../actualizaciones-firma.js");

const KEY = process.env.SECURECHAT_UPDATE_KEY || path.join(__dirname, "..", "..", "privado", "actualizaciones", "clave-privada.pem");
const { version } = require("../package.json");
const file = path.join(__dirname, "..", "dist", `SecureChat-Setup-${version}.exe`);

if (!fs.existsSync(KEY)) {
  console.warn(`Sin clave de firma (${KEY}): el instalador NO se podrá usar como actualización automática.`);
  process.exit(0);
}
const sha = crypto.createHash("sha512").update(fs.readFileSync(file)).digest("hex");
const sig = crypto.sign(null, signedMessage(version, sha), fs.readFileSync(KEY, "utf8"));
fs.writeFileSync(`${file}.sig`, sig.toString("base64") + "\n");
console.log(`firmado: ${path.basename(file)}.sig`);
