// Carga libsodium.js en Node igual que en el navegador (scripts globales) para probar
// el código de la web sin abrir un navegador.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const vendor = new URL("../../web/vendor/", import.meta.url);
if (!globalThis.sodium) {
  const req = createRequire(new URL("x.js", vendor));
  const dir = fileURLToPath(vendor);
  for (const f of ["libsodium-sumo.js", "libsodium-wrappers.js"]) {
    const fn = vm.runInThisContext(`(function(exports, module, define, require, __dirname){${readFileSync(new URL(f, vendor), "utf8")}\n})`);
    fn.call(globalThis, undefined, undefined, undefined, req, dir);
  }
}

export const P = await import("../../web/js/protocol.js");
await P.ready(globalThis.sodium);
export const sodium = globalThis.sodium;
// Argon2id rápido para las pruebas (en la app se usan parámetros fuertes)
export const FAST = [sodium.crypto_pwhash_OPSLIMIT_MIN, sodium.crypto_pwhash_MEMLIMIT_MIN];
