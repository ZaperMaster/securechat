// Ejecuta el código JS de la web en Node para probar la interoperabilidad con Python.
// Lo invoca tests/test_web_interop.py; no hace falta ejecutarlo a mano.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const vendor = new URL("../web/vendor/", import.meta.url);
// Cargamos libsodium.js tal y como lo haría el navegador (scripts globales).
// `exports` indefinido fuerza la rama del navegador del UMD; `require` y `__dirname`
// los usa el runtime de Emscripten al detectar Node.
const req = createRequire(new URL("x.js", vendor));
const dir = fileURLToPath(vendor);
for (const f of ["libsodium-sumo.js", "libsodium-wrappers.js"]) {
  const fn = vm.runInThisContext(`(function(exports, module, define, require, __dirname){${readFileSync(new URL(f, vendor), "utf8")}\n})`);
  fn.call(globalThis, undefined, undefined, undefined, req, dir);
}
const P = await import("../web/js/protocol.js");
const { ChatClient, Contacts } = await import("../web/js/client.js");
await P.ready(globalThis.sodium);

const [mode, ...args] = process.argv.slice(2);
const stdin = () => readFileSync(0, "utf8");
const out = (x) => process.stdout.write(typeof x === "string" ? x : JSON.stringify(x));

const fast = [globalThis.sodium.crypto_pwhash_OPSLIMIT_MIN, globalThis.sodium.crypto_pwhash_MEMLIMIT_MIN];

if (mode === "keystore") {
  const seed = P.newIdentitySeed();
  out(P.saveIdentity(seed, args[0], ...fast));
} else if (mode === "loadkey") {
  out(P.b64e(P.loadIdentity(JSON.parse(stdin()), args[0]).publicKey));
} else if (mode === "safety") {
  out(P.safetyNumber(args[0], P.b64d(args[1]), args[2], P.b64d(args[3])) + "\n" + P.fingerprint(P.b64d(args[1])));
} else if (mode === "kdf") {
  out(P.b64e(P.kdf(P.b64d(args[0]), args[1], P.b64d(args[2]))));
} else if (mode === "chat" || mode === "listen" || mode === "sealed") {
  const [url, name, peer] = args;
  const seed = P.newIdentitySeed();
  const kp = globalThis.sodium.crypto_sign_seed_keypair(seed);
  const identity = { seed, publicKey: kp.publicKey, privateKey: kp.privateKey };
  let client;
  const finish = (code) => { client.close(); setTimeout(() => process.exit(code), 50); };
  client = new ChatClient(name, identity, new Contacts(), (ev) => {
    if (ev.kind !== "message") return;
    if (ev.content.t !== "text") { out(JSON.stringify({ t: ev.content.t, mime: ev.content.mime, len: ev.content.data?.length })); return finish(0); }
    if (mode === "listen") { client.sendText(ev.peer, `eco: ${ev.text}`); setTimeout(() => finish(0), 300); }
    else { out(ev.text); finish(0); }
  });
  setTimeout(() => { process.stderr.write("timeout"); process.exit(2); }, 15000);
  await client.connect(url);
  process.stderr.write("ready\n");
  if (mode === "chat") await client.sendText(peer, "hola desde la web ñ😀");
  if (mode === "sealed") {
    await client.sendSealed(await client.resolve(peer), JSON.stringify({ t: "text", body: "sobre desde la web" }));
    finish(0);
  }
}
