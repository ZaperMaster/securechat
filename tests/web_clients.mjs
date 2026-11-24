// Clientes web reales (el mismo client.js del navegador) contra un servidor de prueba.
// Lo invoca tests/test_web_e2e.py con la dirección del servidor; escribe un JSON con lo ocurrido.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const vendor = new URL("../web/vendor/", import.meta.url);
const req = createRequire(new URL("x.js", vendor));
for (const f of ["libsodium-sumo.js", "libsodium-wrappers.js"]) {
  const fn = vm.runInThisContext(`(function(exports, module, define, require, __dirname){${readFileSync(new URL(f, vendor), "utf8")}\n})`);
  fn.call(globalThis, undefined, undefined, undefined, req, fileURLToPath(vendor));
}
const P = await import("../web/js/protocol.js");
const { ChatClient, Contacts } = await import("../web/js/client.js");
await P.ready(globalThis.sodium);

const [scenario, url] = process.argv.slice(2);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
setTimeout(() => { process.stderr.write("timeout\n"); process.exit(2); }, 25000);

async function user(name) {
  const seed = P.newIdentitySeed();
  const kp = globalThis.sodium.crypto_sign_seed_keypair(seed);
  const inbox = [];
  const c = new ChatClient(name, { seed, publicKey: kp.publicKey, privateKey: kp.privateKey }, new Contacts(), (ev) => {
    if (ev.kind === "message") inbox.push(ev.text);
  });
  await c.connect(url);
  c.inbox = inbox;
  return c;
}

async function until(fn, ms = 4000) {
  for (let t = 0; t < ms; t += 50) { if (fn()) return true; await wait(50); }
  return false;
}

const log = {};
if (scenario === "sealed") {
  const alice = await user("alice"), bob = await user("bob");
  await until(() => alice.myAk && bob.myAk);
  log.aliceHasAk = !!alice.myAk;
  // 1) Bob no conoce la clave de entrega de Alice: el primero va identificado
  await bob.sendText("alice", "hola 1");
  await until(() => alice.inbox.includes("hola 1"));
  log.bobKnowsAliceAk = !!bob.contacts.get("alice")?.ak; // aún no
  // 2) Alice responde: ya tiene la de Bob (venía dentro del mensaje) y él recibe la suya
  await alice.sendText("bob", "hola 2");
  await until(() => bob.inbox.includes("hola 2"));
  log.aliceKnowsBobAk = !!alice.contacts.get("bob")?.ak;
  log.bobKnowsAliceAkAfter = !!bob.contacts.get("alice")?.ak;
  // 3) Ahora Bob ya escribe con remitente oculto
  await bob.sendText("alice", "hola 3");
  await until(() => alice.inbox.includes("hola 3"));
  // 4) Alice bloquea a Bob: su clave de entrega cambia y el servidor descarta lo que mande identificado
  await alice.setBlocked("bob", true);
  log.epochAfterBlock = alice.akEpoch;
  const st = await bob.sendText("alice", "hola 4");
  log.bobStatusWhenBlocked = st.status;
  await wait(600);
  log.bobAkDroppedAfterBlock = !bob.contacts.get("alice")?.ak;
  // 5) Desbloquea: vuelve a recibir
  await alice.setBlocked("bob", false);
  await bob.sendText("alice", "hola 5");
  await until(() => alice.inbox.includes("hola 5"));
  log.aliceInbox = alice.inbox;
  log.bobInbox = bob.inbox;
  alice.close(); bob.close();
} else if (scenario === "group") {
  const alice = await user("alice"), bob = await user("bob"), carol = await user("carol");
  await until(() => alice.myAk && bob.myAk && carol.myAk);
  // Se conocen: así cada uno tiene la clave de entrega de los demás
  for (const [a, b] of [[alice, bob], [alice, carol], [bob, carol]]) {
    await a.sendText(b.name, `hola ${b.name}`);
    await until(() => b.inbox.includes(`hola ${b.name}`));
    await b.sendText(a.name, `hola ${a.name}`);
    await until(() => a.inbox.includes(`hola ${a.name}`));
  }
  const g = "grupoPrueba01";
  await alice.sendGroup(g, ["bob", "carol"], { t: "text", body: "hola grupo", mid: "mensajeGrupo01", g });
  await until(() => bob.inbox.includes("hola grupo") && carol.inbox.includes("hola grupo"));
  await alice.sendGroup(g, ["bob", "carol"], { t: "text", body: "segundo", mid: "mensajeGrupo02", g });
  await until(() => bob.inbox.includes("segundo") && carol.inbox.includes("segundo"));
  log.bobInbox = bob.inbox;
  log.carolInbox = carol.inbox;
  alice.close(); bob.close(); carol.close();
} else if (scenario === "pq") {
  const alice = await user("alice"), bob = await user("bob");
  await wait(300); // que suban sus prekeys
  await alice.sendText("bob", "cuántico");
  await until(() => bob.inbox.includes("cuántico"));
  log.alicePq = alice.keys.postQuantum("bob");
  log.bobPq = bob.keys.postQuantum("alice");
  log.bobInbox = bob.inbox;
  alice.close(); bob.close();
}
process.stdout.write(JSON.stringify(log));
setTimeout(() => process.exit(0), 100);
