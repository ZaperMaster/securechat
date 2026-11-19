// Pruebas de las sender keys de grupo (node --test tests/web)
import assert from "node:assert/strict";
import { test } from "node:test";
import { sodium } from "./setup.mjs";

const SK = await import("../../web/js/senderkeys.js");

/** Lo que tendría un miembro tras recibir la distribución ("skey") de alice. */
const receiverState = (key) => { const d = SK.distribution("grupo1", key); return { kid: d.kid, ck: d.ck, n: d.n, spk: d.spk, skipped: {} }; };

test("un mensaje cifrado una vez lo leen todos los miembros", () => {
  const key = SK.newSenderKey(["bob", "carol"]);
  const bob = receiverState(key), carol = receiverState(key);
  const p = SK.skEncrypt(key, "grupo1", "alice", "devA", "hola grupo");
  assert.equal(SK.skDecrypt(bob, "alice", p), "hola grupo");
  assert.equal(SK.skDecrypt(carol, "alice", p), "hola grupo");
  assert.ok(!JSON.stringify(p).includes("hola"));
});

test("cada mensaje usa una clave distinta y la cadena avanza", () => {
  const key = SK.newSenderKey(["bob"]);
  const bob = receiverState(key);
  const a = SK.skEncrypt(key, "grupo1", "alice", "devA", "uno");
  const b = SK.skEncrypt(key, "grupo1", "alice", "devA", "dos");
  assert.notEqual(a.ct, b.ct);
  assert.equal(key.n, 2);
  assert.equal(SK.skDecrypt(bob, "alice", a), "uno");
  assert.equal(SK.skDecrypt(bob, "alice", b), "dos");
});

test("se leen mensajes desordenados, pero no repetidos", () => {
  const key = SK.newSenderKey(["bob"]);
  const bob = receiverState(key);
  const msgs = ["a", "b", "c", "d"].map((t) => SK.skEncrypt(key, "grupo1", "alice", "devA", t));
  assert.equal(SK.skDecrypt(bob, "alice", msgs[3]), "d");
  assert.equal(SK.skDecrypt(bob, "alice", msgs[1]), "b");
  assert.equal(SK.skDecrypt(bob, "alice", msgs[0]), "a");
  assert.equal(SK.skDecrypt(bob, "alice", msgs[2]), "c");
  assert.throws(() => SK.skDecrypt(bob, "alice", msgs[1]), /repetido/);
});

test("un miembro no puede hacerse pasar por otro (firma)", () => {
  const key = SK.newSenderKey(["bob", "mallory"]);
  const bob = receiverState(key);
  const p = SK.skEncrypt(key, "grupo1", "alice", "devA", "texto real");
  // mallory conoce la cadena (es miembro) pero no la clave de firma de alice
  const fake = SK.newSenderKey(["bob"]);
  const forged = SK.skEncrypt({ ...fake, kid: key.kid, ck: SK.distribution("grupo1", key).ck, n: 0 }, "grupo1", "alice", "devA", "texto falso");
  assert.throws(() => SK.skDecrypt(receiverState(key), "alice", forged), /firma/);
  assert.equal(SK.skDecrypt(bob, "alice", p), "texto real");
});

test("no sirve cambiar el grupo, el autor ni manipular el texto", () => {
  const key = SK.newSenderKey(["bob"]);
  const p = SK.skEncrypt(key, "grupo1", "alice", "devA", "hola");
  assert.throws(() => SK.skDecrypt(receiverState(key), "alice", { ...p, g: "grupo2" }), /firma/);
  assert.throws(() => SK.skDecrypt(receiverState(key), "carol", p), /firma/);
  const ct = sodium.from_base64(p.ct, sodium.base64_variants.ORIGINAL);
  ct[0] ^= 1;
  assert.throws(() => SK.skDecrypt(receiverState(key), "alice", { ...p, ct: sodium.to_base64(ct, sodium.base64_variants.ORIGINAL) }));
});

test("al cambiar los miembros se rota la cadena (quien sale no lee lo nuevo)", () => {
  const key = SK.newSenderKey(["bob", "carol"]);
  assert.equal(SK.needsRotation(key, ["carol", "bob"]), false); // mismo grupo, otro orden
  assert.equal(SK.needsRotation(key, ["bob"]), true);           // carol ha salido
  const carol = receiverState(key);
  const next = SK.newSenderKey(["bob"]);
  const p = SK.skEncrypt(next, "grupo1", "alice", "devA", "carol ya no está");
  assert.throws(() => SK.skDecrypt(carol, "alice", p), /clave/);
});

test("la cadena también se rota por número de mensajes", () => {
  const key = SK.newSenderKey(["bob"]);
  key.n = SK.SK_MAX_MESSAGES;
  assert.equal(SK.needsRotation(key, ["bob"]), true);
});

test("las distribuciones mal formadas se rechazan", () => {
  const key = SK.newSenderKey(["bob"]);
  assert.equal(SK.validDistribution(SK.distribution("g", key)), true);
  assert.equal(SK.validDistribution({ ...SK.distribution("g", key), ck: "corta" }), false);
  assert.equal(SK.validDistribution({ ...SK.distribution("g", key), n: -1 }), false);
});
