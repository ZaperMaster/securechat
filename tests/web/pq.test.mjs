// PQXDH (X3DH + ML-KEM-768) y código de recuperación (se ejecutan con: node --test tests/web)
import assert from "node:assert/strict";
import { test } from "node:test";
import { P, sodium } from "./setup.mjs";

const R = await import("../../web/js/ratchet.js");

function device(name) {
  const seed = P.newIdentitySeed();
  const kp = sodium.crypto_sign_seed_keypair(seed);
  const identity = { seed, publicKey: kp.publicKey, privateKey: kp.privateKey };
  return { name, identity, keys: new R.DeviceKeys(name, identity, null) };
}

/** Lo que entregaría el servidor: la prekey firmada, una OPK y (si la hay) la poscuántica. */
function bundleOf(d, { pq = true } = {}) {
  const up = d.keys.uploadMessage(0);
  const b = { spk: up.spk, sig: up.sig, created: up.created, opk: up.opks[0] };
  if (pq) Object.assign(b, { kem: up.kem, kem_sig: up.kem_sig, kem_created: up.kem_created });
  return b;
}

test("PQXDH: la sesión mezcla ML-KEM y los dos lados lo saben", () => {
  const a = device("alice"), b = device("bob");
  const r = R.initiate("alice", a.keys.device, a.identity, "bob", b.keys.device, b.identity.publicKey, bundleOf(b), null);
  a.keys.pushNew("bob", b.keys.device, r);
  const msg = R.encryptFor(a.keys.device, r, "hola poscuántico");
  assert.ok(msg.x3dh.kem?.ct, "el primer mensaje lleva el cifrado ML-KEM");
  assert.equal(sodium.from_base64(msg.x3dh.kem.ct, sodium.base64_variants.ORIGINAL).length, 1088);
  const got = R.decryptFrom("bob", b.keys, "alice", msg, null);
  assert.equal(got.text, "hola poscuántico");
  assert.ok(a.keys.postQuantum("bob") && b.keys.postQuantum("alice"));
  // La respuesta (ratchet DH) sigue funcionando
  const back = R.encryptFor(b.keys.device, b.keys.session("alice", a.keys.device), "recibido");
  assert.equal(R.decryptFrom("alice", a.keys, "bob", back, null).text, "recibido");
});

test("sin prekey poscuántica (cliente de terminal) se usa X3DH clásico", () => {
  const a = device("alice"), b = device("bob");
  const r = R.initiate("alice", a.keys.device, a.identity, "bob", b.keys.device, b.identity.publicKey, bundleOf(b, { pq: false }), null);
  const msg = R.encryptFor(a.keys.device, r, "clásico");
  assert.equal(msg.x3dh.kem, undefined);
  assert.equal(R.decryptFrom("bob", b.keys, "alice", msg, null).text, "clásico");
  assert.ok(!b.keys.postQuantum("alice"));
});

test("una prekey poscuántica con firma falsa se rechaza", () => {
  const a = device("alice"), b = device("bob"), mallory = device("mallory");
  const bundle = bundleOf(b);
  bundle.kem = bundleOf(mallory).kem; // el servidor intenta colar la suya
  assert.throws(() => R.initiate("alice", a.keys.device, a.identity, "bob", b.keys.device, b.identity.publicKey, bundle, null),
    /firma inválida/);
});

test("si el cifrado ML-KEM se manipula, el mensaje no se descifra", () => {
  const a = device("alice"), b = device("bob");
  const r = R.initiate("alice", a.keys.device, a.identity, "bob", b.keys.device, b.identity.publicKey, bundleOf(b), null);
  const msg = R.encryptFor(a.keys.device, r, "secreto");
  const ct = sodium.from_base64(msg.x3dh.kem.ct, sodium.base64_variants.ORIGINAL);
  ct[10] ^= 1;
  msg.x3dh.kem.ct = sodium.to_base64(ct, sodium.base64_variants.ORIGINAL);
  assert.throws(() => R.decryptFrom("bob", b.keys, "alice", msg, null));
});

// ------------------------------------------------------- código de recuperación

test("el código de recuperación abre la cuenta y uno incorrecto no", () => {
  const code = P.newRecoveryCode();
  assert.match(code, /^([A-HJ-NP-Z2-9]{4}-){5}[A-HJ-NP-Z2-9]{4}$/);
  const seed = P.newIdentitySeed();
  const blob = P.recoveryBlob(seed, code);
  assert.deepEqual(Object.keys(blob).sort(), ["ciphertext", "public_key", "version"]);
  // Se acepta en minúsculas, sin guiones o con espacios
  assert.deepEqual(P.openRecovery(blob, code.toLowerCase().replace(/-/g, " ")), seed);
  assert.throws(() => P.openRecovery(blob, P.newRecoveryCode()), /incorrecto/);
  assert.equal(P.normalizeRecoveryCode("demasiado-corto"), null);
  // La prueba para el servidor no sirve para abrir la copia
  assert.notDeepEqual(P.recoveryAuth(code), sodium.crypto_generichash(32, code, null));
  assert.deepEqual(P.recoveryAuth(code), P.recoveryAuth(code.replace(/-/g, "")));
});
