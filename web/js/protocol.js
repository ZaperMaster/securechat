// Port a JavaScript de securechat/crypto.py y securechat/session.py.
// Debe producir exactamente los mismos bytes que la versión Python para que
// clientes web y de terminal puedan hablar entre sí (lo comprueban los tests).

let S; // libsodium.js, inicializado en ready()

export async function ready(sodium = globalThis.sodium) {
  await sodium.ready;
  S = sodium;
  return S;
}

const PROTOCOL = utf8("securechat-v1");
const AUTH_CONTEXT = utf8("securechat-auth-v1");
const MAX_SKIP = 1000;
const KEYSTORE_VERSION = 1;

export class CryptoError extends Error {}
export class IdentityMismatch extends CryptoError {
  constructor(peer, expected, received) {
    super(`¡La clave de identidad de '${peer}' ha cambiado!`);
    Object.assign(this, { peer, expected, received });
  }
}

// ------------------------------------------------------------ utilidades

export function utf8(s) { return new TextEncoder().encode(s); }
export const b64e = (b) => S.to_base64(b, S.base64_variants.ORIGINAL);
export function b64d(s) {
  try { return S.from_base64(s, S.base64_variants.ORIGINAL); }
  catch { throw new CryptoError("base64 inválido"); }
}
export const equal = (a, b) => a.length === b.length && S.memcmp(a, b);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function encodeFields(...fields) {
  return concat(...fields.flatMap((f) => {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, f.length);
    return [len, f];
  }));
}

export function kdf(key, label, data = new Uint8Array(), size = 32) {
  return S.crypto_generichash(size, encodeFields(utf8("securechat-kdf"), utf8(label), data), key);
}

function u64(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

// ----------------------------------------------------- almacén de claves

export function saveIdentity(seed, password,
  ops = S.crypto_pwhash_OPSLIMIT_INTERACTIVE, mem = S.crypto_pwhash_MEMLIMIT_INTERACTIVE) {
  const salt = S.randombytes_buf(S.crypto_pwhash_SALTBYTES);
  const key = S.crypto_pwhash(32, utf8(password), salt, ops, mem, S.crypto_pwhash_ALG_ARGON2ID13);
  const nonce = S.randombytes_buf(24);
  const kp = S.crypto_sign_seed_keypair(seed);
  return {
    version: KEYSTORE_VERSION, kdf: "argon2id", opslimit: ops, memlimit: mem,
    salt: b64e(salt), public_key: b64e(kp.publicKey),
    ciphertext: b64e(concat(nonce, S.crypto_secretbox_easy(seed, nonce, key))),
  };
}

/** Devuelve {seed, publicKey, privateKey}. Mismo formato que identity.json de la CLI. */
export function loadIdentity(blob, password) {
  if (blob.version !== KEYSTORE_VERSION || blob.kdf !== "argon2id")
    throw new CryptoError("formato de almacén de claves no soportado");
  const key = S.crypto_pwhash(32, utf8(password), b64d(blob.salt), blob.opslimit, blob.memlimit,
    S.crypto_pwhash_ALG_ARGON2ID13);
  const raw = b64d(blob.ciphertext);
  let seed;
  try { seed = S.crypto_secretbox_open_easy(raw.subarray(24), raw.subarray(0, 24), key); }
  catch { throw new CryptoError("contraseña incorrecta o almacén corrupto"); }
  const kp = S.crypto_sign_seed_keypair(seed);
  if (!equal(kp.publicKey, b64d(blob.public_key)))
    throw new CryptoError("la clave pública almacenada no coincide");
  return { seed, publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function newIdentitySeed() { return S.randombytes_buf(32); }

// ------------------------------------------- huellas y números de seguridad

function digits(name, key) {
  let h = encodeFields(utf8("securechat-fp-v1"), utf8(name), key);
  for (let i = 0; i < 5200; i++) h = S.crypto_generichash(64, concat(h, key), null);
  let out = "";
  for (let i = 0; i < 30; i += 5) {
    let v = 0n;
    for (let j = 0; j < 5; j++) v = (v << 8n) | BigInt(h[i + j]);
    out += String(v % 100000n).padStart(5, "0");
  }
  return out;
}

export function fingerprint(key) {
  return S.to_hex(S.crypto_generichash(16, key, null)).match(/.{4}/g).join(" ");
}

export function safetyNumber(nameA, keyA, nameB, keyB) {
  const full = [digits(nameA, keyA), digits(nameB, keyB)].sort().join("");
  return full.match(/.{5}/g).join(" ");
}

export function verifySignature(key, message, sig) {
  let ok = false;
  try { ok = key.length === 32 && sig.length === 64 && S.crypto_sign_verify_detached(sig, message, key); }
  catch { ok = false; }
  if (!ok) throw new CryptoError("firma inválida");
}

export function signAuth(identity, nonce, user) {
  return S.crypto_sign_detached(encodeFields(AUTH_CONTEXT, nonce, utf8(user)), identity.privateKey);
}

// Las sesiones (X3DH + Double Ratchet, por dispositivo) están en ratchet.js.
