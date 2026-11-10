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

// --------------------------------------------------------------- sesiones

function checkPinned(peer, pinned, received) {
  if (pinned && !equal(pinned, received)) throw new IdentityMismatch(peer, pinned, received);
}

export class Session {
  constructor(me, identity, peer, initiator) {
    Object.assign(this, { me, identity, peer, initiator });
    this.ephPriv = S.randombytes_buf(32);
    this.ephPub = S.crypto_scalarmult_base(this.ephPriv);
    this.peerIdentity = null;
    this.established = false;
    this.sendN = 0; this.recvN = 0; this.lost = 0;
  }

  get a() { return this.initiator ? this.me : this.peer; }
  get b() { return this.initiator ? this.peer : this.me; }

  static initiate(me, identity, peer) {
    const s = new Session(me, identity, peer, true);
    const sig = S.crypto_sign_detached(encodeFields(PROTOCOL, utf8("hs1"), utf8(me), utf8(peer),
      identity.publicKey, s.ephPub), identity.privateKey);
    return [s, { kind: "hs1", identity_key: b64e(identity.publicKey), eph: b64e(s.ephPub), sig: b64e(sig) }];
  }

  static accept(me, identity, peer, hs1, pinned) {
    if (hs1.kind !== "hs1") throw new CryptoError("se esperaba hs1");
    const idA = b64d(hs1.identity_key), ephA = b64d(hs1.eph);
    checkPinned(peer, pinned, idA);
    verifySignature(idA, encodeFields(PROTOCOL, utf8("hs1"), utf8(peer), utf8(me), idA, ephA), b64d(hs1.sig));
    const s = new Session(me, identity, peer, false);
    s.peerIdentity = idA;
    const idB = identity.publicKey;
    const sig = S.crypto_sign_detached(encodeFields(PROTOCOL, utf8("hs2"), utf8(peer), utf8(me),
      idA, idB, ephA, s.ephPub), identity.privateKey);
    const hs2 = { kind: "hs2", identity_key: b64e(idB), eph: b64e(s.ephPub), sig: b64e(sig) };
    s.derive(idA, idB, ephA, s.ephPub, ephA);
    return [s, hs2];
  }

  complete(hs2, pinned) {
    if (!this.initiator || this.established || hs2.kind !== "hs2") throw new CryptoError("hs2 inesperado");
    const idB = b64d(hs2.identity_key), ephB = b64d(hs2.eph);
    checkPinned(this.peer, pinned, idB);
    const idA = this.identity.publicKey;
    verifySignature(idB, encodeFields(PROTOCOL, utf8("hs2"), utf8(this.me), utf8(this.peer),
      idA, idB, this.ephPub, ephB), b64d(hs2.sig));
    this.peerIdentity = idB;
    this.derive(idA, idB, this.ephPub, ephB, ephB);
  }

  derive(idA, idB, ephA, ephB, ephPeer) {
    if (ephPeer.length !== 32) throw new CryptoError("clave efímera con longitud inválida");
    let shared;
    try { shared = S.crypto_scalarmult(this.ephPriv, ephPeer); }
    catch { throw new CryptoError("clave efímera inválida"); }
    if (S.is_zero(shared)) throw new CryptoError("clave efímera inválida");
    this.th = S.crypto_generichash(32, encodeFields(PROTOCOL, utf8(this.a), utf8(this.b), idA, idB, ephA, ephB), null);
    const root = kdf(shared, "sc-root", this.th);
    const i2r = kdf(root, "sc-chain-i2r"), r2i = kdf(root, "sc-chain-r2i");
    [this.sendCk, this.recvCk] = this.initiator ? [i2r, r2i] : [r2i, i2r];
    S.memzero(this.ephPriv); S.memzero(shared); S.memzero(root);
    this.ephPriv = null;
    this.established = true;
  }

  aad(sender, n) { return encodeFields(this.th, utf8(sender), u64(n)); }

  encrypt(text) {
    if (!this.established) throw new CryptoError("la sesión no está establecida");
    const mk = kdf(this.sendCk, "sc-msg");
    this.sendCk = kdf(this.sendCk, "sc-chain");
    const n = this.sendN++;
    const nonce = S.randombytes_buf(24);
    const ct = S.crypto_aead_xchacha20poly1305_ietf_encrypt(utf8(text), this.aad(this.me, n), null, nonce, mk);
    S.memzero(mk);
    return { kind: "msg", n, nonce: b64e(nonce), ct: b64e(ct) };
  }

  decrypt(p) {
    if (!this.established) throw new CryptoError("la sesión no está establecida");
    const n = p.n;
    if (!Number.isSafeInteger(n) || n < this.recvN) throw new CryptoError("mensaje repetido o antiguo");
    if (n - this.recvN > MAX_SKIP) throw new CryptoError("salto de contador demasiado grande");
    let ck = this.recvCk;
    for (let i = this.recvN; i < n; i++) ck = kdf(ck, "sc-chain");
    const mk = kdf(ck, "sc-msg");
    let pt;
    try { pt = S.crypto_aead_xchacha20poly1305_ietf_decrypt(null, b64d(p.ct), this.aad(this.peer, n), b64d(p.nonce), mk); }
    catch { throw new CryptoError("mensaje manipulado o clave incorrecta"); }
    this.lost += n - this.recvN;
    this.recvCk = kdf(ck, "sc-chain");
    this.recvN = n + 1;
    return new TextDecoder("utf-8", { fatal: true }).decode(pt);
  }
}
