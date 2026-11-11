// Port a JavaScript de securechat/ratchet.py: X3DH con one-time prekeys +
// Double Ratchet, por dispositivo. Debe producir los mismos bytes que Python.

import { b64d, b64e, CryptoError, encodeFields, IdentityMismatch, kdf, utf8, verifySignature } from "./protocol.js";

const S = () => globalThis.sodium;
const PROTO = utf8("securechat-v2");
const MAX_SKIP = 1000;
const MAX_SKIPPED_STORED = 2000;
const SPK_LIFETIME = 7 * 24 * 3600;
export const OPK_BATCH = 20;
export const DEVICE_RE = /^[A-Za-z0-9_-]{6,24}$/;

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
const clone = (o) => JSON.parse(JSON.stringify(o));

export function newDeviceId() {
  return S().to_base64(S().randombytes_buf(9), S().base64_variants.URLSAFE_NO_PADDING);
}

function dh(priv, pub) {
  if (pub.length !== 32) throw new CryptoError("clave pública con longitud inválida");
  let out;
  try { out = S().crypto_scalarmult(priv, pub); } catch { throw new CryptoError("clave inválida"); }
  if (S().is_zero(out)) throw new CryptoError("clave inválida");
  return out;
}

function keypair() {
  const priv = S().randombytes_buf(32);
  return [priv, S().crypto_scalarmult_base(priv)];
}

const ikPriv = (identity) => S().crypto_sign_ed25519_sk_to_curve25519(identity.privateKey);
const ikPub = (edPub) => S().crypto_sign_ed25519_pk_to_curve25519(edPub);

export const spkMessage = (user, device, spk, created) =>
  encodeFields(PROTO, utf8("spk"), utf8(user), utf8(device), spk, u64(created));

const x3dhAd = (a, aDev, b, bDev, ikA, ikB) => encodeFields(PROTO, utf8("ad"), utf8(a), utf8(aDev), utf8(b), utf8(bDev), ikA, ikB);

function x3dhSecret(dhs, ad) {
  const ikm = S().crypto_generichash(32, encodeFields(...dhs), null);
  return kdf(ikm, "sc-x3dh", ad);
}

function kdfRk(rk, dhOut) {
  const out = kdf(rk, "sc-rk", dhOut, 64);
  return [out.slice(0, 32), out.slice(32)];
}

const kdfCk = (ck) => [kdf(ck, "sc-ck"), kdf(ck, "sc-mk")];
const headerBytes = (dhPub, pn, n) => encodeFields(dhPub, u32(pn), u32(n));

// ------------------------------------------------------------ Double Ratchet

export class Ratchet {
  constructor(st) { this.st = st; }

  static asInitiator(sk, ad, theirSpk, x3dh) {
    const [priv, pub] = keypair();
    const [rk, cks] = kdfRk(sk, dh(priv, theirSpk));
    return new Ratchet({ ad: b64e(ad), dhs: [b64e(priv), b64e(pub)], dhr: b64e(theirSpk), rk: b64e(rk),
      cks: b64e(cks), ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, x3dh });
  }

  static asResponder(sk, ad, spkPriv, spkPub) {
    return new Ratchet({ ad: b64e(ad), dhs: [b64e(spkPriv), b64e(spkPub)], dhr: null, rk: b64e(sk),
      cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, x3dh: null });
  }

  encrypt(plaintext) {
    const st = this.st;
    const [ck, mk] = kdfCk(b64d(st.cks));
    st.cks = b64e(ck);
    const header = { dh: st.dhs[1], pn: st.pn, n: st.ns };
    const aad = encodeFields(b64d(st.ad), headerBytes(b64d(st.dhs[1]), st.pn, st.ns));
    st.ns += 1;
    const nonce = S().randombytes_buf(24);
    const ct = S().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, mk);
    const out = { header, nonce: b64e(nonce), ct: b64e(ct) };
    if (st.x3dh) out.x3dh = st.x3dh; // hasta que nos respondan, repetimos el inicio X3DH
    return out;
  }

  decrypt(msg) {
    const backup = clone(this.st);
    try { return this._decrypt(msg); }
    catch (e) { this.st = backup; throw e; } // un mensaje malo no estropea la sesión
  }

  _decrypt(msg) {
    const st = this.st;
    const h = msg.header;
    const pn = Number(h.pn), n = Number(h.n);
    if (!Number.isInteger(pn) || !Number.isInteger(n) || pn < 0 || n < 0) throw new CryptoError("cabecera inválida");
    const dhPub = b64d(h.dh);
    const aad = encodeFields(b64d(st.ad), headerBytes(dhPub, pn, n));
    const nonce = b64d(msg.nonce), ct = b64d(msg.ct);
    const key = `${h.dh}:${n}`;
    if (key in st.skipped) {
      const mk = b64d(st.skipped[key]);
      delete st.skipped[key];
      return this.open(mk, nonce, ct, aad);
    }
    if (h.dh !== st.dhr) {
      if (st.dhr !== null) this.skip(pn);
      this.dhRatchet(dhPub);
    }
    this.skip(n);
    const [ck, mk] = kdfCk(b64d(st.ckr));
    st.ckr = b64e(ck);
    st.nr += 1;
    const pt = this.open(mk, nonce, ct, aad);
    st.x3dh = null; // nos han respondido: ya no hace falta repetir el inicio
    return pt;
  }

  open(mk, nonce, ct, aad) {
    try { return S().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, mk); }
    catch { throw new CryptoError("mensaje manipulado o clave incorrecta"); }
  }

  skip(until) {
    const st = this.st;
    if (st.ckr === null) return;
    if (until - st.nr > MAX_SKIP) throw new CryptoError("demasiados mensajes saltados");
    let ck = b64d(st.ckr);
    while (st.nr < until) {
      const [next, mk] = kdfCk(ck);
      st.skipped[`${st.dhr}:${st.nr}`] = b64e(mk);
      ck = next;
      st.nr += 1;
    }
    st.ckr = b64e(ck);
    const keys = Object.keys(st.skipped);
    for (let i = 0; i < keys.length - MAX_SKIPPED_STORED; i++) delete st.skipped[keys[i]];
  }

  dhRatchet(theirPub) {
    const st = this.st;
    st.pn = st.ns; st.ns = 0; st.nr = 0;
    st.dhr = b64e(theirPub);
    let [rk, ckr] = kdfRk(b64d(st.rk), dh(b64d(st.dhs[0]), theirPub));
    const [priv, pub] = keypair();
    st.dhs = [b64e(priv), b64e(pub)];
    const [rk2, cks] = kdfRk(rk, dh(priv, theirPub));
    st.rk = b64e(rk2); st.ckr = b64e(ckr); st.cks = b64e(cks);
  }
}

// ------------------------------------------------------------------- X3DH

export function initiate(me, myDev, identity, peer, peerDev, peerIk, bundle, pinned) {
  if (pinned && !S().memcmp(pinned, peerIk)) throw new IdentityMismatch(peer, pinned, peerIk);
  const spk = b64d(bundle.spk);
  verifySignature(peerIk, spkMessage(peer, peerDev, spk, bundle.created), b64d(bundle.sig));
  const opk = bundle.opk ? b64d(bundle.opk) : null;
  const [ekPriv, ekPub] = keypair();
  const dhs = [dh(ikPriv(identity), spk), dh(ekPriv, ikPub(peerIk)), dh(ekPriv, spk)];
  if (opk) dhs.push(dh(ekPriv, opk));
  const ad = x3dhAd(me, myDev, peer, peerDev, identity.publicKey, peerIk);
  const x3dh = { ik: b64e(identity.publicKey), ek: b64e(ekPub), spk: bundle.spk, opk: bundle.opk || null };
  return Ratchet.asInitiator(x3dhSecret(dhs, ad), ad, spk, x3dh);
}

function accept(me, myDev, identity, peer, peerDev, x3dh, keys, pinned) {
  const peerIk = b64d(x3dh.ik);
  if (pinned && !S().memcmp(pinned, peerIk)) throw new IdentityMismatch(peer, pinned, peerIk);
  const spk = b64d(x3dh.spk);
  const spkPriv = keys.spkPrivate(spk);
  if (!spkPriv) throw new CryptoError("mensaje para una prekey que ya no existe");
  let opkPriv = null;
  if (x3dh.opk) {
    opkPriv = keys.opkPrivate(b64d(x3dh.opk));
    if (!opkPriv) throw new CryptoError("prekey de un solo uso ya usada (¿mensaje repetido?)");
  }
  const ek = b64d(x3dh.ek);
  const dhs = [dh(spkPriv, ikPub(peerIk)), dh(ikPriv(identity), ek), dh(spkPriv, ek)];
  if (opkPriv) dhs.push(dh(opkPriv, ek));
  const ad = x3dhAd(peer, peerDev, me, myDev, peerIk, identity.publicKey);
  return [Ratchet.asResponder(x3dhSecret(dhs, ad), ad, spkPriv, spk), peerIk];
}

// --------------------------------------------- claves de este dispositivo

/**
 * Prekeys de ESTE dispositivo y sus sesiones. `data` es lo guardado (descifrado)
 * y `save(data)` lo guarda; la app lo cifra con una clave derivada de la identidad.
 */
export class DeviceKeys {
  constructor(user, identity, data, save = () => {}) {
    this.user = user;
    this.identity = identity;
    this._save = save;
    this.device = data?.device || newDeviceId();
    this.spks = data?.spks || [];
    this.opks = data?.opks || {};
    this.sessions = data?.sessions || {};
    this.seen = data?.seen || [];
    if (!data?.device) this.save();
  }

  save() {
    this._save({ device: this.device, spks: this.spks, opks: this.opks, sessions: this.sessions, seen: this.seen.slice(-2000) });
  }

  currentSpk() {
    const now = Math.floor(Date.now() / 1000);
    if (!this.spks.length || now - this.spks.at(-1).created > SPK_LIFETIME) {
      const [priv, pub] = keypair();
      this.spks = [...this.spks, { priv: b64e(priv), pub: b64e(pub), created: now }].slice(-3);
      this.save();
    }
    return this.spks.at(-1);
  }

  spkPrivate(pub) {
    const k = this.spks.find((x) => x.pub === b64e(pub));
    return k ? b64d(k.priv) : null;
  }

  opkPrivate(pub) {
    const key = b64e(pub);
    const priv = this.opks[key];
    if (!priv) return null;
    delete this.opks[key]; // de un solo uso: se borra al usarla
    this.save();
    return b64d(priv);
  }

  newOpks(n = OPK_BATCH) {
    const pubs = [];
    for (let i = 0; i < n; i++) {
      const [priv, pub] = keypair();
      this.opks[b64e(pub)] = b64e(priv);
      pubs.push(b64e(pub));
    }
    this.save();
    return pubs;
  }

  uploadMessage(opksOnServer) {
    const spk = this.currentSpk();
    const sig = S().crypto_sign_detached(spkMessage(this.user, this.device, b64d(spk.pub), spk.created), this.identity.privateKey);
    const opks = opksOnServer < OPK_BATCH / 2 ? this.newOpks() : [];
    return { type: "prekeys", spk: spk.pub, sig: b64e(sig), created: spk.created, opks };
  }

  key(user, device) { return `${user.toLowerCase()}|${device}`; }
  states(user, device) { const v = this.sessions[this.key(user, device)] || []; return Array.isArray(v) ? v : [v]; }
  session(user, device) { const st = this.states(user, device); return st.length ? new Ratchet(st[0]) : null; }

  store(user, device, r, index = 0) {
    const st = this.states(user, device).slice();
    if (index < st.length) st.splice(index, 1);
    this.sessions[this.key(user, device)] = [r.st, ...st].slice(0, 4);
    this.save();
  }

  pushNew(user, device, r) {
    this.sessions[this.key(user, device)] = [r.st, ...this.states(user, device)].slice(0, 4);
    this.save();
  }

  drop(user, device) { delete this.sessions[this.key(user, device)]; this.save(); }

  firstTime(mid) {
    if (!mid) return true;
    if (this.seen.includes(mid)) return false;
    this.seen.push(mid);
    return true;
  }
}

export function encryptFor(myDev, r, plaintext) {
  return { kind: "dr", dev: myDev, ...r.encrypt(utf8(plaintext)) };
}

/** Descifra un mensaje "dr". Devuelve {text, ik} (ik si se acaba de conocer por X3DH). */
export function decryptFrom(me, keys, sender, payload, pinned) {
  const dev = payload?.dev;
  if (typeof dev !== "string" || !DEVICE_RE.test(dev)) throw new CryptoError("dispositivo de origen inválido");
  const states = keys.states(sender, dev);
  const x3dh = payload.x3dh;
  const known = x3dh && states.some((st) => st.x3dh_seen === x3dh.ek || st.x3dh?.ek === x3dh.ek);
  const decode = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (x3dh && !known) {
    // Primer mensaje de esa sesión: creamos la sesión de respuesta
    const [fresh, ik] = accept(me, keys.device, keys.identity, sender, dev, x3dh, keys, pinned);
    const pt = fresh.decrypt(payload);
    fresh.st.x3dh_seen = x3dh.ek;
    keys.pushNew(sender, dev, fresh);
    return { text: decode(pt), ik };
  }
  for (let i = 0; i < states.length; i++) {
    const r = new Ratchet(clone(states[i]));
    let pt;
    try { pt = r.decrypt(payload); } catch { continue; }
    keys.store(sender, dev, r, i); // la que ha funcionado pasa a ser la actual
    return { text: decode(pt), ik: null };
  }
  throw new CryptoError("no se pudo descifrar (sesión desconocida o mensaje manipulado)");
}
