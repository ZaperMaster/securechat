// Sender keys para grupos (la idea de Signal para grupos grandes).
//
// Sin esto, cada mensaje de grupo se cifra una vez por cada dispositivo de cada
// miembro: con 20 personas y una foto de 5 MB se suben 100 MB. Con sender keys:
//
//  1. Cada dispositivo crea, para cada grupo, su propia "cadena" (una clave de 32
//     bytes) y una clave de firma Ed25519. Se las manda a los demás miembros UNA vez,
//     cifradas por el canal normal 1 a 1 (X3DH + Double Ratchet): mensaje "skey".
//  2. Cada mensaje del grupo se cifra UNA sola vez con una clave sacada de esa cadena
//     (que avanza en cada mensaje y se olvida: secreto hacia adelante) y se firma.
//     El servidor entrega esa misma copia cifrada a todos los dispositivos.
//  3. Si alguien sale o le sacan del grupo, todos crean una cadena nueva y se la mandan
//     solo a los que quedan: quien se fue ya no puede leer lo siguiente.
//
// La firma evita que un miembro (que conoce la cadena) se haga pasar por otro.

import { b64d, b64e, CryptoError, encodeFields, kdf, utf8 } from "./protocol.js";

const S = () => globalThis.sodium;
const CTX = utf8("securechat-sk-v1");
export const SK_MAX_SKIP = 2000;        // mensajes que se pueden saltar (llegan desordenados)
export const SK_MAX_MESSAGES = 500;     // tras tantos mensajes se rota la cadena
export const SK_MAX_AGE = 7 * 86400000; // o tras una semana

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

function step(ck) { return [kdf(ck, "sc-sk-ck"), kdf(ck, "sc-sk-mk")]; }

/** Datos autenticados de cada mensaje: grupo, autor, dispositivo, cadena e índice. */
export const skAad = (g, sender, dev, kid, n) =>
  encodeFields(CTX, utf8(g), utf8(sender.toLowerCase()), utf8(dev), utf8(kid), u32(n));

/** Cadena nueva para un grupo (la mía). members: a quién va dirigida (para saber cuándo rotar). */
export function newSenderKey(members) {
  const sig = S().crypto_sign_keypair();
  return {
    kid: S().to_base64(S().randombytes_buf(8), S().base64_variants.URLSAFE_NO_PADDING),
    ck: b64e(S().randombytes_buf(32)), n: 0, created: Date.now(),
    spk: b64e(sig.publicKey), ssk: b64e(sig.privateKey),
    members: memberSig(members), sentTo: [],
  };
}

export const memberSig = (members) => [...new Set(members.map((m) => m.toLowerCase()))].sort().join(",");

/** ¿Hay que cambiar de cadena? (cambió el grupo, demasiados mensajes o demasiado tiempo) */
export function needsRotation(key, members) {
  return !key || key.members !== memberSig(members) || key.n >= SK_MAX_MESSAGES || Date.now() - key.created > SK_MAX_AGE;
}

/** Lo que se manda a cada miembro (por el canal 1 a 1) para que pueda leer mis mensajes. */
export function distribution(g, key) {
  return { t: "skey", g, kid: key.kid, ck: key.ck, n: key.n, spk: key.spk };
}

/** Cifra un mensaje del grupo con mi cadena (y la avanza). Devuelve el sobre para el servidor. */
export function skEncrypt(key, g, sender, dev, plaintext) {
  const [ck, mk] = step(b64d(key.ck));
  const n = key.n;
  key.ck = b64e(ck);
  key.n = n + 1;
  const aad = skAad(g, sender, dev, key.kid, n);
  const nonce = S().randombytes_buf(24);
  const ct = S().crypto_aead_xchacha20poly1305_ietf_encrypt(utf8(plaintext), aad, null, nonce, mk);
  const sig = S().crypto_sign_detached(encodeFields(aad, nonce, ct), b64d(key.ssk));
  return { kind: "sk", g, dev, kid: key.kid, n, nonce: b64e(nonce), ct: b64e(ct), sig: b64e(sig) };
}

/**
 * Descifra un sobre "sk". state es la cadena de ese autor y dispositivo que recibimos
 * con "skey": {kid, ck, n, spk, skipped}. Se modifica (avanza y guarda claves saltadas).
 */
export function skDecrypt(state, sender, payload) {
  const { g, dev, kid } = payload;
  const n = payload.n;
  if (!state || state.kid !== kid) throw new CryptoError("todavía no tengo la clave de este grupo");
  if (!Number.isInteger(n) || n < 0) throw new CryptoError("mensaje de grupo inválido");
  const aad = skAad(g, sender, dev, kid, n);
  const nonce = b64d(payload.nonce), ct = b64d(payload.ct);
  // Primero la firma: solo el dueño de la cadena puede haberlo escrito
  let ok = false;
  try { ok = S().crypto_sign_verify_detached(b64d(payload.sig), encodeFields(aad, nonce, ct), b64d(state.spk)); } catch { ok = false; }
  if (!ok) throw new CryptoError("firma del mensaje de grupo inválida");
  state.skipped ??= {};
  let mk;
  if (n < state.n) {
    // Llegó tarde: su clave tiene que estar guardada (y se usa una sola vez)
    const k = state.skipped[n];
    if (!k) throw new CryptoError("mensaje de grupo repetido o demasiado antiguo");
    delete state.skipped[n];
    mk = b64d(k);
  } else {
    if (n - state.n > SK_MAX_SKIP) throw new CryptoError("demasiados mensajes de grupo perdidos");
    let ck = b64d(state.ck);
    for (let i = state.n; i < n; i++) {
      const [next, skippedMk] = step(ck);
      state.skipped[i] = b64e(skippedMk);
      ck = next;
    }
    const [next, thisMk] = step(ck);
    mk = thisMk;
    state.ck = b64e(next);
    state.n = n + 1;
    // No guardamos claves saltadas sin límite
    const keys = Object.keys(state.skipped).map(Number).sort((a, b) => a - b);
    for (const k of keys.slice(0, Math.max(0, keys.length - SK_MAX_SKIP))) delete state.skipped[k];
  }
  let pt;
  try { pt = S().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, mk); }
  catch { throw new CryptoError("no se pudo descifrar el mensaje de grupo"); }
  return new TextDecoder().decode(pt);
}

/** Valida una distribución recibida ("skey") antes de guardarla. */
export function validDistribution(c) {
  const b64ok = (v, len) => { try { return typeof v === "string" && b64d(v).length === len; } catch { return false; } };
  return typeof c.g === "string" && typeof c.kid === "string" && c.kid.length <= 24 && Number.isInteger(c.n) && c.n >= 0
    && b64ok(c.ck, 32) && b64ok(c.spk, 32);
}
