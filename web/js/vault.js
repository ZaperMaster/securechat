// Almacenamiento en el dispositivo (IndexedDB):
//  * "Recordarme": la semilla de tu identidad se guarda cifrada con una clave
//    AES-GCM de WebCrypto marcada como NO exportable. El navegador la usa, pero
//    nadie puede sacarla del dispositivo (ni siquiera el propio código de la web).
//  * Historial: cada mensaje se guarda cifrado con una clave derivada de tu
//    identidad. Las fotos y vídeos van aparte para no cargarlos hasta verlos.

import { kdf } from "./protocol.js";

const DB_NAME = "securechat";
let dbPromise = null;

function db() {
  dbPromise ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const d = req.result;
      d.createObjectStore("devicekeys");                       // cuenta -> {key, iv, ct}
      const m = d.createObjectStore("messages", { keyPath: "k" }); // cuenta|peer|id
      m.createIndex("account", "account");
      d.createObjectStore("media");                            // cuenta|peer|id -> bytes cifrados
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx(store, mode, fn) {
  return db().then((d) => new Promise((resolve, reject) => {
    const t = d.transaction(store, mode);
    let result;
    Promise.resolve(fn(t.objectStore(store))).then((r) => { result = r; });
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  }));
}

const req2p = (r) => new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });

// --------------------------------------------------------- sesión recordada

export const canRemember = () => !!(globalThis.crypto?.subtle && globalThis.indexedDB);

export async function remember(account, seed) {
  if (!canRemember()) return false;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, seed));
  await tx("devicekeys", "readwrite", (s) => s.put({ key, iv, ct }, account.toLowerCase()));
  return true;
}

export async function recall(account) {
  if (!canRemember()) return null;
  try {
    const rec = await tx("devicekeys", "readonly", (s) => req2p(s.get(account.toLowerCase())));
    if (!rec) return null;
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv }, rec.key, rec.ct));
  } catch {
    return null;
  }
}

export async function forget(account) {
  if (!canRemember()) return;
  await tx("devicekeys", "readwrite", (s) => s.delete(account.toLowerCase()));
}

// ------------------------------------------------------------------ historial

export class History {
  constructor(account, seed) {
    this.account = account.toLowerCase();
    this.key = kdf(seed, "sc-history");
  }

  seal(bytes) {
    const nonce = sodium.randombytes_buf(24);
    const ct = sodium.crypto_secretbox_easy(bytes, nonce, this.key);
    const out = new Uint8Array(24 + ct.length);
    out.set(nonce); out.set(ct, 24);
    return out;
  }

  open(box) {
    return sodium.crypto_secretbox_open_easy(box.subarray(24), box.subarray(0, 24), this.key);
  }

  k(peer, id) { return `${this.account}|${peer.toLowerCase()}|${id}`; }

  /** Guarda o actualiza un mensaje. `m` no debe llevar los bytes de la foto/vídeo. */
  async put(peer, m) {
    const { el, url, ...plain } = m; // ni elementos del DOM ni URLs temporales
    const box = this.seal(new TextEncoder().encode(JSON.stringify({ ...plain, peer })));
    await tx("messages", "readwrite", (s) => s.put({ k: this.k(peer, m.id), account: this.account, box }));
  }

  async putMedia(peer, id, bytes) {
    await tx("media", "readwrite", (s) => s.put(this.seal(bytes), this.k(peer, id)));
  }

  async getMedia(peer, id) {
    const box = await tx("media", "readonly", (s) => req2p(s.get(this.k(peer, id))));
    return box ? this.open(box) : null;
  }

  /** Todos los mensajes de esta cuenta, descifrados, agrupados por contacto. */
  async loadAll() {
    const rows = await tx("messages", "readonly", (s) => req2p(s.index("account").getAll(this.account)));
    const byPeer = new Map();
    for (const r of rows) {
      let m;
      try { m = JSON.parse(new TextDecoder().decode(this.open(r.box))); } catch { continue; }
      m.time = new Date(m.time);
      if (!byPeer.has(m.peer)) byPeer.set(m.peer, []);
      byPeer.get(m.peer).push(m);
    }
    for (const list of byPeer.values()) list.sort((a, b) => a.time - b.time);
    return byPeer;
  }

  async deleteChat(peer) {
    const prefix = `${this.account}|${peer.toLowerCase()}|`;
    const range = IDBKeyRange.bound(prefix, `${prefix}￿`);
    await tx("messages", "readwrite", (s) => s.delete(range));
    await tx("media", "readwrite", (s) => s.delete(range));
  }
}
