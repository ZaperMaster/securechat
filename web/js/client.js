// Lógica de red del cliente web (equivalente a securechat/client.py).
// No toca el DOM: la interfaz recibe eventos por `onEvent`.

import { b64d, b64e, CryptoError, equal, IdentityMismatch, Session, signAuth } from "./protocol.js";

export class ClientError extends Error {}

export const IMAGE_MIME = ["image/png", "image/jpeg", "image/gif", "image/webp"];
export const VIDEO_MIME = ["video/mp4", "video/webm", "video/quicktime"];
export const MAX_MEDIA = 8 * 1024 * 1024;

/** Valida el contenido descifrado (ver securechat/content.py). Nunca confiamos en él. */
export function decodeContent(plaintext) {
  let c;
  try { c = JSON.parse(plaintext); } catch { return { t: "text", body: plaintext }; }
  if (!c || typeof c !== "object" || typeof c.t !== "string") return { t: "text", body: plaintext };
  const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  switch (c.t) {
    case "text": return { t: "text", body: str(c.body, 20000) };
    case "sticker": return { t: "sticker", id: str(c.id, 16) };
    case "image": case "video": {
      const allowed = c.t === "image" ? IMAGE_MIME : VIDEO_MIME;
      if (!allowed.includes(c.mime) || typeof c.data !== "string") return { t: "unsupported" };
      return { t: c.t, mime: c.mime, name: str(c.name, 120), data: c.data };
    }
    case "profile": {
      const avatar = typeof c.avatar === "string" && c.avatar.length < 200000 ? c.avatar : null;
      return { t: "profile", name: str(c.name, 64).trim(), avatar };
    }
    default: return { t: "unsupported" };
  }
}

/** Contactos en memoria; la app los guarda en localStorage. */
export class Contacts {
  constructor(data = {}, onChange = () => {}) {
    this.items = new Map(Object.entries(data).map(([n, c]) => [n, {
      name: n, key: b64d(c.identity_key), verified: c.verified,
      displayName: c.display_name || "", avatar: c.avatar || null,
    }]));
    this.onChange = onChange;
  }
  get(name) { return this.items.get(name) || null; }
  pinned(name) { return this.items.get(name)?.key || null; }
  pin(name, key) {
    const c = this.items.get(name);
    if (c) { if (!equal(c.key, key)) throw new CryptoError("la clave no coincide con la fijada"); return c; }
    this.items.set(name, { name, key, verified: false });
    this.save();
  }
  setVerified(name, v = true) { this.items.get(name).verified = v; this.save(); }
  /** Perfil que el contacto nos envió dentro de la sesión cifrada. */
  setProfile(name, { name: displayName, avatar }) {
    const c = this.items.get(name);
    if (!c) return;
    c.displayName = displayName || "";
    c.avatar = typeof avatar === "string" && /^[A-Za-z0-9+/=]+$/.test(avatar) ? avatar : null;
    this.save();
  }
  forget(name) { this.items.delete(name); this.save(); }
  all() { return [...this.items.values()].sort((a, b) => a.name.localeCompare(b.name)); }
  toJSON() {
    return Object.fromEntries([...this.items.values()].map((c) => [c.name, {
      identity_key: b64e(c.key), verified: c.verified, display_name: c.displayName, avatar: c.avatar,
    }]));
  }
  save() { this.onChange(this.toJSON()); }
}

export class ChatClient {
  constructor(name, identity, contacts, onEvent = () => {}) {
    Object.assign(this, { name, identity, contacts, onEvent });
    this.sessions = new Map();
    this.pending = new Map(); // peer -> {session, resolve, reject, timer}
    this.ws = null;
    this.lookups = new Map();
    this.lookupId = 0;
    this.profile = null; // {name, avatar}: se envía cifrado a cada contacto
  }

  connect(url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      let stage = "hello";
      ws.onopen = () => this.send({ type: "hello", user: this.name, identity_key: b64e(this.identity.publicKey) });
      ws.onerror = () => { if (stage !== "ready") reject(new ClientError("no se pudo conectar con el servidor")); };
      ws.onclose = () => {
        if (stage !== "ready") reject(new ClientError("el servidor cerró la conexión"));
        for (const p of this.pending.values()) p.reject(new ClientError("conexión cerrada"));
        this.pending.clear();
        this.emit("disconnected");
      };
      ws.onmessage = async (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (stage === "hello") {
          if (msg.type !== "challenge") { stage = "failed"; return reject(new ClientError(msg.message || "respuesta inesperada")); }
          this.send({ type: "auth", sig: b64e(signAuth(this.identity, b64d(msg.nonce), this.name)) });
          stage = "auth";
        } else if (stage === "auth") {
          if (msg.type !== "welcome") { stage = "failed"; return reject(new ClientError(msg.message || "autenticación rechazada")); }
          stage = "ready";
          this.name = msg.user; // grafía oficial registrada en el servidor
          resolve();
        } else {
          try { await this.dispatch(msg); }
          catch (e) { this.emit("warning", "", `mensaje malformado ignorado: ${e.message}`); }
        }
      };
    });
  }

  close() { this.ws?.close(); }

  /** ¿Existe el usuario? → {exists, user (grafía oficial), online} */
  lookup(name) {
    const id = ++this.lookupId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.lookups.delete(id); reject(new ClientError("el servidor no responde")); }, 5000);
      this.lookups.set(id, {
        resolve: (v) => { clearTimeout(timer); this.lookups.delete(id); resolve(v); },
        reject: (e) => { clearTimeout(timer); this.lookups.delete(id); reject(e); },
      });
      this.send({ type: "lookup", user: name, id });
    });
  }

  async resolve(name) {
    if (this.sessions.has(name)) return name;
    const info = await this.lookup(name);
    if (!info.exists) throw new ClientError(`El usuario @${name} no existe`);
    return info.user;
  }

  async openSession(name, timeout = 10000) {
    const peer = await this.resolve(name);
    if (peer.toLowerCase() === this.name.toLowerCase()) throw new ClientError("no puedes abrir un chat contigo mismo");
    const [session, hs1] = Session.initiate(this.name, this.identity, peer);
    return new Promise((resolve, reject) => {
      const done = (fn) => (v) => { clearTimeout(entry.timer); if (this.pending.get(peer) === entry) this.pending.delete(peer); fn(v); };
      const entry = { session, resolve: done(resolve), reject: done(reject) };
      entry.timer = setTimeout(() => entry.reject(new ClientError(`'${peer}' no respondió al handshake`)), timeout);
      this.pending.set(peer, entry);
      this.send({ type: "send", to: peer, payload: hs1 });
    });
  }

  sendText(peer, text) { return this.sendContent(peer, { t: "text", body: text }); }

  /** Envía contenido estructurado (texto, imagen, vídeo, sticker, perfil), siempre cifrado. */
  async sendContent(name, content) {
    const peer = await this.resolve(name);
    const session = this.sessions.get(peer) || await this.openSession(peer);
    this.send({ type: "send", to: peer, payload: session.encrypt(JSON.stringify(content)) });
    return peer;
  }

  /** Cambia mi perfil y se lo envía (cifrado) a todas las sesiones abiertas. */
  setProfile(profile) {
    this.profile = profile;
    for (const peer of this.sessions.keys()) this.sendProfile(peer);
  }

  sendProfile(peer) {
    if (!this.profile) return;
    const s = this.sessions.get(peer);
    try { this.send({ type: "send", to: peer, payload: s.encrypt(JSON.stringify({ t: "profile", ...this.profile })) }); }
    catch { /* desconectado: se reenviará en la próxima sesión */ }
  }

  who() {
    return new Promise((resolve, reject) => {
      this.whoResolve = resolve;
      setTimeout(() => reject(new ClientError("sin respuesta")), 5000);
      this.send({ type: "who" });
    });
  }

  async dispatch(msg) {
    if (msg.type === "deliver") return this.onDeliver(msg.from, msg.payload);
    if (msg.type === "who") return this.whoResolve?.(msg.users);
    if (msg.type === "lookup") return this.lookups.get(msg.id)?.resolve({ exists: msg.exists, user: msg.user, online: msg.online });
    if (msg.type === "error" && this.lookups.has(msg.id)) return this.lookups.get(msg.id).reject(new ClientError(msg.message));
    if (msg.type === "error") {
      const p = this.pending.get(msg.to);
      if (msg.code === "offline" && p) p.reject(new ClientError(msg.message || "usuario no conectado"));
      else this.emit("warning", msg.to || "", msg.message || "error del servidor");
    }
  }

  async onDeliver(sender, payload) {
    const kind = payload?.kind;
    try {
      if (kind === "hs1") this.onHs1(sender, payload);
      else if (kind === "hs2") this.onHs2(sender, payload);
      else if (kind === "msg") {
        const s = this.sessions.get(sender);
        if (!s) throw new CryptoError("mensaje sin sesión establecida");
        const before = s.lost;
        const text = s.decrypt(payload);
        if (s.lost > before) this.emit("warning", sender, `se perdieron ${s.lost - before} mensaje(s) de ${sender}`);
        const c = decodeContent(text);
        if (c.t === "profile") this.emit("profile", sender, "", { name: c.name, avatar: c.avatar });
        else this.emit("message", sender, c.t === "text" ? c.body : "", c);
      } else throw new CryptoError(`tipo de payload desconocido: ${kind}`);
    } catch (e) {
      if (!(e instanceof CryptoError)) throw e;
      if (e instanceof IdentityMismatch || kind === "hs2") this.pending.get(sender)?.reject(e);
      if (e instanceof IdentityMismatch) this.emit("identity_changed", sender, e.message);
      else this.emit("warning", sender, `descartado mensaje de ${sender}: ${e.message}`);
    }
  }

  onHs1(sender, hs1) {
    if (this.pending.has(sender) && this.name < sender) return; // apertura simultánea
    const [session, hs2] = Session.accept(this.name, this.identity, sender, hs1, this.contacts.pinned(sender));
    this.contacts.pin(sender, session.peerIdentity);
    const renewed = this.sessions.has(sender);
    this.sessions.set(sender, session);
    this.send({ type: "send", to: sender, payload: hs2 });
    this.pending.get(sender)?.resolve(session);
    this.emit("session", sender, renewed ? "sesión renovada" : "sesión iniciada");
    this.sendProfile(sender);
  }

  onHs2(sender, hs2) {
    const p = this.pending.get(sender);
    if (!p) throw new CryptoError("hs2 no solicitado");
    p.session.complete(hs2, this.contacts.pinned(sender));
    this.contacts.pin(sender, p.session.peerIdentity);
    this.sessions.set(sender, p.session);
    p.resolve(p.session);
    this.emit("session", sender, "sesión iniciada");
    this.sendProfile(sender);
  }

  emit(kind, peer = "", text = "", content = null) { this.onEvent({ kind, peer, text, content }); }

  send(msg) {
    if (this.ws?.readyState !== 1) throw new ClientError("no conectado");
    this.ws.send(JSON.stringify(msg));
  }
}
