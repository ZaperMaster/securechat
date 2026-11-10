// Lógica de red del cliente web (equivalente a securechat/client.py).
// No toca el DOM: la interfaz recibe eventos por `onEvent`.

import {
  b64d, b64e, CryptoError, equal, IdentityMismatch, openSealed, PrekeyStore, seal, Session, signAuth, verifyBundle,
} from "./protocol.js";

export class ClientError extends Error {
  constructor(message, code = null) { super(message); this.code = code; }
}

export const IMAGE_MIME = ["image/png", "image/jpeg", "image/gif", "image/webp"];
export const VIDEO_MIME = ["video/mp4", "video/webm", "video/quicktime"];
export const MAX_MEDIA = 8 * 1024 * 1024;

/** Valida el contenido descifrado (ver securechat/content.py). Nunca confiamos en él. */
export function decodeContent(plaintext) {
  let c;
  try { c = JSON.parse(plaintext); } catch { return { t: "text", body: plaintext }; }
  if (!c || typeof c !== "object" || typeof c.t !== "string") return { t: "text", body: plaintext };
  const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  const mid = /^[A-Za-z0-9_-]{8,32}$/.test(c.mid) ? c.mid : null;
  switch (c.t) {
    case "text": return { t: "text", body: str(c.body, 20000), mid };
    case "sticker": return { t: "sticker", id: str(c.id, 16), mid };
    case "image": case "video": {
      const allowed = c.t === "image" ? IMAGE_MIME : VIDEO_MIME;
      if (!allowed.includes(c.mime) || typeof c.data !== "string") return { t: "unsupported", mid };
      return { t: c.t, mime: c.mime, name: str(c.name, 120), data: c.data, mid };
    }
    case "profile": {
      const avatar = typeof c.avatar === "string" && c.avatar.length < 200000 ? c.avatar : null;
      return { t: "profile", name: str(c.name, 64).trim(), bio: str(c.bio, 140).trim(), avatar };
    }
    case "receipt": {
      const ids = Array.isArray(c.ids) ? c.ids.filter((x) => /^[A-Za-z0-9_-]{8,32}$/.test(x)).slice(0, 500) : [];
      return { t: "receipt", ids, s: c.s === "read" ? "read" : "delivered" };
    }
    default: return { t: "unsupported" };
  }
}

/** Contactos en memoria; la app los guarda en localStorage. */
export class Contacts {
  constructor(data = {}, onChange = () => {}) {
    this.items = new Map(Object.entries(data).map(([n, c]) => [n, {
      name: n, key: b64d(c.identity_key), verified: c.verified,
      displayName: c.display_name || "", avatar: c.avatar || null, bio: c.bio || "", nick: c.nick || "",
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
  /** Apodo que solo ves tú (no se envía a nadie). */
  setNick(name, nick) { const c = this.items.get(name); if (c) { c.nick = nick.trim().slice(0, 64); this.save(); } }
  /** Perfil que el contacto nos envió dentro de la sesión cifrada. */
  setProfile(name, { name: displayName, avatar, bio }) {
    const c = this.items.get(name);
    if (!c) return;
    c.displayName = displayName || "";
    c.bio = bio || "";
    c.avatar = typeof avatar === "string" && /^[A-Za-z0-9+/=]+$/.test(avatar) ? avatar : null;
    this.save();
  }
  forget(name) { this.items.delete(name); this.save(); }
  all() { return [...this.items.values()].sort((a, b) => a.name.localeCompare(b.name)); }
  toJSON() {
    return Object.fromEntries([...this.items.values()].map((c) => [c.name, {
      identity_key: b64e(c.key), verified: c.verified, display_name: c.displayName, avatar: c.avatar,
      bio: c.bio || "", nick: c.nick || "",
    }]));
  }
  save() { this.onChange(this.toJSON()); }
}

/**
 * Cómo se envía un mensaje (igual que securechat/client.py):
 *  - Con sesión en vivo (los dos conectados): ratchet con clave nueva por mensaje.
 *  - Sin sesión y el contacto conectado: se negocia una (handshake).
 *  - Contacto desconectado: "sobre sellado" con su prekey firmada; el servidor lo
 *    guarda y se lo entrega cuando se conecta.
 * Las sesiones solo viven mientras los dos siguen conectados.
 */
export class ChatClient {
  constructor(name, identity, contacts, onEvent = () => {}, { prekeys = null, code = null } = {}) {
    Object.assign(this, { name, identity, contacts, onEvent, code });
    this.prekeys = prekeys || new PrekeyStore(name, identity, null);
    this.sessions = new Map();
    this.pending = new Map(); // peer -> {session, resolve, reject, timer}
    this.requests = new Map(); // id -> {resolve, reject}
    this.nextId = 0;
    this.known = new Map(); // minúsculas -> grafía oficial
    this.online = new Map(); // peer -> bool
    this.profileSent = new Set(); // contactos que ya tienen mi perfil en esta conexión
    this.ws = null;
    this.profile = null; // {name, avatar}: se envía cifrado a cada contacto
  }

  /**
   * Conecta y se autentica. Al crear cuenta, si el servidor pide verificar un correo,
   * se llama a `onVerify(destino, error)`, que debe devolver el código recibido.
   */
  connect(url, { email = null, onVerify = null } = {}) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      let stage = "hello";
      ws.onopen = () => this.send({ type: "hello", user: this.name, code: this.code, email, identity_key: b64e(this.identity.publicKey) });
      ws.onerror = () => { if (stage === "hello" || stage === "auth") reject(new ClientError("no se pudo conectar con el servidor", "down")); };
      ws.onclose = (ev) => {
        if (stage === "hello" || stage === "auth") reject(new ClientError("el servidor cerró la conexión", "down"));
        for (const p of [...this.pending.values(), ...this.requests.values()]) p.reject(new ClientError("conexión cerrada"));
        this.pending.clear();
        this.requests.clear();
        // 4000 = el servidor nos echa porque la cuenta se ha abierto en otro sitio
        if (stage === "ready" && this.ws === ws) this.emit("disconnected", "", ev.code === 4000 ? "replaced" : "");
      };
      ws.onmessage = async (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (stage === "hello") {
          if (msg.type !== "challenge") { stage = "failed"; return reject(new ClientError(msg.message || "respuesta inesperada", msg.code)); }
          this.send({ type: "auth", sig: b64e(signAuth(this.identity, b64d(msg.nonce), this.name)) });
          stage = "auth";
        } else if (stage === "auth" && (msg.type === "verify_needed" || msg.type === "verify_failed")) {
          if (!onVerify) { stage = "failed"; ws.close(); return reject(new ClientError("este servidor pide verificar tu correo", "email_required")); }
          if (msg.type === "verify_needed") this.verifyTarget = msg.to;
          try { this.send({ type: "verify", code: await onVerify(this.verifyTarget, msg.type === "verify_failed" ? msg.message : null) }); }
          catch (e) { stage = "failed"; ws.close(); reject(e); }
        } else if (stage === "auth") {
          if (msg.type !== "welcome") { stage = "failed"; return reject(new ClientError(msg.message || "autenticación rechazada", msg.code)); }
          stage = "ready";
          this.name = this.prekeys.user = msg.user; // grafía oficial registrada en el servidor
          this.sessions.clear(); // una conexión nueva empieza sin sesiones en vivo
          this.profileSent.clear();
          this.send({ type: "prekey", ...this.prekeys.bundle() });
          resolve();
        } else {
          try { await this.dispatch(msg); }
          catch (e) { this.emit("warning", "", `mensaje malformado ignorado: ${e.message}`); }
        }
      };
    });
  }

  close() { this.ws?.close(); }

  /** Petición con id; resuelve con la respuesta del servidor. */
  request(msg, timeout = 15000) {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.requests.delete(id); reject(new ClientError("el servidor no responde")); }, timeout);
      this.requests.set(id, {
        resolve: (v) => { clearTimeout(timer); this.requests.delete(id); resolve(v); },
        reject: (e) => { clearTimeout(timer); this.requests.delete(id); reject(e); },
      });
      try { this.send({ ...msg, id }); } catch (e) { this.requests.get(id).reject(e); }
    });
  }

  /** ¿Existe el usuario? → {exists, user (grafía oficial), online} */
  async lookup(name) {
    const r = await this.request({ type: "lookup", user: name }, 5000);
    if (r.exists) { this.known.set(name.toLowerCase(), r.user); this.online.set(r.user, r.online); }
    return { exists: r.exists, user: r.user, online: r.online };
  }

  async resolve(name) {
    if (this.sessions.has(name)) return name;
    if (this.known.has(name.toLowerCase())) return this.known.get(name.toLowerCase());
    if (this.contacts.get(name)) return name;
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

  /**
   * Envía contenido cifrado (texto, imagen, vídeo, sticker o perfil).
   * Devuelve {peer, status}: status = "delivered" (entregado) o "queued" (en espera).
   */
  async sendContent(name, content) {
    const peer = await this.resolve(name);
    if (peer.toLowerCase() === this.name.toLowerCase()) throw new ClientError("no puedes escribirte a ti mismo");
    const plaintext = JSON.stringify(content);
    let session = this.sessions.get(peer);
    if (!session && this.online.get(peer) !== false) {
      try { session = await this.openSession(peer, 5000); }
      catch (e) { if (e instanceof IdentityMismatch) throw e; session = null; }
    }
    let status = null;
    if (session) {
      try { status = (await this.request({ type: "send", to: peer, payload: session.encrypt(plaintext) })).status; }
      catch { this.sessions.delete(peer); } // se desconectó justo ahora: va en diferido
    }
    if (!status) {
      status = await this.sendSealed(peer, plaintext);
      if (content.t !== "profile" && !this.profileSent.has(peer) && this.profile) {
        this.profileSent.add(peer);
        this.sendSealed(peer, JSON.stringify({ t: "profile", ...this.profile })).catch(() => this.profileSent.delete(peer));
      }
    }
    return { peer, status };
  }

  async sendSealed(peer, plaintext) {
    const r = await this.request({ type: "bundle", user: peer });
    if (!r.exists) throw new ClientError(`El usuario @${peer} no existe`);
    if (!r.prekey) throw new ClientError(`@${peer} no está conectado y su app aún no admite mensajes en diferido`);
    const { ident, spk } = verifyBundle(r.user, r.identity_key, r.prekey, this.contacts.pinned(peer));
    this.contacts.pin(peer, ident);
    const payload = seal(this.name, this.identity, peer, ident, spk, plaintext);
    return (await this.request({ type: "send", to: peer, payload })).status;
  }

  /** Cambia mi perfil y se lo envía (cifrado) a todas las sesiones abiertas. */
  setProfile(profile) {
    this.profile = profile;
    this.profileSent.clear();
    for (const peer of this.sessions.keys()) this.sendProfile(peer);
  }

  sendProfile(peer) {
    if (!this.profile) return;
    const s = this.sessions.get(peer);
    try {
      this.send({ type: "send", to: peer, payload: s.encrypt(JSON.stringify({ t: "profile", ...this.profile })) });
      this.profileSent.add(peer);
    } catch { /* desconectado: se reenviará la próxima vez */ }
  }

  async dispatch(msg) {
    const req = msg.id != null ? this.requests.get(msg.id) : null;
    if (msg.type === "deliver") return this.onDeliver(msg.from, msg.payload, msg.queued_at);
    if (msg.type === "presence") {
      this.online.set(msg.user, msg.online);
      this.sessions.delete(msg.user); // su estado de sesión ya no es fiable
      return this.emit("presence", msg.user, msg.online ? "online" : "offline");
    }
    if (req) return msg.type === "error" ? req.reject(new ClientError(msg.message || "error del servidor", msg.code)) : req.resolve(msg);
    if (msg.type === "error") {
      const p = this.pending.get(msg.to);
      if (msg.code === "offline" && p) { this.online.set(msg.to, false); p.reject(new ClientError(msg.message || "usuario no conectado")); }
      else this.emit("warning", msg.to || "", msg.message || "error del servidor");
    }
  }

  async onDeliver(sender, payload, queuedAt) {
    const kind = payload?.kind;
    try {
      if (kind === "hs1") this.onHs1(sender, payload);
      else if (kind === "hs2") this.onHs2(sender, payload);
      else if (kind === "reset") this.sessions.delete(sender);
      else if (kind === "msg") {
        const s = this.sessions.get(sender);
        if (!s) {
          // Su sesión es de antes de que nos reconectáramos: que negocie otra.
          this.send({ type: "send", to: sender, payload: { kind: "reset" } });
          throw new CryptoError("llegó un mensaje de una sesión caducada; pídele que lo reenvíe");
        }
        const before = s.lost;
        const text = s.decrypt(payload);
        if (s.lost > before) this.emit("warning", sender, `se perdieron ${s.lost - before} mensaje(s) de ${sender}`);
        this.onContent(sender, text, null);
      } else if (kind === "sealed") {
        const { text, ident } = openSealed(this.name, this.identity, sender, payload, this.prekeys, this.contacts.pinned(sender));
        this.contacts.pin(sender, ident);
        this.onContent(sender, text, queuedAt);
      } else throw new CryptoError(`tipo de payload desconocido: ${kind}`);
    } catch (e) {
      if (!(e instanceof CryptoError)) throw e;
      if (e instanceof IdentityMismatch || kind === "hs2") this.pending.get(sender)?.reject(e);
      if (e instanceof IdentityMismatch) this.emit("identity_changed", sender, e.message);
      else this.emit("warning", sender, `No se pudo leer un mensaje de ${sender}: ${e.message}`);
    }
  }

  onContent(sender, text, queuedAt) {
    const c = decodeContent(text);
    if (c.t === "receipt") return this.emit("receipt", sender, c.s, c);
    if (c.t === "profile") this.emit("profile", sender, "", { name: c.name, bio: c.bio, avatar: c.avatar });
    else this.emit("message", sender, c.t === "text" ? c.body : "", c, queuedAt);
  }

  onHs1(sender, hs1) {
    if (this.pending.has(sender) && this.name < sender) return; // apertura simultánea
    const [session, hs2] = Session.accept(this.name, this.identity, sender, hs1, this.contacts.pinned(sender));
    this.contacts.pin(sender, session.peerIdentity);
    this.sessions.set(sender, session);
    this.online.set(sender, true);
    this.send({ type: "send", to: sender, payload: hs2 });
    this.pending.get(sender)?.resolve(session);
    this.emit("session", sender, "sesión iniciada");
    this.sendProfile(sender);
  }

  onHs2(sender, hs2) {
    const p = this.pending.get(sender);
    if (!p) throw new CryptoError("hs2 no solicitado");
    p.session.complete(hs2, this.contacts.pinned(sender));
    this.contacts.pin(sender, p.session.peerIdentity);
    this.sessions.set(sender, p.session);
    this.online.set(sender, true);
    p.resolve(p.session);
    this.emit("session", sender, "sesión iniciada");
    this.sendProfile(sender);
  }

  emit(kind, peer = "", text = "", content = null, queuedAt = null) { this.onEvent({ kind, peer, text, content, queuedAt }); }

  send(msg) {
    if (this.ws?.readyState !== 1) throw new ClientError("no conectado");
    this.ws.send(JSON.stringify(msg));
  }
}
