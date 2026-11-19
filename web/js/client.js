// Lógica de red del cliente web (equivalente a securechat/client.py).
// No toca el DOM: la interfaz recibe eventos por `onEvent`.

import { b64d, b64e, CryptoError, equal, IdentityMismatch, signAuth } from "./protocol.js";
import { decryptFrom, DeviceKeys, encryptFor, initiate } from "./ratchet.js";

export class ClientError extends Error {
  constructor(message, code = null) { super(message); this.code = code; }
}

export const IMAGE_MIME = ["image/png", "image/jpeg", "image/gif", "image/webp"];
export const VIDEO_MIME = ["video/mp4", "video/webm", "video/quicktime"];
export const MAX_MEDIA = 8 * 1024 * 1024;

// Relleno (padding): todo mensaje cifrado ocupa uno de estos tamaños, para que quien
// vea el tráfico no pueda distinguir un «ok» de un párrafo por su longitud.
const PAD_BUCKETS = [256, 1024, 4096, 16384, 65536];
const PAD_BLOCK = 65536; // a partir de aquí (fotos, archivos), múltiplos de 64 KB
const PAD_FIELD = 9;     // ,"pad":""

/** Añade un campo "pad" de espacios para que el JSON (en bytes UTF-8) mida justo un tamaño fijo. */
export function padJson(json) {
  if (!json.startsWith("{") || !json.endsWith("}") || json.length < 3) return json;
  const len = new TextEncoder().encode(json).length;
  const need = len + PAD_FIELD;
  const target = PAD_BUCKETS.find((b) => b >= need) ?? Math.ceil(need / PAD_BLOCK) * PAD_BLOCK;
  return `${json.slice(0, -1)},"pad":"${" ".repeat(target - need)}"}`;
}

export const TIMER_OPTIONS = [0, 86400, 604800, 7776000];
const CALL_KINDS = new Set(["offer", "answer", "reject", "end", "busy", "taken", "ring", "joined", "here", "left"]);

export const AUDIO_MIME = ["audio/webm", "audio/ogg", "audio/mp4", "audio/mpeg", "audio/aac"];
const ID_RE = /^[A-Za-z0-9_-]{8,32}$/;
const NAME_OK = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9_]$/;

/**
 * Valida el contenido descifrado (ver securechat/content.py). Nunca confiamos en él:
 * todo lo que no encaja se descarta o se recorta.
 *
 * Campos comunes opcionales:
 *   mid   identificador del mensaje (para checks, respuestas, reacciones…)
 *   g     id del grupo, si el mensaje es de un grupo
 *   reply {mid, from, text}: el mensaje al que responde
 */
export function decodeContent(plaintext) {
  let c;
  try { c = JSON.parse(plaintext); } catch { return { t: "text", body: plaintext }; }
  if (!c || typeof c !== "object" || typeof c.t !== "string") return { t: "text", body: plaintext };
  const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  const id = (v) => (typeof v === "string" && ID_RE.test(v) ? v : null);
  const common = { mid: id(c.mid), g: id(c.g), fwd: c.fwd === true ? true : null,
    exp: Number.isInteger(c.exp) && TIMER_OPTIONS.includes(c.exp) && c.exp > 0 ? c.exp : null,
    once: c.once === true && (c.t === "image" || c.t === "video") ? true : null };
  if (c.reply && typeof c.reply === "object" && id(c.reply.mid)) {
    common.reply = { mid: c.reply.mid, from: str(c.reply.from, 32), text: str(c.reply.text, 120) };
  }
  const out = (o) => Object.fromEntries(Object.entries({ ...o, ...common }).filter(([, v]) => v != null));
  switch (c.t) {
    case "text": {
      // Vista previa del enlace generada por quien lo envía: solo texto y una miniatura JPEG pequeña
      const lp = c.lp && typeof c.lp === "object" && typeof c.lp.url === "string" && /^https?:\/\//.test(c.lp.url)
        ? Object.fromEntries(Object.entries({ url: str(c.lp.url, 2000), title: str(c.lp.title, 200), desc: str(c.lp.desc, 300),
          site: str(c.lp.site, 80), img: typeof c.lp.img === "string" && c.lp.img.length < 120000 && /^[A-Za-z0-9+/=]+$/.test(c.lp.img) ? c.lp.img : null })
          .filter(([, v]) => v)) : null;
      return out({ t: "text", body: str(c.body, 20000), lp });
    }
    case "sticker": return out({ t: "sticker", id: str(c.id, 16) });
    case "image": case "video": case "audio": {
      const allowed = { image: IMAGE_MIME, video: VIDEO_MIME, audio: AUDIO_MIME }[c.t];
      const mime = str(c.mime, 60).split(";")[0];
      if (!allowed.includes(mime) || typeof c.data !== "string") return out({ t: "unsupported" });
      const dur = Number.isFinite(c.dur) ? Math.max(0, Math.min(3600, c.dur)) : undefined;
      return out({ t: c.t, mime, name: str(c.name, 120), data: c.data, dur });
    }
    case "file": {
      if (typeof c.data !== "string") return out({ t: "unsupported" });
      const size = Number.isFinite(c.size) ? Math.max(0, Math.min(MAX_MEDIA, Math.round(c.size))) : undefined;
      return out({ t: "file", mime: str(c.mime, 100).split(";")[0] || "application/octet-stream",
        name: str(c.name, 120) || "archivo", size, data: c.data });
    }
    case "poll": {
      const opts = Array.isArray(c.opts) ? c.opts.filter((o) => typeof o === "string" && o.trim()).map((o) => o.slice(0, 100)).slice(0, 12) : [];
      if (opts.length < 2) return out({ t: "unsupported" });
      return out({ t: "poll", q: str(c.q, 200), opts, multi: c.multi === true });
    }
    case "vote": {
      if (!id(c.target)) return { t: "ignore" };
      const choices = Array.isArray(c.choices) ? [...new Set(c.choices.filter((n) => Number.isInteger(n) && n >= 0 && n < 12))] : [];
      return out({ t: "vote", target: c.target, choices });
    }
    case "timer": return TIMER_OPTIONS.includes(c.secs) ? out({ t: "timer", secs: c.secs }) : { t: "ignore" };
    case "join": return id(c.g) && typeof c.token === "string" ? { t: "join", g: c.g, token: c.token.slice(0, 64) } : { t: "ignore" };
    case "call": {
      if (!CALL_KINDS.has(c.kind) || !id(c.id)) return { t: "ignore" };
      return { t: "call", kind: c.kind, id: c.id, sdp: str(c.sdp, 30000), video: c.video === true, dev: str(c.dev, 40),
        ...(id(c.g) ? { g: c.g } : {}) };
    }
    case "profile": {
      const avatar = typeof c.avatar === "string" && c.avatar.length < 200000 ? c.avatar : null;
      return { t: "profile", name: str(c.name, 64).trim(), bio: str(c.bio, 140).trim(), avatar };
    }
    case "receipt": {
      const ids = Array.isArray(c.ids) ? c.ids.filter((x) => ID_RE.test(x)).slice(0, 500) : [];
      return out({ t: "receipt", ids, s: c.s === "read" ? "read" : "delivered" });
    }
    // Acciones sobre un mensaje anterior (target = su mid)
    case "react": return id(c.target) ? out({ t: "react", target: c.target, emoji: str(c.emoji, 16) }) : { t: "ignore" };
    case "edit": return id(c.target) ? out({ t: "edit", target: c.target, body: str(c.body, 20000) }) : { t: "ignore" };
    case "delete": return id(c.target) ? out({ t: "delete", target: c.target }) : { t: "ignore" };
    case "typing": return out({ t: "typing", on: c.on !== false });
    // Grupos: el estado del grupo lo manda su administrador a cada miembro
    case "group": {
      if (!id(c.g)) return { t: "ignore" };
      const members = Array.isArray(c.members) ? [...new Set(c.members.filter((m) => NAME_OK.test(m)))].slice(0, 64) : [];
      const avatar = typeof c.avatar === "string" && c.avatar.length < 200000 ? c.avatar : null;
      const inGroup = (list) => (Array.isArray(list) ? [...new Set(list.filter((m) => members.includes(m)))] : []);
      return { t: "group", g: c.g, name: str(c.name, 64).trim() || "Grupo", members, admin: str(c.admin, 32),
        admins: inGroup(c.admins), muted: inGroup(c.muted), v: Number.isFinite(c.v) ? c.v : 0, avatar };
    }
    case "group-leave": return id(c.g) ? { t: "group-leave", g: c.g } : { t: "ignore" };
    default: return out({ t: "unsupported" });
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

const DEVICE_CACHE_MS = 60_000;
const SILENT_TYPES = new Set(["receipt", "profile", "typing", "group-leave", "vote", "join"]);

/**
 * Protocolo v2 (ver securechat/ratchet.py): cada mensaje se cifra con Double Ratchet
 * para CADA dispositivo del destinatario, y se manda una copia ("sync") a mis otros
 * dispositivos. La primera vez con un dispositivo se usa X3DH con sus prekeys, así
 * que da igual que esté conectado o no.
 */
export class ChatClient {
  constructor(name, identity, contacts, onEvent = () => {}, { keys = null, code = null } = {}) {
    Object.assign(this, { name, identity, contacts, onEvent, code });
    this.keys = keys || new DeviceKeys(name, identity, null);
    this.myDevices = [];
    this.requests = new Map();
    this.nextId = 0;
    this.known = new Map();          // minúsculas -> grafía oficial
    this.online = new Map();         // peer -> bool
    this.deviceCache = new Map();    // peer (minúsculas) -> {user, ik, list, bundles, at}
    this.profileSent = new Set();    // contactos que ya tienen mi perfil en esta conexión
    this.queue = Promise.resolve();  // los envíos van en orden (el ratchet lo necesita)
    this.ws = null;
    this.profile = null;
  }

  get device() { return this.keys.device; }

  /**
   * Conecta y se autentica. Al crear cuenta, si el servidor pide verificar un correo,
   * se llama a `onVerify(destino, error)`, que debe devolver el código recibido.
   */
  connect(url, { email = null, onVerify = null } = {}) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      this.ws = ws;
      let stage = "hello";
      // Cada conexión habla por su propio canal (por si hubiera otra más nueva en marcha)
      const own = (msg) => { if (ws.readyState === 1) ws.send(JSON.stringify(msg)); };
      ws.onopen = () => own({ type: "hello", user: this.name, code: this.code, email, device: this.device,
        identity_key: b64e(this.identity.publicKey) });
      ws.onerror = () => { if (stage === "hello" || stage === "auth") reject(new ClientError("no se pudo conectar con el servidor", "down")); };
      ws.onclose = (ev) => {
        if (stage === "hello" || stage === "auth") reject(new ClientError("el servidor cerró la conexión", "down"));
        for (const p of this.requests.values()) p.reject(new ClientError("conexión cerrada"));
        this.requests.clear();
        // 4000 = la cuenta se ha abierto otra vez en ESTE dispositivo (otra pestaña)
        if (stage === "ready" && this.ws === ws) this.emit("disconnected", "", ev.code === 4000 ? "replaced" : ev.code === 4001 ? "removed" : ev.code === 4002 ? "deleted" : "");
      };
      ws.onmessage = async (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (stage === "hello") {
          if (msg.type !== "challenge") { stage = "failed"; return reject(new ClientError(msg.message || "respuesta inesperada", msg.code)); }
          own({ type: "auth", sig: b64e(signAuth(this.identity, b64d(msg.nonce), this.name)) });
          stage = "auth";
        } else if (stage === "auth" && (msg.type === "verify_needed" || msg.type === "verify_failed")) {
          if (!onVerify) { stage = "failed"; ws.close(); return reject(new ClientError("este servidor pide verificar tu correo", "email_required")); }
          if (msg.type === "verify_needed") this.verifyTarget = msg.to;
          try { own({ type: "verify", code: await onVerify(this.verifyTarget, msg.type === "verify_failed" ? msg.message : null) }); }
          catch (e) { stage = "failed"; ws.close(); reject(e); }
        } else if (stage === "auth") {
          if (msg.type !== "welcome") { stage = "failed"; return reject(new ClientError(msg.message || "autenticación rechazada", msg.code)); }
          stage = "ready";
          this.name = this.keys.user = msg.user; // grafía oficial registrada en el servidor
          this.myDevices = msg.devices || [];
          this.hasEmail = !!msg.has_email;
          this.emailAvailable = !!msg.email_available;
          this.deviceCache.clear();
          this.profileSent.clear();
          this.request(this.keys.uploadMessage(msg.opks || 0)).catch(() => {});
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
      try { this.send({ ...msg, id }); } catch (e) { this.requests.get(id)?.reject(e); }
    });
  }

  /** ¿Existe el usuario? → {exists, user (grafía oficial), online, lastSeen} */
  async lookup(name) {
    const r = await this.request({ type: "lookup", user: name }, 5000);
    if (r.exists) { this.known.set(name.toLowerCase(), r.user); this.online.set(r.user, r.online); }
    return { exists: r.exists, user: r.user, online: r.online, away: !!r.away, lastSeen: r.last_seen ?? null };
  }

  async resolve(name) {
    if (name.toLowerCase() === this.name.toLowerCase()) return this.name;
    if (this.known.has(name.toLowerCase())) return this.known.get(name.toLowerCase());
    if (this.contacts.get(name)) return name;
    const info = await this.lookup(name);
    if (!info.exists) throw new ClientError(`El usuario @${name} no existe`);
    return info.user;
  }

  async devices() { return (await this.request({ type: "devices" })).devices; }
  async removeDevice(device) { await this.request({ type: "remove-device", device }); }

  /** Dispositivos de un usuario con sus prekeys (cada petición consume una OPK por dispositivo). */
  async peerDevices(peer, refresh = false) {
    const k = peer.toLowerCase();
    const c = this.deviceCache.get(k);
    if (c && !refresh && Date.now() - c.at < DEVICE_CACHE_MS) return c;
    const r = await this.request({ type: "bundle", user: peer });
    if (!r.exists) throw new ClientError(`El usuario @${peer} no existe`);
    const ik = b64d(r.identity_key);
    if (k !== this.name.toLowerCase()) {
      const pinned = this.contacts.pinned(r.user);
      if (pinned && !equal(pinned, ik)) throw new IdentityMismatch(r.user, pinned, ik);
      this.contacts.pin(r.user, ik);
    }
    const info = { user: r.user, ik, list: r.devices.map((d) => d.device),
      bundles: Object.fromEntries(r.devices.map((d) => [d.device, d])), at: Date.now() };
    this.deviceCache.set(k, info);
    return info;
  }

  sendText(peer, text) { return this.sendContent(peer, { t: "text", body: text }); }

  /**
   * Cifra y envía a todos los dispositivos de `name` (y una copia a los míos).
   * Devuelve {peer, status}: "delivered" si algún dispositivo lo tiene ya, si no "queued".
   */
  sendContent(name, content, { ephemeral = false, sync = true } = {}) {
    const job = this.queue.then(() => this._send(name, content, { ephemeral, sync }));
    this.queue = job.catch(() => {});
    return job;
  }

  async _send(name, content, { ephemeral, sync }) {
    const peer = await this.resolve(name);
    if (peer.toLowerCase() === this.name.toLowerCase()) throw new ClientError("no puedes escribirte a ti mismo");
    const plaintext = JSON.stringify(content);
    const silent = SILENT_TYPES.has(content.t);
    const statuses = await this.sendToUser(peer, plaintext, { silent, ephemeral });
    if (sync && !ephemeral && content.t !== "receipt" && this.myDevices.length) {
      await this.sendToUser(this.name, JSON.stringify({ t: "sync", to: peer, c: content }), { silent: true, ephemeral: false });
    }
    // La primera vez en esta conexión, le mandamos también nuestro perfil (cifrado)
    if (!silent && !ephemeral && this.profile && !this.profileSent.has(peer)) {
      this.profileSent.add(peer);
      this.sendToUser(peer, JSON.stringify({ t: "profile", ...this.profile }), { silent: true, ephemeral: false }).catch(() => this.profileSent.delete(peer));
    }
    return { peer, status: statuses.includes("delivered") ? "delivered" : "queued" };
  }

  async sendToUser(user, plaintext, { silent, ephemeral }) {
    const mine = user.toLowerCase() === this.name.toLowerCase();
    let info = mine ? null : await this.peerDevices(user);
    const targets = mine ? [...this.myDevices] : [...info.list];
    plaintext = padJson(plaintext);
    const tried = new Set();
    const statuses = [];
    while (targets.length) {
      const dev = targets.shift();
      if (tried.has(dev)) continue;
      tried.add(dev);
      let r = this.keys.session(user, dev);
      if (!r) {
        if (ephemeral) continue; // "escribiendo…" no merece abrir sesión
        if (!info || !info.bundles[dev]) info = await this.peerDevices(user, true);
        const bundle = info.bundles[dev];
        if (!bundle) continue; // ese dispositivo aún no ha publicado sus prekeys
        r = initiate(this.name, this.device, this.identity, mine ? this.name : user, dev, info.ik, bundle,
          mine ? null : this.contacts.pinned(user));
        this.keys.pushNew(user, dev, r);
      }
      const payload = encryptFor(this.device, r, plaintext);
      this.keys.store(user, dev, r);
      let ack;
      try {
        ack = await this.request({ type: "send", to: user, device: dev, payload, ...(silent ? { silent: true } : {}), ...(ephemeral ? { ephemeral: true } : {}) });
      } catch (e) {
        if (e.code === "no_device") { this.keys.drop(user, dev); continue; }
        throw e;
      }
      statuses.push(ack.status);
      // ¿Tiene dispositivos que no conocíamos? También se lo mandamos a ellos
      const fresh = (ack.devices || []).filter((d) => d !== this.device && !tried.has(d) && !targets.includes(d));
      if (fresh.length) {
        if (mine) this.myDevices = ack.devices.filter((d) => d !== this.device);
        else info = await this.peerDevices(user, true);
        targets.push(...fresh);
      }
    }
    return statuses;
  }

  /** "Escribiendo…": solo a dispositivos con los que ya hay sesión, nunca se guarda en cola. */
  sendLive(peer, content) {
    this.sendContent(peer, content, { ephemeral: true, sync: false }).catch(() => {});
    return true;
  }

  /** Notificaciones con la app cerrada: registra (o quita) este dispositivo. */
  setPushSubscription(sub) { try { this.send({ type: "push-sub", sub }); } catch { /* al reconectar */ } }
  removePushSubscription(endpoint) { try { this.send({ type: "push-unsub", endpoint }); } catch { /* */ } }

  /** Privacidad: si ocultas tu "última vez", el servidor no la comparte con nadie. */
  /** status: "online" | "away" | "invisible" (invisible = los demás te ven desconectado) */
  setPrivacy({ lastSeen, status = "online" }) {
    try { this.send({ type: "privacy", last_seen: !!lastSeen, status }); } catch { /* se envía al reconectar */ }
  }

  /** Cambia mi perfil y se lo envía (cifrado) a mis contactos. */
  setProfile(profile, to = []) {
    this.profile = profile;
    this.profileSent.clear();
    for (const peer of to) {
      this.profileSent.add(peer);
      this.sendContent(peer, { t: "profile", ...profile }, { sync: false }).catch(() => this.profileSent.delete(peer));
    }
  }

  who() {
    return new Promise((resolve, reject) => {
      this.whoResolve = resolve;
      setTimeout(() => reject(new ClientError("sin respuesta")), 5000);
      this.send({ type: "who" });
    });
  }

  async dispatch(msg) {
    const req = msg.id != null ? this.requests.get(msg.id) : null;
    if (msg.type === "deliver") return this.onDeliver(msg.from, msg.payload, msg.queued_at);
    if (msg.type === "presence") {
      this.online.set(msg.user, msg.online);
      return this.emit("presence", msg.user, msg.online ? "online" : "offline", { lastSeen: msg.last_seen ?? null, away: !!msg.away });
    }
    if (msg.type === "my-devices") {
      const before = new Set(this.myDevices);
      this.myDevices = (msg.devices || []).filter((d) => d !== this.device);
      const added = this.myDevices.filter((d) => !before.has(d));
      if (added.length) this.emit("new_device", "", added.join(","));
      return;
    }
    if (req) return msg.type === "error" ? req.reject(new ClientError(msg.message || "error del servidor", msg.code)) : req.resolve(msg);
    if (msg.type === "who") return this.whoResolve?.(msg.users);
    if (msg.type === "error") this.emit("warning", msg.to || "", msg.message || "error del servidor");
  }

  onDeliver(sender, payload, queuedAt) {
    const mine = sender.toLowerCase() === this.name.toLowerCase();
    try {
      if (payload?.kind !== "dr") throw new CryptoError("formato antiguo: pídele que recargue la app");
      const pinned = mine ? this.identity.publicKey : this.contacts.pinned(sender);
      const { text, ik } = decryptFrom(this.name, this.keys, sender, payload, pinned);
      if (ik && !mine) this.contacts.pin(sender, ik);
      if (mine && !this.myDevices.includes(payload.dev)) this.myDevices.push(payload.dev);
      this.onContent(sender, text, queuedAt, mine);
    } catch (e) {
      if (!(e instanceof CryptoError)) throw e;
      if (e instanceof IdentityMismatch) this.emit("identity_changed", sender, e.message);
      else this.emit("warning", mine ? "" : sender, `No se pudo leer un mensaje de ${sender}: ${e.message}`);
    }
  }

  onContent(sender, text, queuedAt, mine) {
    let c;
    if (mine) {
      // Copia de algo que envié desde otro dispositivo
      let raw;
      try { raw = JSON.parse(text); } catch { return; }
      if (raw?.t !== "sync" || typeof raw.to !== "string") return;
      c = decodeContent(JSON.stringify(raw.c));
      if (c.t === "ignore" || c.t === "unsupported") return;
      return this.emit("sync", raw.to, "", c, queuedAt);
    }
    c = decodeContent(text);
    if (c.t === "ignore") return;
    if (c.mid && !this.keys.firstTime(`${sender}|${c.mid}`) && c.t !== "receipt") return; // repetido
    if (c.t === "receipt") return this.emit("receipt", sender, c.s, c);
    if (c.t === "profile") return this.emit("profile", sender, "", { name: c.name, bio: c.bio, avatar: c.avatar });
    this.emit("message", sender, c.t === "text" ? c.body : "", c, queuedAt);
  }

  emit(kind, peer = "", text = "", content = null, queuedAt = null) { this.onEvent({ kind, peer, text, content, queuedAt }); }

  send(msg) {
    if (this.ws?.readyState !== 1) throw new ClientError("no conectado");
    this.ws.send(JSON.stringify(msg));
  }
}
