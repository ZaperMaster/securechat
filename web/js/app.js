// Interfaz web. Toda la criptografía ocurre aquí, en el navegador:
// el servidor solo recibe mensajes ya cifrados (texto, fotos, vídeos y perfiles).

import { ChatClient, ClientError, Contacts, IMAGE_MIME, MAX_MEDIA, VIDEO_MIME } from "./client.js";
import { EMOJIS, STICKERS } from "./emoji.js";
import * as P from "./protocol.js";
import { DeviceKeys } from "./ratchet.js";
import { icon } from "./icons.js";
import * as Vault from "./vault.js";

const $ = (id) => document.getElementById(id);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9_]$/;
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
};
const idKey = (name) => `sc:identity:${name.toLowerCase()}`;
const newId = () => sodium.to_base64(sodium.randombytes_buf(12), sodium.base64_variants.URLSAFE_NO_PADDING);

let me = null;          // mi @usuario (grafía oficial)
let identity = null;    // {seed, publicKey, privateKey}
let profile = null;     // {name, bio, avatar}: lo que ven los demás
let client = null;
let history = null;     // historial cifrado en este dispositivo
let active = null;      // conversación abierta
let connected = false;
let replaced = false;   // la cuenta se abrió en otra pestaña o dispositivo
let connecting = false; // hay un intento de conexión en curso (nunca dos a la vez)
const chats = new Map(); // peer -> {messages: [], online: bool|null}
let reconnectTimer = null;
let serverConfig = { code_required: false, email_required: false };
const prefs = () => window.SC_PREFS();

// ---------------------------------------------------------------- acceso

// Pantalla de acceso con dos modos: "login" (principal) y "register"
let authMode = "login";

function setAuthMode(mode) {
  authMode = mode;
  $("login-form").dataset.mode = mode;
  $("login-error").textContent = "";
  updateLoginMode();
  $("login-name").focus();
}

function updateLoginMode() {
  const reg = authMode === "register";
  const name = $("login-name").value.trim();
  $("auth-title").textContent = reg ? "Crear cuenta" : "Iniciar sesión";
  $("auth-sub").textContent = reg
    ? "Elige tu @usuario y una contraseña. Después podrás poner tu nombre visible y una foto."
    : "Entra con tu usuario y contraseña desde cualquier dispositivo.";
  $("login-pass2").required = reg;
  $("login-email-wrap").hidden = !(reg && serverConfig.email_required);
  $("login-email").required = reg && serverConfig.email_required;
  $("login-btn").textContent = reg ? "Crear cuenta" : "Entrar";
  $("login-pass").autocomplete = reg ? "new-password" : "current-password";
  $("login-hint").textContent = name && !NAME_RE.test(name) ? "3-32 caracteres: letras, números, '_', '.' o '-'."
    : reg ? "Si olvidas la contraseña no se puede recuperar: nadie (ni el servidor) puede abrir tu cuenta sin ella." : "";
  $("login-remember-wrap").hidden = !Vault.canRemember();
}

/** Busca la copia cifrada de la cuenta: primero en este dispositivo y si no, en el servidor. */
async function findKeystore(name) {
  const local = store.get(idKey(name));
  if (local) return local;
  const code = encodeURIComponent($("login-code").value.trim());
  let r;
  try { r = await fetch(`keystore?user=${encodeURIComponent(name)}&code=${code}`, { cache: "no-store" }); }
  catch { throw Object.assign(new Error("No se puede conectar con el servidor."), { code: "down" }); }
  if (r.status === 404) return null;
  if (r.status === 403) throw Object.assign(new Error("bad code"), { code: "bad_code" });
  if (r.status === 429) throw new Error("Demasiados intentos. Espera un minuto.");
  if (!r.ok) throw new Error("El servidor no ha podido responder. Inténtalo de nuevo.");
  const { user, blob } = await r.json();
  return { ...blob, username: user };
}

async function onLogin(ev) {
  ev.preventDefault();
  const name = $("login-name").value.trim().replace(/^@/, "");
  const pass = $("login-pass").value;
  const reg = authMode === "register";
  $("login-error").textContent = "";
  $("login-btn").disabled = true;
  $("login-btn").textContent = reg ? "Creando cuenta…" : "Comprobando…";
  await new Promise((r) => setTimeout(r, 30)); // deja pintar antes de Argon2id
  try {
    if (serverConfig.code_required) store.set("sc:code", $("login-code").value.trim());
    if (reg) {
      if (pass !== $("login-pass2").value) throw new Error("Las contraseñas no coinciden.");
      if (store.get(idKey(name))) throw new Error(`Ya tienes la cuenta @${name} en este dispositivo. Inicia sesión.`);
      const blob = { ...P.saveIdentity(P.newIdentitySeed(), pass), username: name };
      identity = P.loadIdentity(blob, pass);
      // La cuenta solo se guarda si el servidor acepta el nombre (y el correo)
      await startApp(name, { mustConnect: true, email: $("login-email").value.trim() || null, blob });
    } else {
      const blob = await findKeystore(name);
      if (!blob) throw new Error("Usuario o contraseña incorrectos.");
      $("login-btn").textContent = "Abriendo tu cuenta…";
      await new Promise((r) => setTimeout(r, 30));
      try { identity = P.loadIdentity(blob, pass); }
      catch { throw new Error("Usuario o contraseña incorrectos."); }
      store.set(idKey(blob.username || name), blob);
      await startApp(blob.username || name, { blob });
    }
    if ($("login-remember").checked) await Vault.remember(me, identity.seed);
    $("login-pass").value = $("login-pass2").value = "";
  } catch (e) {
    identity = null;
    client = null;
    hideVerify();
    if (e.code === "down") { showDown(true); return; }
    $("login-error").textContent = /en uso/.test(e.message) ? `El usuario @${name} ya existe. Elige otro nombre o inicia sesión.`
      : e.code === "bad_code" ? "Código de acceso incorrecto. Pídeselo a quien gestiona el servidor." : e.message;
  } finally {
    $("login-btn").disabled = false;
    updateLoginMode();
  }
}

/** Pide al usuario el código que le llegó por correo. */
function askVerifyCode(to, error) {
  return new Promise((resolve, reject) => {
    $("login-form").hidden = true;
    $("verify-step").hidden = false;
    $("verify-to").textContent = to;
    $("verify-error").textContent = error || "";
    $("verify-code").value = "";
    $("verify-code").focus();
    $("verify-form").onsubmit = (e) => { e.preventDefault(); resolve($("verify-code").value.trim()); };
    $("verify-cancel").onclick = () => { hideVerify(); reject(new Error("Has cancelado la verificación.")); };
  });
}

function hideVerify() {
  $("verify-step").hidden = true;
  $("login-form").hidden = false;
}

/** Las claves del dispositivo van cifradas con una clave derivada de la identidad. */
const deviceKey = () => P.kdf(identity.seed, "sc-storage-v2");

function loadDeviceData(username) {
  const raw = store.get(`sc:device:${username.toLowerCase()}`);
  if (!raw) return null;
  try {
    const box = P.b64d(raw);
    return JSON.parse(new TextDecoder().decode(sodium.crypto_secretbox_open_easy(box.subarray(24), box.subarray(0, 24), deviceKey())));
  } catch { return null; }
}

let savePending = null;
function saveDeviceData(username, data) {
  // Se guarda como mucho una vez por "tick": cada mensaje cambia el ratchet
  savePending = { username, data };
  queueMicrotask(() => {
    if (!savePending) return;
    const { username: u, data: d } = savePending;
    savePending = null;
    const nonce = sodium.randombytes_buf(24);
    const ct = sodium.crypto_secretbox_easy(new TextEncoder().encode(JSON.stringify(d)), nonce, deviceKey());
    const out = new Uint8Array(24 + ct.length);
    out.set(nonce); out.set(ct, 24);
    store.set(`sc:device:${u.toLowerCase()}`, P.b64e(out));
  });
}

async function startApp(username, { mustConnect = false, email = null, blob = null } = {}) {
  const contacts = new Contacts(store.get(`sc:contacts:${username.toLowerCase()}`) || {}, (data) => {
    store.set(`sc:contacts:${(me || username).toLowerCase()}`, data);
    renderContacts();
    renderHeader();
  });
  const keys = new DeviceKeys(username, identity, loadDeviceData(username), (data) => saveDeviceData(me || username, data));
  client = new ChatClient(username, identity, contacts, onEvent, { keys, code: store.get("sc:code") });
  me = username;
  if (mustConnect) {
    connecting = true;
    try { await client.connect(wsUrl(), { email, onVerify: askVerifyCode }); }
    finally { connecting = false; }
    me = client.name;
    connected = true;
    if (blob) store.set(idKey(me), { ...blob, username: me });
  }
  history = new Vault.History(me, identity.seed);
  loadGroups();
  profile = store.get(`sc:profile:${me.toLowerCase()}`) || { name: me, bio: "", avatar: null };
  client.profile = profile;
  store.set("sc:last", me);
  chats.clear();
  for (const [peer, list] of await history.loadAll()) chats.set(peer, { messages: list, online: null });
  hideVerify();
  $("login").hidden = true;
  $("app").hidden = false;
  renderMe();
  renderContacts();
  renderChat();
  updateTitle();
  if (connected) onConnected();
  else reconnect();
}

const wsUrl = () => `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/`;

async function reconnect() {
  if (!client || connecting || connected) return;
  clearTimeout(reconnectTimer);
  connecting = true;
  try {
    await client.connect(wsUrl());
    me = client.name;
    connected = true;
    onConnected();
  } catch (e) {
    connected = false;
    setConn(false);
    if (e.code === "bad_code" || e.code === "name_taken") {
      // El servidor cambió de código (o de dueño): volver a la pantalla de acceso
      logout({ keepSession: true });
      $("login-error").textContent = e.code === "bad_code"
        ? "El servidor ha cambiado su código de acceso. Pide el nuevo a quien lo gestiona."
        : e.message;
      return;
    }
    if (e.code === "down") probe().then((ok) => { if (!ok) showDown(true); });
    scheduleReconnect();
  } finally {
    connecting = false;
  }
}

function onConnected() {
  setupPush();
  client.setPrivacy({ lastSeen: prefs().lastSeen });
  // Copia de la clave cifrada con tu contraseña: permite iniciar sesión desde otro dispositivo
  const blob = store.get(idKey(me));
  if (blob) { try { client.send({ type: "keystore", blob }); } catch { /* se reintentará */ } }
  replaced = false;
  $("replaced-banner").hidden = true;
  setConn(true);
  showDown(false);
  renderHeader();
  flushAll();
  if (active) markRead(active);
}

function scheduleReconnect(ms = 3000) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(reconnect, ms);
}

/** En móvil la conexión se corta al pasar la app a segundo plano: al volver, reconectamos ya. */
function wakeUp() {
  if (client && !connected && !replaced && !connecting) scheduleReconnect(50);
}

/** "Usar aquí": recupera la cuenta en este dispositivo (la otra pestaña quedará en pausa). */
function useHere() {
  replaced = false;
  $("replaced-banner").hidden = true;
  reconnect();
}

// ---------------------------------------------------- servicio caído

let downTimer = null;

/** Comprueba si el servidor responde. Devuelve true/false. */
async function probe() {
  try {
    const r = await fetch(`config.json?t=${Date.now()}`, { cache: "no-store" });
    if (!r.ok) return false;
    serverConfig = await r.json();
    $("login-code-wrap").hidden = !serverConfig.code_required;
    $("login-code").required = serverConfig.code_required;
    updateLoginMode();
    return true;
  } catch {
    return false;
  }
}

function showDown(down) {
  // Con la sesión iniciada no tapamos la app: se puede leer el historial y escribir
  // (los mensajes esperan en la bandeja de salida). Basta con la franja de aviso.
  $("down").hidden = !down || !!client;
  $("offline-banner").textContent = down
    ? "El servicio no está disponible: quien lo gestiona tiene que ponerlo en marcha. Tus mensajes se enviarán al volver."
    : "Sin conexión. Reconectando…";
  clearTimeout(downTimer);
  if (down) {
    downTimer = setTimeout(async () => {
      if (await probe()) { showDown(false); if (client) reconnect(); }
      else showDown(true);
    }, 4000);
  }
}

function setConn(on) {
  $("conn").textContent = on ? "En línea" : "Conectando…";
  $("conn").className = `conn ${on ? "on" : "off"}`;
  $("offline-banner").hidden = on;
}

/** Cierra la sesión. Con keepSession no olvida la clave recordada (cambio de código). */
async function logout({ keepSession = false } = {}) {
  clearTimeout(reconnectTimer);
  const c = client;
  client = null;
  connected = false;
  c?.close();
  if (!keepSession && me) { await removePush(); await Vault.forget(me); }
  for (const ch of chats.values()) for (const m of ch.messages) if (m.url) URL.revokeObjectURL(m.url);
  identity = null; me = null; active = null; profile = null; history = null;
  chats.clear();
  $("messages").replaceChildren();
  $("contacts").replaceChildren();
  $("picker").hidden = true;
  $("replaced-banner").hidden = true;
  replaced = false;
  $("app").hidden = true;
  $("app").classList.remove("in-chat");
  $("login").hidden = false;
  authMode = "login";
  $("login-form").dataset.mode = "login";
  updateLoginMode();
}

// ------------------------------------------------------------- nombres

const displayName = (peer) => {
  const c = client?.contacts.get(peer);
  return c?.nick || c?.displayName || peer;
};
const avatarOf = (peer) => client?.contacts.get(peer)?.avatar || null;

/** Avatar: la foto si la hay; si no, la inicial con un color estable según el nombre. */
function setAvatar(el, name, photo) {
  el.replaceChildren();
  el.classList.toggle("has-photo", !!photo);
  if (photo) {
    const img = document.createElement("img");
    img.src = `data:image/jpeg;base64,${photo}`;
    img.alt = "";
    el.append(img);
  } else {
    let h = 0;
    for (const ch of name) h = (h * 31 + ch.codePointAt(0)) % 360;
    el.textContent = [...name][0] || "?";
    el.style.setProperty("--h", h); // CSSOM: permitido por la CSP
  }
  return el;
}

// ------------------------------------------------------------ mensajes

// =========================================================== conversaciones
// Una conversación es un contacto ("ana") o un grupo ("#<id>"). Los grupos no
// existen para el servidor: cada mensaje se cifra por separado para cada miembro.

const isGroup = (conv) => typeof conv === "string" && conv.startsWith("#");
const gidOf = (conv) => conv.slice(1);
const same = (a, b) => a?.toLowerCase() === b?.toLowerCase();
let groups = new Map(); // gid -> {id, name, members, admin, v, avatar, left}

function loadGroups() { groups = new Map(Object.entries(store.get(`sc:groups:${me.toLowerCase()}`) || {})); }
function saveGroups() { store.set(`sc:groups:${me.toLowerCase()}`, Object.fromEntries(groups)); }

function chat(conv) {
  if (!chats.has(conv)) chats.set(conv, { messages: [], online: null, lastSeen: null, typing: new Map() });
  const c = chats.get(conv);
  c.typing ??= new Map();
  return c;
}

const unreadOf = (conv) => chats.get(conv)?.messages.filter((m) => m.from === "them" && !m.read && !m.deleted).length || 0;
const convName = (conv) => (isGroup(conv) ? groups.get(gidOf(conv))?.name || "Grupo" : displayName(conv));
const convAvatar = (conv) => (isGroup(conv) ? groups.get(gidOf(conv))?.avatar || null : avatarOf(conv));

/** A quién hay que enviar un mensaje de esta conversación. */
function targetsOf(conv) {
  if (!isGroup(conv)) return [conv];
  const g = groups.get(gidOf(conv));
  return g && !g.left ? g.members.filter((x) => !same(x, me)) : [];
}

/** Añade un mensaje a la conversación, lo pinta y lo guarda cifrado. */
function addMsg(conv, entry, { persist = true } = {}) {
  const m = { id: newId(), time: new Date(), ...entry };
  chat(conv).messages.push(m);
  if (conv === active) appendMessage(m);
  renderContacts();
  updateTitle();
  if (persist) history?.put(conv, m);
  return m;
}

/** Aviso de cifrado: siempre el primero del chat, aunque ya hubiera mensajes. */
function e2eNotice(conv) {
  const t = "Los mensajes y archivos de este chat están cifrados de extremo a extremo.";
  const list = chat(conv).messages;
  if (list.some((m) => m.sys && m.sys.includes("cifrados de extremo a extremo"))) return;
  const m = { id: newId(), sys: t, time: list[0] ? new Date(list[0].time.getTime() - 1) : new Date() };
  list.unshift(m);
  history?.put(conv, m);
}

function sysOnce(conv, t) {
  if (!chat(conv).messages.some((m) => m.sys === t)) addMsg(conv, { sys: t });
}

function save(conv, m) {
  history?.put(conv, m);
  if (conv === active && m.el) rerenderMessage(m);
}

const ORDER = { sending: 0, sent: 1, delivered: 2, read: 3 };
const STATUS = {
  sending: ["clock_small", "Enviando…"],
  sent: ["check", "Enviado"],
  delivered: ["checks", "Entregado"],
  read: ["checks", "Leído"],
  failed: ["alert", "No se pudo enviar"],
};

/** Estado que se muestra: en grupos, el del miembro más "atrasado" (como WhatsApp). */
function statusOf(conv, m) {
  if (m.status === "failed" || m.status === "sending") return m.status;
  if (!isGroup(conv)) return m.status || "sent";
  const members = targetsOf(conv);
  if (!members.length) return "sent";
  return members.map((x) => m.receipts?.[x.toLowerCase()] || "sent").sort((a, b) => ORDER[a] - ORDER[b])[0];
}

function setStatus(conv, m, status) {
  if (m.status === status) return;
  if (status !== "failed" && m.status in ORDER && ORDER[status] < ORDER[m.status]) return; // nunca hacia atrás
  m.status = status;
  history?.put(conv, m);
  const el = m.el?.querySelector(".tick");
  if (el) paintTick(el, statusOf(conv, m));
  renderContacts();
}

function paintTick(el, status) {
  el.replaceChildren(icon(STATUS[status][0]));
  el.title = STATUS[status][1];
  el.setAttribute("aria-label", STATUS[status][1]);
  el.className = `tick ${status}`;
}

// ------------------------------------------------------------------ eventos

function onEvent(ev) {
  switch (ev.kind) {
    case "message": return onIncoming(ev);
    case "receipt": return onReceipt(ev);
    case "sync": return onSync(ev);
    case "profile":
      client.contacts.setProfile(ev.peer, ev.content);
      renderContacts();
      if (ev.peer === active) renderHeader();
      break;
    case "presence":
      chat(ev.peer).online = ev.text === "online";
      if (ev.content?.lastSeen) chat(ev.peer).lastSeen = ev.content.lastSeen;
      if (ev.text === "online") flushAll();
      if (ev.peer === active) renderHeader();
      break;
    case "session":
      chat(ev.peer).online = true;
      sysOnce(ev.peer, "Los mensajes y archivos de este chat están cifrados de extremo a extremo.");
      if (ev.peer === active) renderHeader();
      break;
    case "identity_changed":
      addMsg(ev.peer, { sys: `La clave de seguridad de @${ev.peer} ha cambiado. Si no ha cambiado de dispositivo, alguien podría estar suplantándole. Confírmalo con esa persona por otro medio.`, warn: true });
      break;
    case "warning":
      if (ev.peer && !/no está conectado|sesión caducada/.test(ev.text)) addMsg(ev.peer, { sys: ev.text, warn: true });
      break;
    case "disconnected":
      if (!client) break;
      connected = false;
      if (ev.text === "removed") {
        logout();
        $("login-error").textContent = "Este dispositivo se ha desvinculado de tu cuenta desde otro dispositivo.";
        break;
      }
      if (ev.text === "replaced") {
        // Otra pestaña o dispositivo ha abierto la misma cuenta: no peleamos por la conexión
        replaced = true;
        clearTimeout(reconnectTimer);
        setConn(false);
        $("conn").textContent = "Abierta en otro sitio";
        $("offline-banner").hidden = true;
        $("replaced-banner").hidden = false;
        break;
      }
      setConn(false);
      scheduleReconnect(document.hidden ? 3000 : 800);
      probe().then((ok) => { if (!ok) showDown(true); });
      break;
  }
}

/** Algo que envié yo desde otro de mis dispositivos: lo reflejamos aquí. */
function onSync(ev) {
  const c = ev.content, peer = ev.peer;
  if (c.t === "group") {
    const existing = groups.get(c.g);
    if (!existing || c.v > existing.v) {
      groups.set(c.g, { id: c.g, name: c.name, members: c.members, admin: c.admin, v: c.v, avatar: c.avatar,
        left: !c.members.some((x) => same(x, me)) });
      saveGroups();
      renderContacts();
    }
    return;
  }
  if (c.t === "group-leave") {
    const g = groups.get(c.g);
    if (g) { g.left = true; g.members = g.members.filter((x) => !same(x, me)); saveGroups(); renderContacts(); }
    return;
  }
  if (c.g && !groups.has(c.g)) return;
  const conv = c.g ? `#${c.g}` : peer;
  if (c.t === "react" || c.t === "edit" || c.t === "delete") return applyAction(conv, me, c);
  if (c.t === "typing" || c.t === "receipt" || c.t === "profile") return;
  if (c.mid && chat(conv).messages.some((m) => m.id === c.mid)) return; // ya lo tenemos
  const entry = { from: "me", content: { ...c, data: undefined }, status: "sent", to: [],
    ...(c.mid ? { id: c.mid } : {}), ...(ev.queuedAt ? { time: new Date(ev.queuedAt * 1000) } : {}),
    ...(isGroup(conv) ? { receipts: {} } : {}) };
  if (c.t === "image" || c.t === "video" || c.t === "audio") {
    const bytes = sodium.from_base64(c.data, sodium.base64_variants.ORIGINAL);
    entry.url = URL.createObjectURL(new Blob([bytes], { type: c.mime }));
    entry.hasMedia = true;
    const m = addMsg(conv, entry);
    history?.putMedia(conv, m.id, bytes);
  } else {
    addMsg(conv, entry);
  }
}

function memberOf(gid, user) {
  const g = groups.get(gid);
  return !!g && !g.left && g.members.some((x) => same(x, user));
}

async function onIncoming(ev) {
  const c = ev.content;
  const sender = ev.peer;
  if (c.t === "group") return onGroupState(sender, c);
  if (c.t === "group-leave") return onGroupLeave(sender, c.g);
  if (c.g && !memberOf(c.g, sender)) return; // grupo desconocido o no es miembro: se ignora
  const conv = c.g ? `#${c.g}` : sender;
  if (c.t === "typing") return showTyping(conv, sender, c.on);
  if (c.t === "react" || c.t === "edit" || c.t === "delete") return applyAction(conv, sender, c);
  showTyping(conv, sender, false);
  if (c.mid && chat(conv).messages.some((m) => m.id === c.mid)) {
    sendReceipt(sender, [c.mid], "delivered", c.g); // repetido (se reenvió): solo confirmamos
    return;
  }
  if (c.t === "unsupported") {
    addMsg(conv, { sys: `${displayName(sender)} envió un contenido que esta versión no puede mostrar.` });
    return;
  }
  const entry = { from: "them", sender, content: { ...c, data: undefined }, read: false,
    ...(c.mid ? { id: c.mid } : {}), ...(ev.queuedAt ? { time: new Date(ev.queuedAt * 1000) } : {}) };
  if (c.t === "image" || c.t === "video" || c.t === "audio") {
    const bytes = sodium.from_base64(c.data, sodium.base64_variants.ORIGINAL);
    entry.url = URL.createObjectURL(new Blob([bytes], { type: c.mime }));
    entry.hasMedia = true;
    const m = addMsg(conv, entry);
    history?.putMedia(conv, m.id, bytes);
  } else {
    addMsg(conv, entry);
  }
  if (c.mid) sendReceipt(sender, [c.mid], "delivered", c.g);
  if (conv === active && !document.hidden) markRead(conv);
  notify(conv, sender, c);
}

function onReceipt(ev) {
  const sender = ev.peer, c = ev.content;
  // Las confirmaciones de la terminal no dicen el grupo: buscamos el mensaje donde esté
  const convs = c.g ? [`#${c.g}`] : [sender, ...[...groups.keys()].filter((g) => memberOf(g, sender)).map((g) => `#${g}`)];
  for (const id of c.ids) {
    for (const conv of convs) {
      const m = chats.get(conv)?.messages.find((x) => x.from === "me" && x.id === id);
      if (!m) continue;
      if (isGroup(conv)) {
        m.receipts ??= {};
        const k = sender.toLowerCase();
        if (!m.receipts[k] || ORDER[c.s] > ORDER[m.receipts[k]]) m.receipts[k] = c.s;
        history?.put(conv, m);
        const el = m.el?.querySelector(".tick");
        if (el) paintTick(el, statusOf(conv, m));
        renderContacts();
      } else {
        setStatus(conv, m, c.s);
      }
      break;
    }
  }
}

/** Reacciones, ediciones y borrados que llegan de otros. */
function applyAction(conv, sender, c) {
  const m = chat(conv).messages.find((x) => x.id === c.target);
  if (!m) return;
  const author = m.from === "me" ? me : (m.sender || conv);
  if (c.t === "react") {
    m.reactions ??= {};
    if (c.emoji) m.reactions[sender.toLowerCase()] = c.emoji; else delete m.reactions[sender.toLowerCase()];
  } else if (!same(author, sender)) {
    return; // solo el autor puede editar o borrar su mensaje
  } else if (c.t === "edit" && m.content?.t === "text" && !m.deleted) {
    m.content = { ...m.content, body: c.body };
    m.edited = true;
  } else if (c.t === "delete") {
    deleteLocal(conv, m);
  }
  save(conv, m);
  renderContacts();
}

function deleteLocal(conv, m) {
  if (m.url) URL.revokeObjectURL(m.url);
  m.deleted = true;
  m.content = { t: "deleted", mid: m.content?.mid };
  m.reactions = {};
  delete m.url;
  m.hasMedia = false;
}

// "Escribiendo…": señal efímera, solo en vivo
const TYPING_MS = 6000;
function showTyping(conv, user, on) {
  const ch = chat(conv);
  clearTimeout(ch.typing.get(user));
  if (on) ch.typing.set(user, setTimeout(() => { ch.typing.delete(user); if (conv === active) renderHeader(); renderContacts(); }, TYPING_MS));
  else ch.typing.delete(user);
  if (conv === active) renderHeader();
  renderContacts();
}

let lastTypingSent = 0;
function onTypingInput() {
  if (!active || !prefs().typing || !connected) return;
  const now = Date.now();
  if (now - lastTypingSent < 3000) return;
  lastTypingSent = now;
  const g = isGroup(active) ? gidOf(active) : undefined;
  for (const t of targetsOf(active)) client.sendLive(t, { t: "typing", on: true, ...(g ? { g } : {}) });
}

function stopTyping() {
  if (!lastTypingSent || !active || !client) return;
  lastTypingSent = 0;
  const g = isGroup(active) ? gidOf(active) : undefined;
  for (const t of targetsOf(active)) client.sendLive(t, { t: "typing", on: false, ...(g ? { g } : {}) });
}

// Confirmaciones agrupadas: si llegan 10 mensajes seguidos, mandamos una sola
const pendingReceipts = new Map(); // `${peer}|${status}|${g}` -> Set(ids)
function sendReceipt(peer, ids, status, g) {
  if (status === "read" && !prefs().readReceipts) return;
  const k = `${peer}|${status}|${g || ""}`;
  const first = !pendingReceipts.has(k);
  if (first) pendingReceipts.set(k, new Set());
  for (const id of ids) pendingReceipts.get(k).add(id);
  if (!first) return;
  setTimeout(async () => {
    const set = pendingReceipts.get(k);
    pendingReceipts.delete(k);
    try { await client?.sendContent(peer, { t: "receipt", ids: [...set], s: status, ...(g ? { g } : {}) }); }
    catch { /* son opcionales: si falla, no pasa nada */ }
  }, 300);
}

function markRead(conv) {
  const unread = chat(conv).messages.filter((m) => m.from === "them" && !m.read);
  if (!unread.length) return;
  const bySender = new Map();
  for (const m of unread) {
    m.read = true;
    history?.put(conv, m);
    const s = m.sender || conv;
    if (m.content?.mid) bySender.set(s, [...(bySender.get(s) || []), m.content.mid]);
  }
  if (connected) for (const [s, ids] of bySender) sendReceipt(s, ids, "read", isGroup(conv) ? gidOf(conv) : undefined);
  renderContacts();
  updateTitle();
}

function notify(conv, sender, content) {
  if (!document.hidden || !prefs().notifications || !("Notification" in window) || Notification.permission !== "granted") return;
  // No mostramos el contenido: la notificación podría verse con la pantalla bloqueada.
  const title = isGroup(conv) ? convName(conv) : displayName(sender);
  const who = isGroup(conv) ? `${displayName(sender)}: ` : "";
  new Notification(title, { body: who + (content.t === "text" ? "Nuevo mensaje" : previewOf(content)), tag: conv });
}

// ------------------------------------------------------------------- grupos

function groupState(g) {
  return { t: "group", g: g.id, name: g.name, members: g.members, admin: g.admin, v: g.v, avatar: g.avatar || null };
}

/** Estado de un grupo recibido: solo lo acepta del administrador. */
function onGroupState(sender, c) {
  const existing = groups.get(c.g);
  const valid = existing
    ? same(sender, existing.admin) && c.v > existing.v
    : same(sender, c.admin) && c.members.some((x) => same(x, sender));
  if (!valid) return;
  const conv = `#${c.g}`;
  const inside = c.members.some((x) => same(x, me));
  const wasInside = existing && !existing.left;
  groups.set(c.g, { id: c.g, name: c.name, members: c.members, admin: c.admin, v: c.v, avatar: c.avatar, left: !inside });
  saveGroups();
  if (!existing && inside) addMsg(conv, { sys: `${displayName(sender)} te ha añadido al grupo «${c.name}».` });
  else if (wasInside && !inside) addMsg(conv, { sys: `${displayName(sender)} te ha sacado del grupo.`, warn: true });
  else if (existing && existing.name !== c.name) addMsg(conv, { sys: `${displayName(sender)} ha cambiado el nombre a «${c.name}».` });
  else if (existing) {
    const added = c.members.filter((x) => !existing.members.some((y) => same(x, y)));
    const removed = existing.members.filter((x) => !c.members.some((y) => same(x, y)));
    for (const a of added) addMsg(conv, { sys: `${displayName(sender)} ha añadido a ${displayName(a)}.` });
    for (const r of removed) addMsg(conv, { sys: `${displayName(r)} ya no está en el grupo.` });
  }
  renderContacts();
  if (active === conv) renderChat();
}

function onGroupLeave(sender, gid) {
  const g = groups.get(gid);
  if (!g || !g.members.some((x) => same(x, sender))) return;
  g.members = g.members.filter((x) => !same(x, sender));
  addMsg(`#${gid}`, { sys: `${displayName(sender)} ha salido del grupo.` });
  // Si se fue el administrador, lo hereda el primer miembro (en orden alfabético)
  if (same(sender, g.admin) && g.members.length) {
    g.admin = [...g.members].sort((a, b) => a.localeCompare(b))[0];
    if (same(g.admin, me) && !g.left) { g.v = Date.now(); queueAction(`#${gid}`, groupState(g)); }
  }
  saveGroups();
  renderContacts();
  if (active === `#${gid}`) renderChat();
}

function createGroup(name, members) {
  const g = { id: newId(), name, members: [me, ...members], admin: me, v: Date.now(), avatar: null, left: false };
  groups.set(g.id, g);
  saveGroups();
  const conv = `#${g.id}`;
  addMsg(conv, { sys: `Has creado el grupo «${name}». Los mensajes van cifrados de extremo a extremo para cada miembro.` });
  queueAction(conv, groupState(g));
  openChat(conv);
}

function updateGroup(gid, patch) {
  const g = groups.get(gid);
  const before = [...g.members];
  Object.assign(g, patch, { v: Date.now() });
  saveGroups();
  // El nuevo estado va a todos los miembros, también a los que se quitan (para que lo sepan)
  const to = [...new Set([...before, ...g.members])].filter((x) => !same(x, me));
  queueAction(`#${gid}`, groupState(g), to);
  renderContacts();
  if (active === `#${gid}`) renderChat();
}

function leaveGroup(gid) {
  const g = groups.get(gid);
  queueAction(`#${gid}`, { t: "group-leave", g: gid });
  g.left = true;
  g.members = g.members.filter((x) => !same(x, me));
  saveGroups();
  addMsg(`#${gid}`, { sys: "Has salido del grupo." });
  renderChat();
}

// --------------------------------------------------------------- acciones

async function onNewChat(ev) {
  ev.preventDefault();
  const input = $("new-chat-name");
  const name = input.value.trim().replace(/^@/, "");
  $("new-chat-error").hidden = true;
  if (!NAME_RE.test(name)) return showNewChatError("Escribe un @usuario válido.");
  if (same(name, me)) return showNewChatError("Ese eres tú.");
  if (!connected) return showNewChatError("Sin conexión: espera a que vuelva para buscar usuarios.");
  input.disabled = true;
  try {
    const info = await client.lookup(name);
    if (!info.exists) return showNewChatError(`No existe ningún usuario @${name}.`);
    input.value = "";
    chat(info.user).online = info.online;
    chat(info.user).lastSeen = info.lastSeen;
    openChat(info.user);
  } catch (e) {
    showNewChatError(e.message);
  } finally {
    input.disabled = false;
    input.focus();
  }
}

function showNewChatError(t) {
  $("new-chat-error").textContent = t;
  $("new-chat-error").hidden = false;
}

async function openChat(conv) {
  stopTyping();
  active = conv;
  if (!isGroup(conv)) e2eNotice(conv);
  cancelReply();
  $("app").classList.add("in-chat");
  $("new-chat-error").hidden = true;
  closePicker();
  renderContacts();
  renderChat();
  markRead(conv);
  if (window.matchMedia("(pointer: fine)").matches) $("text").focus();
  if (isGroup(conv) || !connected) return;
  // Contacto: miramos si está conectado y su "última vez"
  client.lookup(conv).then((info) => {
    chat(conv).online = info.online;
    chat(conv).lastSeen = info.lastSeen;
    if (active === conv) renderHeader();
  }).catch(() => {});
}

let replyingTo = null; // {mid, from, text}
let editing = null;    // mensaje que se está editando

function startReply(m) {
  editing = null;
  replyingTo = { mid: m.id, from: m.from === "me" ? me : (m.sender || active), text: previewOf(m.content).slice(0, 120) };
  showComposerBar(`Respondiendo a ${m.from === "me" ? "ti" : displayName(replyingTo.from)}`, replyingTo.text);
  $("text").focus();
}

function startEdit(m) {
  replyingTo = null;
  editing = m;
  $("text").value = m.content.body;
  showComposerBar("Editando mensaje", m.content.body.slice(0, 120));
  $("text").focus();
}

function showComposerBar(title, body) {
  $("reply-title").textContent = title;
  $("reply-text").textContent = body;
  $("reply-bar").hidden = false;
}

function cancelReply() {
  if (editing) $("text").value = "";
  replyingTo = null;
  editing = null;
  $("reply-bar").hidden = true;
}

/** Escribe un mensaje: aparece al momento con 🕓 y sale en cuanto haya conexión. */
async function send(content, { bytes = null, url = null } = {}) {
  const conv = active;
  if (!conv) return;
  if (isGroup(conv) && !targetsOf(conv).length) {
    addMsg(conv, { sys: groups.get(gidOf(conv))?.left ? "Ya no estás en este grupo." : "El grupo no tiene más miembros.", warn: true }, { persist: false });
    return;
  }
  const mid = newId();
  const full = { ...content, mid, ...(replyingTo ? { reply: replyingTo } : {}) };
  cancelReply();
  const m = addMsg(conv, { id: mid, from: "me", content: { ...full, data: undefined }, status: "sending",
    to: targetsOf(conv), ...(isGroup(conv) ? { receipts: {} } : {}), ...(bytes ? { hasMedia: true, url } : {}) });
  if (bytes) await history?.putMedia(conv, mid, bytes);
  stopTyping();
  askNotifications();
  flushAll();
}

// La bandeja de salida: mensajes con 🕓 y acciones (reacciones, ediciones, grupos…)
// que aún no ha recibido el servidor. Se guarda para sobrevivir a recargas.
const actionsKey = () => `sc:actions:${me.toLowerCase()}`;

function queueAction(conv, content, to = null) {
  const g = isGroup(conv) ? gidOf(conv) : undefined;
  const list = store.get(actionsKey()) || [];
  list.push({ to: to || targetsOf(conv), content: { ...content, ...(g && !content.g ? { g } : {}) } });
  store.set(actionsKey(), list);
  flushAll();
}

let flushingNow = false;
async function flushAll() {
  if (!client || !connected || flushingNow) return;
  flushingNow = true;
  try {
    await flushActions();
    await flushOutbox();
  } finally {
    flushingNow = false;
  }
}

async function flushActions() {
  const list = store.get(actionsKey()) || [];
  while (list.length && connected) {
    const a = list[0];
    while (a.to.length && connected) {
      try { await client.sendContent(a.to[0], a.content); a.to.shift(); }
      catch (e) { if (isConnectivity(e)) { store.set(actionsKey(), list); return; } a.to.shift(); }
      store.set(actionsKey(), list);
    }
    if (!a.to.length) { list.shift(); store.set(actionsKey(), list); }
  }
}

async function flushOutbox() {
  for (const [conv, ch] of chats) {
    for (const m of ch.messages.filter((x) => x.from === "me" && x.status === "sending")) {
      if (!connected) return;
      m.to ??= [conv];
      let content = { ...m.content, ...(isGroup(conv) ? { g: gidOf(conv) } : {}) };
      if (m.hasMedia) {
        const bytes = await history.getMedia(conv, m.id);
        if (!bytes) { setStatus(conv, m, "failed"); continue; }
        content = { ...content, data: sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL) };
      }
      while (m.to.length) {
        try {
          await client.sendContent(m.to[0], content);
          m.to.shift();
          history?.put(conv, m);
        } catch (e) {
          if (isConnectivity(e)) return; // se queda con 🕓 y se reintenta al reconectar
          const who = m.to.shift();
          addMsg(conv, { sys: e instanceof P.IdentityMismatch ? e.message
            : `No se pudo enviar${isGroup(conv) ? ` a ${displayName(who)}` : ""}: ${e.message}`, warn: true });
          if (!isGroup(conv)) { setStatus(conv, m, "failed"); break; }
        }
      }
      if (!m.to.length && m.status === "sending") setStatus(conv, m, "sent");
    }
  }
}

const isConnectivity = (e) => e instanceof ClientError && /no conectado|conexión cerrada|no responde|no respondió/.test(e.message);

async function onSend(ev) {
  ev.preventDefault();
  const t = $("text").value;
  if (editing) {
    if (t.trim() && t !== editing.content.body) myEdit(active, editing, t);
    $("text").value = "";
    cancelReply();
    return;
  }
  if (!t.trim()) return;
  $("text").value = "";
  closePicker();
  await send({ t: "text", body: t });
}

// Acciones propias sobre un mensaje
function myReact(conv, m, emoji) {
  m.reactions ??= {};
  const mine = m.reactions[me.toLowerCase()];
  const value = mine === emoji ? "" : emoji; // tocar la misma reacción la quita
  if (value) m.reactions[me.toLowerCase()] = value; else delete m.reactions[me.toLowerCase()];
  save(conv, m);
  queueAction(conv, { t: "react", target: m.id, emoji: value });
}

function myEdit(conv, m, body) {
  m.content = { ...m.content, body };
  m.edited = true;
  save(conv, m);
  queueAction(conv, { t: "edit", target: m.id, body });
}

function myDelete(conv, m, forAll) {
  if (forAll) queueAction(conv, { t: "delete", target: m.id });
  if (forAll) { deleteLocal(conv, m); save(conv, m); }
  else {
    chat(conv).messages = chat(conv).messages.filter((x) => x !== m);
    history?.remove(conv, m.id);
    renderChat();
  }
  renderContacts();
}

async function sendFile(file) {
  if (!file || !active) return;
  const isImage = IMAGE_MIME.includes(file.type), isVideo = VIDEO_MIME.includes(file.type);
  if (!isImage && !isVideo) return addMsg(active, { sys: "Solo puedes enviar fotos (PNG, JPG, GIF, WebP) o vídeos (MP4, WebM, MOV).", warn: true }, { persist: false });
  if (file.size > MAX_MEDIA) return addMsg(active, { sys: `El archivo pesa ${(file.size / 1048576).toFixed(1)} MB. El máximo es 8 MB.`, warn: true }, { persist: false });
  const bytes = new Uint8Array(await file.arrayBuffer());
  await send({ t: isImage ? "image" : "video", mime: file.type, name: file.name.slice(0, 120) },
    { bytes, url: URL.createObjectURL(file) });
}

// ------------------------------------------------------------- notas de voz

let recorder = null, recStart = 0, recTimer = null, recChunks = [], recCancelled = false;

async function startRecording() {
  if (!active || recorder) return;
  if (!navigator.mediaDevices?.getUserMedia) {
    addMsg(active, { sys: "Este navegador no permite grabar audio aquí (hace falta HTTPS).", warn: true }, { persist: false });
    return;
  }
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); }
  catch { addMsg(active, { sys: "No hay permiso para usar el micrófono.", warn: true }, { persist: false }); return; }
  const mime = ["audio/webm;codecs=opus", "audio/mp4", "audio/ogg;codecs=opus", "audio/webm"].find((t) => MediaRecorder.isTypeSupported?.(t)) || "";
  recorder = new MediaRecorder(stream, mime ? { mimeType: mime } : {});
  recChunks = [];
  recCancelled = false;
  recorder.ondataavailable = (e) => { if (e.data.size) recChunks.push(e.data); };
  recorder.onstop = async () => {
    stream.getTracks().forEach((t) => t.stop());
    const dur = (Date.now() - recStart) / 1000;
    const type = (recorder.mimeType || mime || "audio/webm").split(";")[0];
    recorder = null;
    clearInterval(recTimer);
    $("rec-bar").hidden = true;
    $("composer").classList.remove("recording");
    if (recCancelled || dur < 0.7) return;
    const blob = new Blob(recChunks, { type });
    if (blob.size > MAX_MEDIA) return addMsg(active, { sys: "La nota de voz es demasiado larga.", warn: true }, { persist: false });
    const bytes = new Uint8Array(await blob.arrayBuffer());
    await send({ t: "audio", mime: type, dur: Math.round(dur * 10) / 10 }, { bytes, url: URL.createObjectURL(blob) });
  };
  recorder.start(250);
  recStart = Date.now();
  $("composer").classList.add("recording");
  $("rec-bar").hidden = false;
  const tick = () => {
    const s = Math.floor((Date.now() - recStart) / 1000);
    $("rec-time").textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
    if (s >= 120) stopRecording(false); // máximo 2 minutos
  };
  tick();
  recTimer = setInterval(tick, 250);
}

function stopRecording(cancel) {
  if (!recorder) return;
  recCancelled = cancel;
  recorder.stop();
}

/** Suscribe este dispositivo a los avisos con la app cerrada (Web Push). */
async function setupPush() {
  try {
    if (!prefs().notifications || !serverConfig.push_key || !("PushManager" in window) || !navigator.serviceWorker
      || Notification.permission !== "granted" || !client) return;
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      const key = Uint8Array.from(atob(serverConfig.push_key.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    }
    client.setPushSubscription(sub.toJSON());
  } catch { /* el navegador no lo permite (p. ej. sin HTTPS): no pasa nada */ }
}

async function removePush() {
  try {
    const sub = await (await navigator.serviceWorker?.ready)?.pushManager.getSubscription();
    if (sub) { client?.removePushSubscription(sub.endpoint); await sub.unsubscribe(); }
  } catch { /* */ }
}

function askNotifications() {
  if (prefs().notifications && "Notification" in window && Notification.permission === "default") {
    Notification.requestPermission().then((p) => { if (p === "granted") setupPush(); });
  }

}

// ------------------------------------------------------- emojis y stickers

let pickerTab = "emoji";

function togglePicker() {
  if ($("picker").hidden) { renderPicker(); $("picker").hidden = false; }
  else closePicker();
}
function closePicker() { $("picker").hidden = true; }

function renderPicker() {
  for (const b of document.querySelectorAll(".picker-tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === pickerTab));
  const body = $("picker-body");
  body.replaceChildren();
  if (pickerTab === "emoji") {
    const recent = store.get("sc:recent-emoji") || [];
    const groups = recent.length ? [["Recientes", recent], ...EMOJIS] : EMOJIS;
    for (const [group, list] of groups) {
      body.append(text(group, "p", "picker-group"));
      const grid = text("", "div", "emoji-grid");
      for (const e of list) {
        const b = text(e, "button", "emoji");
        b.type = "button";
        b.onclick = () => {
          insertAtCursor($("text"), e);
          store.set("sc:recent-emoji", [e, ...recent.filter((x) => x !== e)].slice(0, 16));
        };
        grid.append(b);
      }
      body.append(grid);
    }
  } else {
    const grid = text("", "div", "sticker-grid");
    for (const s of STICKERS) {
      const b = text(s, "button", "sticker-btn");
      b.type = "button";
      b.title = "Enviar sticker";
      b.onclick = () => { closePicker(); send({ t: "sticker", id: s }); };
      grid.append(b);
    }
    body.append(grid);
  }
}

function insertAtCursor(input, str) {
  const { selectionStart: a = input.value.length, selectionEnd: b = input.value.length } = input;
  input.value = input.value.slice(0, a) + str + input.value.slice(b);
  input.setSelectionRange(a + str.length, a + str.length);
  input.focus();
}

// ---------------------------------------------------------------- perfiles

function field(label, input, hint) {
  const f = text("", "label", "field");
  f.append(text(label, "span"), input);
  if (hint) f.append(text(hint, "small", "hint"));
  return f;
}

function input(value, { max = 64, placeholder = "" } = {}) {
  const i = document.createElement("input");
  i.value = value || "";
  i.maxLength = max;
  i.placeholder = placeholder;
  return i;
}

function showMyProfile() {
  let avatar = profile.avatar;
  const preview = setAvatar(text("", "span", "avatar xl"), profile.name || me, avatar);
  const fileIn = document.createElement("input");
  fileIn.type = "file";
  fileIn.accept = "image/png,image/jpeg,image/webp,image/gif";
  fileIn.hidden = true;
  const change = text("Cambiar foto", "button", "chip");
  change.type = "button";
  change.onclick = () => fileIn.click();
  const remove = text("Quitar", "button", "chip");
  remove.type = "button";
  remove.onclick = () => { avatar = null; setAvatar(preview, nameIn.value || me, null); };
  fileIn.onchange = async () => {
    try { avatar = await resizeImage(fileIn.files[0], 256, true); setAvatar(preview, nameIn.value || me, avatar); }
    catch { change.textContent = "Imagen no válida"; }
  };
  const nameIn = input(profile.name || me, { placeholder: me });
  const bioIn = input(profile.bio, { max: 140, placeholder: "Disponible · ¡Hola! Estoy usando SecureChat" });
  const head = text("", "div", "profile-head");
  const btns = text("", "div", "profile-photo-btns");
  btns.append(change, remove, fileIn);
  head.append(preview, btns);

  dialog("Mi perfil", [
    head,
    field("Nombre visible", nameIn),
    field("Estado", bioIn, "Una frase que verán tus contactos."),
    text(`Tu usuario es @${me}. Es único y es lo que otros escriben para encontrarte.`, "p", "hint"),
    text("Tu nombre, estado y foto viajan cifrados: solo los ven tus contactos, nunca el servidor.", "p", "hint"),
    advancedSecurityMine(),
  ], [["Cancelar"], ["Guardar", () => {
    profile = { name: nameIn.value.trim().slice(0, 64) || me, bio: bioIn.value.trim().slice(0, 140), avatar };
    if (!store.set(`sc:profile:${me.toLowerCase()}`, profile)) profile.avatar = null;
    client.setProfile(profile, client.contacts.all().map((c) => c.name));
    renderMe();
  }]]);
}

/** Recorta/redimensiona una imagen a JPEG: pocos KB y sin metadatos (EXIF/GPS). */
async function resizeImage(file, size, square) {
  const bmp = await createImageBitmap(file);
  const canvas = document.createElement("canvas");
  if (square) {
    const side = Math.min(bmp.width, bmp.height);
    canvas.width = canvas.height = size;
    canvas.getContext("2d").drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, size, size);
  } else {
    const scale = Math.min(1, size / Math.max(bmp.width, bmp.height));
    canvas.width = Math.round(bmp.width * scale);
    canvas.height = Math.round(bmp.height * scale);
    canvas.getContext("2d").drawImage(bmp, 0, 0, canvas.width, canvas.height);
  }
  const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.82));
  return sodium.to_base64(new Uint8Array(await blob.arrayBuffer()), sodium.base64_variants.ORIGINAL);
}

function advancedSecurityMine() {
  const d = document.createElement("details");
  d.className = "advanced";
  d.append(text("Seguridad avanzada", "summary"),
    text("Huella de tu clave:", "p", "hint"),
    text(P.fingerprint(identity.publicKey), "p", "mono"));
  const exp = text("Exportar clave (identity.json)", "button", "chip");
  exp.type = "button";
  exp.onclick = () => download(`${me}-identity.json`, JSON.stringify(store.get(idKey(me)), null, 2));
  d.append(exp, text("Sirve para usar tu misma cuenta en la versión de terminal. Va cifrada con tu contraseña.", "p", "hint"));
  const devBox = text("Cargando…", "div", "member-list");
  d.append(text("Tus dispositivos", "h3", "settings-h"), devBox);
  d.addEventListener("toggle", async () => {
    if (!d.open || !connected) return;
    try {
      const list = await client.devices();
      devBox.replaceChildren(...list.map((x) => {
        const row = text("", "div", "device-row");
        const label = x.device === client.device ? "Este dispositivo" : `Dispositivo ${x.device.slice(0, 6)}`;
        const when = x.online ? "conectado ahora" : x.seen ? `visto ${shortTime(new Date(x.seen * 1000))}` : "";
        row.append(icon(x.device === client.device ? "phone" : "laptop", "muted-ico"), text(`${label} · ${when}`, "span", "member-name"));
        if (x.device !== client.device) {
          const rm = text("Desvincular", "button", "chip danger");
          rm.type = "button";
          rm.onclick = async () => {
            if (!confirm("¿Desvincular este dispositivo? Tendrá que volver a iniciar sesión.")) return;
            await client.removeDevice(x.device);
            row.remove();
          };
          row.append(rm);
        }
        return row;
      }));
    } catch (e) { devBox.textContent = e.message; }
  });
  return d;
}

function showGroupInfo(conv) {
  const gid = gidOf(conv), g = groups.get(gid);
  if (!g) return;
  const isAdmin = same(g.admin, me) && !g.left;
  const head = text("", "div", "profile-view");
  head.append(setAvatar(text("", "span", "avatar xl"), g.name, g.avatar), text(g.name, "h3"),
    text(`${g.members.length} miembros${g.left ? " · ya no estás en este grupo" : ""}`, "p", "muted"));
  const body = [head];
  let nameIn = null;
  if (isAdmin) { nameIn = input(g.name); body.push(field("Nombre del grupo", nameIn)); }
  const list = text("", "ul", "member-list");
  for (const u of g.members) {
    const li = document.createElement("li");
    li.append(setAvatar(text("", "span", "avatar"), same(u, me) ? (profile.name || me) : displayName(u), same(u, me) ? profile.avatar : avatarOf(u)),
      text(same(u, me) ? "Tú" : displayName(u), "span", "member-name"), text(same(u, g.admin) ? "admin" : "", "small", "muted"));
    if (isAdmin && !same(u, me)) {
      const rm = text("Quitar", "button", "chip danger");
      rm.type = "button";
      rm.onclick = () => { updateGroup(gid, { members: g.members.filter((x) => !same(x, u)) }); showGroupInfo(conv); };
      li.append(rm);
    }
    list.append(li);
  }
  body.push(text("Miembros", "h3", "settings-h"), list);
  if (isAdmin) {
    const addIn = input("", { max: 33, placeholder: "@usuario" });
    const addErr = text("", "p", "error");
    const addBtn = text("Añadir", "button", "chip");
    addBtn.type = "button";
    addBtn.onclick = async () => {
      const name = addIn.value.trim().replace(/^@/, "");
      addErr.textContent = "";
      if (!NAME_RE.test(name)) { addErr.textContent = "Escribe un @usuario válido."; return; }
      try {
        const info = await client.lookup(name);
        if (!info.exists) { addErr.textContent = `No existe @${name}.`; return; }
        if (g.members.some((x) => same(x, info.user))) { addErr.textContent = "Ya está en el grupo."; return; }
        updateGroup(gid, { members: [...g.members, info.user] });
        showGroupInfo(conv);
      } catch (e) { addErr.textContent = e.message; }
    };
    const row = text("", "div", "add-row");
    row.append(addIn, addBtn);
    body.push(text("Añadir miembro", "h3", "settings-h"), row, addErr);
  }
  if (!g.left) {
    const leave = text("Salir del grupo", "button", "chip danger");
    leave.type = "button";
    leave.onclick = () => { if (confirm(`¿Salir del grupo «${g.name}»?`)) { leaveGroup(gid); $("dialog").close(); } };
    body.push(leave);
  }
  dialog("Grupo", body, [["Cerrar", () => {
    if (nameIn && nameIn.value.trim() && nameIn.value.trim() !== g.name) updateGroup(gid, { name: nameIn.value.trim().slice(0, 64) });
  }]]);
}

// -------------------------------------------------------- copia de seguridad
// Fichero cifrado con una clave derivada de tu identidad: solo tu cuenta puede
// abrirlo (en cualquier dispositivo, tras iniciar sesión). Incluye fotos y audios.

const BACKUP_MAGIC = "securechat-backup-v1";

async function exportBackup() {
  const convs = [];
  for (const [conv, ch] of chats) {
    const msgs = [];
    for (const m of ch.messages) {
      const { el, url, ...plain } = m;
      if (m.hasMedia) {
        const bytes = await history.getMedia(conv, m.id);
        if (bytes) plain.media = sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
      }
      msgs.push({ ...plain, time: m.time.getTime() });
    }
    convs.push([conv, msgs]);
  }
  const data = {
    magic: BACKUP_MAGIC, account: me, created: Date.now(), convs,
    groups: Object.fromEntries(groups), contacts: client.contacts.toJSON(), profile,
  };
  const key = P.kdf(identity.seed, "sc-backup");
  const nonce = sodium.randombytes_buf(24);
  const ct = sodium.crypto_secretbox_easy(new TextEncoder().encode(JSON.stringify(data)), nonce, key);
  const out = new Uint8Array(24 + ct.length);
  out.set(nonce); out.set(ct, 24);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([out], { type: "application/octet-stream" }));
  a.download = `securechat-${me}-${new Date().toISOString().slice(0, 10)}.scbackup`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  return convs.reduce((n, [, l]) => n + l.length, 0);
}

async function importBackup(file) {
  const raw = new Uint8Array(await file.arrayBuffer());
  let data;
  try {
    const pt = sodium.crypto_secretbox_open_easy(raw.subarray(24), raw.subarray(0, 24), P.kdf(identity.seed, "sc-backup"));
    data = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    throw new Error("Esta copia no es de tu cuenta o está dañada.");
  }
  if (data.magic !== BACKUP_MAGIC) throw new Error("No es una copia de SecureChat.");
  let added = 0;
  for (const [conv, msgs] of data.convs) {
    const have = new Set(chat(conv).messages.map((m) => m.id));
    for (const raw of msgs) {
      if (have.has(raw.id)) continue;
      const { media, ...m } = raw;
      m.time = new Date(m.time);
      if (media) await history.putMedia(conv, m.id, sodium.from_base64(media, sodium.base64_variants.ORIGINAL));
      chat(conv).messages.push(m);
      await history.put(conv, m);
      added++;
    }
    chat(conv).messages.sort((a, b) => a.time - b.time);
  }
  for (const [gid, g] of Object.entries(data.groups || {})) {
    const mine = groups.get(gid);
    if (!mine || (g.v || 0) > (mine.v || 0)) groups.set(gid, g);
  }
  saveGroups();
  for (const [name, c] of Object.entries(data.contacts || {})) {
    if (!client.contacts.get(name)) {
      try { client.contacts.pin(name, P.b64d(c.identity_key)); client.contacts.setProfile(name, { name: c.display_name, avatar: c.avatar, bio: c.bio }); }
      catch { /* clave distinta: se respeta la que ya teníamos */ }
    }
  }
  renderContacts();
  renderChat();
  return added;
}

function showBackup() {
  const status = text("", "p", "hint");
  const exp = withIcon("download", "Descargar copia cifrada", "button", "primary");
  exp.type = "button";
  exp.onclick = async () => {
    exp.disabled = true;
    status.textContent = "Preparando la copia…";
    try { status.textContent = `Copia descargada con ${await exportBackup()} mensajes.`; }
    catch (e) { status.textContent = `No se pudo crear: ${e.message}`; }
    finally { exp.disabled = false; }
  };
  const fileIn = document.createElement("input");
  fileIn.type = "file";
  fileIn.accept = ".scbackup";
  fileIn.hidden = true;
  fileIn.onchange = async () => {
    status.textContent = "Restaurando…";
    try { status.textContent = `Restaurados ${await importBackup(fileIn.files[0])} mensajes nuevos.`; }
    catch (e) { status.textContent = e.message; }
  };
  const imp = withIcon("upload", "Restaurar una copia", "button", "chip");
  imp.type = "button";
  imp.onclick = () => fileIn.click();
  dialog("Copia de seguridad", [
    text("Guarda todo tu historial (mensajes, fotos, notas de voz, grupos y contactos) en un fichero cifrado.", "p"),
    text("Solo tu cuenta puede abrirlo: la clave sale de tu identidad. Sirve para pasar tu historial a otro móvil u ordenador: inicia sesión allí y restaura la copia.", "p", "hint"),
    exp, imp, fileIn, status,
  ]);
}

function showAbout() {
  const items = [
    ["lock", "Cifrado de extremo a extremo", "Tus mensajes, fotos, notas de voz y perfil se cifran en tu dispositivo. El servidor solo ve datos ilegibles."],
    ["users", "Grupos invisibles", "Cada mensaje de grupo se cifra por separado para cada miembro: el servidor no sabe que el grupo existe."],
    ["clock", "Mensajes en diferido", "Si alguien no está conectado, el servidor guarda el mensaje cifrado hasta que entra."],
    ["key", "Tu clave es tuya", "La copia que guarda el servidor va cifrada con tu contraseña. Si la olvidas, nadie puede recuperarla."],
    ["alert", "Proyecto educativo", "No está auditado: no lo uses para información sensible real."],
  ];
  dialog("Cómo te protege SecureChat", items.map(([ic, title, desc]) => {
    const row = text("", "div", "about-row");
    const t = text("", "div");
    t.append(text(title, "strong"), text(desc, "p", "hint"));
    row.append(icon(ic, "about-icon"), t);
    return row;
  }));
}

function showNewGroup() {
  const nameIn = input("", { placeholder: "Amigos de clase" });
  const memberIn = input("", { max: 33, placeholder: "@usuario" });
  const chosen = [];
  const chips = text("", "div", "chosen");
  const err = text("", "p", "error");
  const draw = () => chips.replaceChildren(...chosen.map((u) => {
    const b = withIcon("close", displayName(u), "button", "chip removable", true);
    b.type = "button";
    b.onclick = () => { chosen.splice(chosen.indexOf(u), 1); draw(); };
    return b;
  }));
  const add = async () => {
    const name = memberIn.value.trim().replace(/^@/, "");
    err.textContent = "";
    if (!name) return;
    if (!NAME_RE.test(name)) { err.textContent = "Escribe un @usuario válido."; return; }
    if (same(name, me) || chosen.some((x) => same(x, name))) { memberIn.value = ""; return; }
    try {
      const info = await client.lookup(name);
      if (!info.exists) { err.textContent = `No existe @${name}.`; return; }
      chosen.push(info.user);
      memberIn.value = "";
      draw();
    } catch (e) { err.textContent = e.message; }
  };
  const addBtn = text("Añadir", "button", "chip");
  addBtn.type = "button";
  addBtn.onclick = add;
  memberIn.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } };
  const row = text("", "div", "add-row");
  row.append(memberIn, addBtn);
  dialog("Nuevo grupo", [
    field("Nombre del grupo", nameIn),
    text("Miembros", "h3", "settings-h"), row, err, chips,
    text("Cada mensaje del grupo se cifra por separado para cada miembro: el servidor no sabe que el grupo existe.", "p", "hint"),
  ], [["Cancelar"], ["Crear grupo", () => {
    if (!connected) { alert("Sin conexión: espera a que vuelva."); return; }
    if (!chosen.length) { alert("Añade al menos a una persona."); return; }
    createGroup(nameIn.value.trim().slice(0, 64) || "Grupo", chosen);
  }]]);
  nameIn.focus();
}

function showPeerProfile(peer) {
  if (isGroup(peer)) return showGroupInfo(peer);
  const c = client.contacts.get(peer);
  const head = text("", "div", "profile-view");
  head.append(setAvatar(text("", "span", "avatar xl"), displayName(peer), avatarOf(peer)),
    text(c?.displayName || peer, "h3"), text(`@${peer}`, "p", "muted"));
  if (c?.bio) head.append(text(c.bio, "p", "bio"));
  const body = [head];
  let nickIn = null;
  if (c) {
    nickIn = input(c.nick, { placeholder: c.displayName || peer });
    body.push(field("Apodo", nickIn, "Solo lo ves tú. Sustituye a su nombre en tu lista de chats."));
    const d = document.createElement("details");
    d.className = "advanced";
    const grid = text("", "div", "safety");
    for (const g of P.safetyNumber(me, identity.publicKey, peer, c.key).split(" ")) grid.append(text(g, "span"));
    const toggle = text(c.verified ? "Quitar verificación" : "Coinciden: marcar como verificado", "button", "chip");
    toggle.type = "button";
    toggle.onclick = () => { client.contacts.setVerified(peer, !c.verified); showPeerProfile(peer); };
    d.append(text(`Seguridad avanzada${c.verified ? " · verificado" : ""}`, "summary"),
      text("El servidor solo reenvía mensajes, pero si alguien lo controlara podría intentar hacerse pasar por este contacto. "
        + "Para descartarlo del todo, comparad estos números en persona o por otra app: si coinciden, nadie está en medio.", "p", "hint"),
      grid, toggle);
    body.push(d);
  }
  const clear = text("Vaciar este chat", "button", "chip danger");
  clear.type = "button";
  clear.onclick = async () => {
    if (!confirm(`¿Borrar todos los mensajes con ${displayName(peer)} de este dispositivo? No se puede deshacer.`)) return;
    await history.deleteChat(peer);
    chat(peer).messages = [];
    $("dialog").close();
    renderChat();
    renderContacts();
  };
  body.push(clear);
  dialog("Perfil", body, [["Cerrar", () => { if (nickIn) client.contacts.setNick(peer, nickIn.value); }]]);
}

// ------------------------------------------------------------- personalizar

const ACCENTS = ["#4f46e5", "#7c3aed", "#db2777", "#e11d48", "#ea580c", "#ca8a04", "#16a34a", "#0d9488", "#0284c7", "#475569"];
const WALLS = [["dots", "Puntos"], ["plain", "Liso"], ["grid", "Cuadrícula"], ["diagonal", "Rayas"], ["bubbles", "Burbujas"], ["gradient", "Degradado"], ["image", "Tu foto"]];

function showSettings() {
  const p = prefs();
  const setPref = (patch) => { window.SC_SET_PREFS({ ...prefs(), ...patch }); };

  // Tema
  const current = document.documentElement.dataset.theme;
  const themes = text("", "div", "themes");
  for (const t of window.SC_THEMES) {
    const card = text("", "button", "theme-card");
    card.type = "button";
    card.dataset.theme = t.id; // la tarjeta se pinta con los colores de su propio tema
    card.setAttribute("aria-pressed", String(t.id === current));
    const sw = text("", "span", "swatch");
    sw.style.background = t.swatch[0];
    const a = document.createElement("i"), b = document.createElement("i");
    a.style.background = t.swatch[2];
    a.style.border = "1px solid rgb(127 127 127 / .3)";
    b.style.background = t.swatch[1];
    sw.append(a, b);
    card.append(sw, text(t.name, "strong"), text(t.desc, "small"));
    card.onclick = () => {
      store.set("sc:theme", window.applyTheme(t.id));
      for (const el of themes.children) el.setAttribute("aria-pressed", String(el === card));
    };
    themes.append(card);
  }

  // Color
  const colors = text("", "div", "swatches");
  const mkColor = (value, label) => {
    const b = text(label || "", "button", "color-dot");
    b.type = "button";
    b.title = value || "Color del tema";
    if (value) b.style.background = value; else b.classList.add("theme-color");
    b.setAttribute("aria-pressed", String((p.accent || null) === value));
    b.onclick = () => { setPref({ accent: value }); for (const x of colors.children) x.setAttribute("aria-pressed", String(x === b)); };
    return b;
  };
  colors.append(mkColor(null, "A"), ...ACCENTS.map((c) => mkColor(c)));
  const picker = document.createElement("input");
  picker.type = "color";
  picker.value = p.accent || "#4f46e5";
  picker.title = "Elige cualquier color";
  picker.oninput = () => setPref({ accent: picker.value });
  colors.append(picker);

  // Fondo
  const walls = text("", "div", "wall-grid");
  const wallFile = document.createElement("input");
  wallFile.type = "file";
  wallFile.accept = "image/png,image/jpeg,image/webp";
  wallFile.hidden = true;
  wallFile.onchange = async () => {
    try {
      const img = await resizeImage(wallFile.files[0], 1280, false);
      setPref({ wall: "image", wallImage: `data:image/jpeg;base64,${img}` });
      for (const x of walls.querySelectorAll(".wall")) x.setAttribute("aria-pressed", String(x.dataset.wall === "image"));
    } catch { /* imagen no válida */ }
  };
  for (const [id, label] of WALLS) {
    const b = text(label, "button", "wall");
    b.type = "button";
    b.dataset.wall = id;
    b.setAttribute("aria-pressed", String(p.wall === id));
    b.onclick = () => {
      if (id === "image") return wallFile.click();
      setPref({ wall: id });
      for (const x of walls.querySelectorAll(".wall")) x.setAttribute("aria-pressed", String(x === b));
    };
    walls.append(b);
  }
  walls.append(wallFile);

  // Letra y burbujas
  const seg = (options, key) => {
    const g = text("", "div", "segmented");
    for (const [value, label] of options) {
      const b = text(label, "button");
      b.type = "button";
      b.setAttribute("aria-pressed", String(p[key] === value));
      b.onclick = () => { setPref({ [key]: value }); for (const x of g.children) x.setAttribute("aria-pressed", String(x === b)); };
      g.append(b);
    }
    return g;
  };

  // Privacidad
  const toggle = (key, label, hint) => {
    const l = text("", "label", "switch");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!p[key];
    cb.onchange = () => {
      setPref({ [key]: cb.checked });
      if (key === "lastSeen") { client?.setPrivacy({ lastSeen: cb.checked }); renderHeader(); }
      if (key === "notifications") { if (cb.checked) askNotifications(), setupPush(); else removePush(); }
    };
    const t = text("", "span");
    t.append(text(label, "strong"), text(hint, "small"));
    l.append(cb, t);
    return l;
  };

  dialog("Personalizar", [
    text("Tema", "h3", "settings-h"), themes,
    text("Color principal", "h3", "settings-h"), colors,
    text("Fondo de los chats", "h3", "settings-h"), walls,
    text("Tamaño de letra", "h3", "settings-h"), seg([[13, "Pequeña"], [15, "Normal"], [17, "Grande"], [19, "Enorme"]], "font"),
    text("Forma de las burbujas", "h3", "settings-h"), seg([[22, "Redondas"], [14, "Suaves"], [4, "Rectas"]], "radius"),
    text("Privacidad y avisos", "h3", "settings-h"),
    toggle("readReceipts", "Confirmaciones de lectura", "Si las desactivas, los demás no verán el doble check azul."),
    toggle("typing", "Mostrar «escribiendo…»", "Si lo quitas, los demás no verán cuándo escribes."),
    toggle("lastSeen", "Compartir «última vez»", "Si lo quitas, nadie verá a qué hora te conectaste por última vez (y tú tampoco la de los demás)."),
    toggle("notifications", "Notificaciones", "Aviso cuando llega un mensaje con la app en segundo plano."),
    toggle("enterSends", "Enviar con Intro", "Si lo quitas, Intro hace salto de línea en el ordenador."),
  ]);
}

// -------------------------------------------------------------- renderizado

function text(t, tag = "p", cls = "") {
  const el = document.createElement(tag);
  el.textContent = t; // siempre textContent: nunca interpretamos HTML recibido
  if (cls) el.className = cls;
  return el;
}

const hhmm = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function dayLabel(d) {
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const day = new Date(d); day.setHours(0, 0, 0, 0);
  const diff = Math.round((today - day) / 86400000);
  if (diff === 0) return "Hoy";
  if (diff === 1) return "Ayer";
  if (diff < 7) return d.toLocaleDateString([], { weekday: "long" });
  return d.toLocaleDateString([], { day: "numeric", month: "long", year: diff > 300 ? "numeric" : undefined });
}

function shortTime(d) {
  const label = dayLabel(d);
  return label === "Hoy" ? hhmm(d) : label === "Ayer" ? "Ayer" : d.toLocaleDateString([], { day: "2-digit", month: "2-digit" });
}

function previewOf(c) {
  if (!c) return "";
  if (c.t === "text") return c.body;
  if (c.t === "sticker") return `Sticker ${c.id}`;
  if (c.t === "image") return c.mime === "image/gif" ? "GIF" : "Foto";
  if (c.t === "video") return "Vídeo";
  if (c.t === "audio") return `Nota de voz${c.dur ? ` · ${fmtDur(c.dur)}` : ""}`;
  if (c.t === "deleted") return "Mensaje eliminado";
  return "";
}

const fmtDur = (s) => `${Math.floor(s / 60)}:${String(Math.round(s % 60)).padStart(2, "0")}`;

function lastSeenText(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const label = dayLabel(d);
  return `últ. vez ${label === "Hoy" ? "hoy" : label === "Ayer" ? "ayer" : label} a las ${hhmm(d)}`;
}

function renderMe() {
  $("me-name").textContent = profile.name || me;
  setAvatar($("me-avatar"), profile.name || me, profile.avatar);
}

function renderContacts() {
  if (!client) return;
  const convs = new Set([...client.contacts.all().map((c) => c.name), ...chats.keys(), ...[...groups.keys()].map((g) => `#${g}`)]);
  const visible = (m) => m.content && !m.sys;
  const lastTime = (n) => chats.get(n)?.messages.filter(visible).at(-1)?.time || 0;
  const list = [...convs].sort((a, b) => lastTime(b) - lastTime(a) || convName(a).localeCompare(convName(b)));
  $("contacts-empty").hidden = list.length > 0;
  $("contacts").replaceChildren(...list.map((conv) => {
    const last = chats.get(conv)?.messages.filter(visible).at(-1);
    const unread = unreadOf(conv);
    const li = document.createElement("li");
    if (conv === active) li.className = "active";
    const btn = document.createElement("button");
    btn.type = "button";
    const main = text("", "span", "contact-main");
    const prev = text("", "span", "preview");
    const typing = chats.get(conv)?.typing?.size;
    if (typing) prev.append(text("escribiendo…", "span", "typing"));
    else {
      if (last?.from === "me" && !last.deleted) {
        const tick = text("", "span");
        paintTick(tick, statusOf(conv, last));
        prev.append(tick, " ");
      }
      const who = isGroup(conv) && last ? `${last.from === "me" ? "Tú" : displayName(last.sender)}: ` : "";
      prev.append(last ? who + previewOf(last.content) : isGroup(conv) ? `${groups.get(gidOf(conv))?.members.length || 0} miembros` : `@${conv}`);
    }
    const nameEl = text("", "strong", "contact-name");
    if (isGroup(conv)) nameEl.append(icon("users", "group-ico"));
    nameEl.append(convName(conv));
    main.append(nameEl, prev);
    const side = text("", "span", "contact-side");
    if (last) side.append(text(shortTime(last.time), "time"));
    if (unread) side.append(text(String(unread), "span", "unread"));
    btn.append(setAvatar(text("", "span", "avatar"), convName(conv), convAvatar(conv)), main, side);
    btn.onclick = () => openChat(conv);
    li.append(btn);
    return li;
  }));
}

function renderHeader() {
  if (!client) return;
  const has = !!active;
  if (has) {
    $("peer-name").textContent = convName(active);
    setAvatar($("peer-avatar"), convName(active), convAvatar(active));
    const ch = chat(active);
    let status;
    if (ch.typing.size) {
      const who = [...ch.typing.keys()].map(displayName);
      status = text(isGroup(active) ? `${who.join(", ")} ${who.length > 1 ? "están" : "está"} escribiendo…` : "escribiendo…", "span", "typing");
    } else if (isGroup(active)) {
      const g = groups.get(gidOf(active));
      status = text(g?.left ? "Ya no estás en este grupo" : g ? ["Tú", ...g.members.filter((x) => !same(x, me)).map(displayName)].join(", ") : "", "span");
    } else {
      const online = ch.online === true;
      const c = client.contacts.get(active);
      status = online ? text("en línea", "span", "lock")
        : text((prefs().lastSeen && lastSeenText(ch.lastSeen)) || c?.bio || `@${active}`, "span");
    }
    $("peer-status").replaceChildren(status);
  }
  // Se puede escribir siempre que haya un chat abierto (sin conexión, el mensaje espera con 🕓)
  for (const id of ["text", "send-btn", "emoji-btn", "attach-btn", "mic-btn"]) $(id).disabled = !has;
  $("chat").classList.toggle("is-empty", !has);
  $("empty-chat").hidden = has;
}

function renderChat() {
  renderHeader();
  closeMsgMenu();
  $("messages").replaceChildren();
  $("messages").dataset.day = "";
  if (active) for (const m of chat(active).messages) appendMessage(m);
}

const segmenter = "Segmenter" in Intl ? new Intl.Segmenter() : null;
function isJumboEmoji(s) {
  if (!segmenter || !/^[\p{Extended_Pictographic}\p{Emoji_Component}‍️\s]+$/u.test(s) || /[0-9#*]/.test(s.trim()[0])) return false;
  const n = [...segmenter.segment(s.trim())].length;
  return n >= 1 && n <= 3;
}

async function mediaUrl(conv, m) {
  if (m.url) return m.url;
  const bytes = await history?.getMedia(conv, m.id);
  if (!bytes) return null;
  m.url = URL.createObjectURL(new Blob([bytes], { type: m.content.mime }));
  return m.url;
}

/** Color estable para el nombre de cada miembro en los grupos. */
function nameHue(name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)) % 360;
  return h;
}

function buildMessage(conv, m, prev) {
  const li = document.createElement("li");
  const side = m.from === "me" ? "mine" : "theirs";
  const sameAuthor = prev?.classList.contains(side) && (side === "mine" || prev.dataset.sender === (m.sender || ""));
  const cont = sameAuthor ? "cont" : "first";
  const c = m.content;
  li.dataset.id = m.id;
  li.dataset.sender = m.sender || "";
  let kind = "";
  if (m.deleted) kind = " deleted";
  else if (c.t === "text" && isJumboEmoji(c.body) && !c.reply) kind = " jumbo";
  else if (c.t === "sticker") kind = " sticker";
  else if (c.t === "image" || c.t === "video") kind = " media";
  else if (c.t === "audio") kind = " voice";
  li.className = `msg ${side} ${cont}${kind}`;

  // Nombre del autor en los grupos
  if (isGroup(conv) && side === "theirs" && cont === "first") {
    const n = text(displayName(m.sender), "span", "author");
    n.style.setProperty("--h", nameHue(m.sender || ""));
    li.append(n);
  }
  // Mensaje al que responde
  if (c.reply && !m.deleted) {
    const q = text("", "button", "quote");
    q.type = "button";
    q.append(text(same(c.reply.from, me) ? "Tú" : displayName(c.reply.from), "strong"), text(c.reply.text || "…", "span"));
    q.onclick = (e) => { e.stopPropagation(); jumpTo(c.reply.mid); };
    li.append(q);
  }
  if (m.deleted) {
    const del = text("", "span", "body");
    del.append(icon("ban", "inline-ico"), m.from === "me" ? "Has eliminado este mensaje" : "Mensaje eliminado");
    li.append(del);
  } else if (c.t === "text") {
    li.append(text(c.body, "span", "body"));
  } else if (c.t === "sticker") {
    li.append(text(c.id, "span", "sticker-face"));
  } else if (c.t === "audio") {
    const a = document.createElement("audio");
    a.controls = true;
    a.preload = "metadata";
    mediaUrl(conv, m).then((u) => { if (u) a.src = u; else li.classList.add("missing"); });
    li.append(icon("mic", "mic-icon"), a);
  } else {
    const el = document.createElement(c.t === "image" ? "img" : "video");
    if (c.t === "image") {
      el.alt = c.name || "imagen";
      el.onclick = () => viewImage(m.url, c.name);
      el.onload = () => { if (isNearBottom()) li.scrollIntoView({ block: "end" }); };
    } else {
      el.controls = true;
      el.playsInline = true;
      el.preload = "metadata";
    }
    mediaUrl(conv, m).then((u) => { if (u) el.src = u; else li.classList.add("missing"); });
    li.append(el);
  }
  const t = text((m.edited && !m.deleted ? "editado · " : "") + hhmm(m.time), "time");
  if (m.from === "me" && !m.deleted) {
    const tick = text("", "span");
    paintTick(tick, statusOf(conv, m));
    t.append(" ", tick);
  }
  li.append(t);
  // Reacciones agrupadas: 👍 2  ❤️ 1
  const reactions = Object.entries(m.reactions || {});
  if (reactions.length && !m.deleted) {
    const counts = new Map();
    for (const [, e] of reactions) counts.set(e, (counts.get(e) || 0) + 1);
    const box = text("", "div", "reactions");
    for (const [e, n] of counts) {
      const chip = text(n > 1 ? `${e} ${n}` : e, "button", "reaction");
      chip.type = "button";
      chip.title = reactions.filter(([, x]) => x === e).map(([u]) => (same(u, me) ? "Tú" : displayName(u))).join(", ");
      if (m.reactions[me.toLowerCase()] === e) chip.classList.add("own");
      chip.onclick = (ev) => { ev.stopPropagation(); myReact(conv, m, e); };
      box.append(chip);
    }
    li.append(box);
  }
  // Menú: clic derecho en ordenador, mantener pulsado en el móvil
  li.oncontextmenu = (e) => { e.preventDefault(); openMsgMenu(conv, m, e.clientX, e.clientY); };
  let pressTimer = null;
  li.addEventListener("touchstart", (e) => {
    const t0 = e.touches[0];
    pressTimer = setTimeout(() => { navigator.vibrate?.(15); openMsgMenu(conv, m, t0.clientX, t0.clientY); }, 450);
  }, { passive: true });
  for (const ev of ["touchend", "touchmove", "touchcancel"]) li.addEventListener(ev, () => clearTimeout(pressTimer), { passive: true });
  m.el = li;
  return li;
}

function appendMessage(m) {
  const list = $("messages");
  // Separador de día (Hoy, Ayer, lunes…) como en WhatsApp
  const label = dayLabel(m.time);
  if (list.dataset.day !== label) {
    list.dataset.day = label;
    list.append(text(label, "li", "day"));
  }
  const li = m.sys ? sysItem(m) : buildMessage(active, m, list.lastElementChild);
  list.append(li);
  li.scrollIntoView({ block: "end" });
}

const LEADING_EMOJI = /^[\p{Extended_Pictographic}\u{1F300}-\u{1FAFF}\u2600-\u27BF][\ufe0f\s]*/u;

function sysItem(m) {
  const t = m.sys.replace(LEADING_EMOJI, "");
  const li = text("", "li", `sys${m.warn ? " warn" : ""}`);
  const ic = m.warn ? "alert" : /cifrad/.test(t) ? "lock" : /grupo|añadido|salido/.test(t) ? "users" : "info";
  li.append(icon(ic, "inline-ico"), t);
  return li;
}

/** Botón (u otro elemento) con un icono delante del texto. */
function withIcon(ic, label, tag = "button", cls = "", after = false) {
  const el = text("", tag, cls);
  if (after) el.append(label, icon(ic, "inline-ico"));
  else el.append(icon(ic, "inline-ico"), label);
  return el;
}

function rerenderMessage(m) {
  const old = m.el;
  if (!old?.isConnected) return;
  const li = buildMessage(active, m, old.previousElementSibling); // ojo: esto ya cambia m.el
  old.replaceWith(li);
}

function jumpTo(mid) {
  const m = chat(active).messages.find((x) => x.id === mid);
  if (!m?.el) return;
  m.el.scrollIntoView({ block: "center", behavior: "smooth" });
  m.el.classList.add("flash");
  setTimeout(() => m.el?.classList.remove("flash"), 1200);
}

// --------------------------------------------------- menú de un mensaje

const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

function openMsgMenu(conv, m, x, y) {
  closeMsgMenu();
  if (m.sys) return;
  const menu = text("", "div", "msg-menu");
  menu.id = "msg-menu";
  menu.setAttribute("role", "menu");
  if (!m.deleted) {
    const row = text("", "div", "menu-reactions");
    for (const e of QUICK_REACTIONS) {
      const b = text(e, "button");
      b.type = "button";
      if (m.reactions?.[me.toLowerCase()] === e) b.classList.add("own");
      b.onclick = () => { closeMsgMenu(); myReact(conv, m, e); };
      row.append(b);
    }
    menu.append(row);
  }
  const item = (ic, label, fn, cls = "") => {
    const b = withIcon(ic, label, "button", `menu-item ${cls}`);
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.onclick = () => { closeMsgMenu(); fn(); };
    menu.append(b);
  };
  const canWrite = !isGroup(conv) || targetsOf(conv).length;
  if (!m.deleted && canWrite) item("reply", "Responder", () => startReply(m));
  if (!m.deleted && m.content.t === "text") item("copy", "Copiar", () => navigator.clipboard?.writeText(m.content.body));
  if (m.from === "me" && !m.deleted && m.content.t === "text" && canWrite) item("edit", "Editar", () => startEdit(m));
  item("trash", "Eliminar para mí", () => myDelete(conv, m, false), "danger");
  if (m.from === "me" && !m.deleted && canWrite) item("trash", "Eliminar para todos", () => myDelete(conv, m, true), "danger");
  document.body.append(menu);
  // Que no se salga de la pantalla
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(x, innerWidth - r.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, innerHeight - r.height - 8))}px`;
  setTimeout(() => document.addEventListener("pointerdown", outsideMenu, { once: true }), 0);
}

function outsideMenu(e) {
  if (!$("msg-menu")?.contains(e.target)) closeMsgMenu();
  else document.addEventListener("pointerdown", outsideMenu, { once: true });
}

function closeMsgMenu() { $("msg-menu")?.remove(); }

const isNearBottom = () => { const l = $("messages"); return l.scrollHeight - l.scrollTop - l.clientHeight < 200; };

function viewImage(url, name) {
  const img = document.createElement("img");
  img.src = url;
  img.alt = name || "";
  img.className = "viewer";
  const a = document.createElement("a");
  a.href = url;
  a.download = name || "imagen";
  a.textContent = "Descargar";
  a.className = "chip";
  dialog(name || "Imagen", [img, a]);
}

function updateTitle() {
  const n = [...chats.keys()].reduce((s, p) => s + unreadOf(p), 0);
  document.title = n ? `(${n}) SecureChat` : "SecureChat";
  if ("setAppBadge" in navigator) (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
}

function dialog(title, body, actions = [["Cerrar"]]) {
  $("dlg-title").textContent = title;
  $("dlg-body").replaceChildren(...body);
  $("dlg-actions").replaceChildren(...actions.map(([label, fn], i) => {
    const b = text(label, "button", i === actions.length - 1 ? "primary" : "ghost");
    b.value = label;
    b.onclick = () => { fn?.(); };
    return b;
  }));
  if (!$("dialog").open) $("dialog").showModal();
}

function download(name, content) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type: "application/json" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ------------------------------------------------------------- arranque

let installPrompt = null;
window.addEventListener("beforeinstallprompt", (e) => {
  e.preventDefault();
  installPrompt = e;
  $("install-btn").hidden = false;
});

/** Si este dispositivo recuerda la sesión, entramos sin pedir contraseña. */
async function autoLogin() {
  const last = store.get("sc:last");
  const blob = last && store.get(idKey(last));
  if (!blob) return false;
  const seed = await Vault.recall(last);
  if (!seed) return false;
  const kp = sodium.crypto_sign_seed_keypair(seed);
  if (!P.equal(kp.publicKey, P.b64d(blob.public_key))) { await Vault.forget(last); return false; }
  identity = { seed, publicKey: kp.publicKey, privateKey: kp.privateKey };
  await startApp(blob.username || last);
  return true;
}

async function main() {
  await P.ready();
  const last = store.get("sc:last");
  $("login-name").value = last || "";
  $("login-name").addEventListener("input", updateLoginMode);
  $("login-form").addEventListener("submit", onLogin);
  $("to-register").onclick = () => setAuthMode("register");
  $("to-login").onclick = () => setAuthMode("login");
  $("composer").addEventListener("submit", onSend);
  $("text").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !prefs().enterSends && window.matchMedia("(pointer: fine)").matches) {
      e.preventDefault();
      insertAtCursor($("text"), "\n");
    }
  });
  $("new-chat").addEventListener("submit", onNewChat);
  $("new-chat-name").addEventListener("input", () => { $("new-chat-error").hidden = true; });
  $("profile-btn").onclick = showMyProfile;
  $("peer-btn").onclick = () => active && showPeerProfile(active);
  $("logout-btn").onclick = () => { if (confirm("¿Cerrar sesión en este dispositivo? Tendrás que volver a escribir tu contraseña.")) logout(); };
  $("theme-btn").onclick = showSettings;
  $("login-theme-btn").onclick = showSettings;
  $("emoji-btn").onclick = togglePicker;
  $("attach-btn").onclick = () => $("file-input").click();
  $("file-input").onchange = () => { sendFile($("file-input").files[0]); $("file-input").value = ""; };
  for (const b of document.querySelectorAll(".picker-tabs button")) b.onclick = () => { pickerTab = b.dataset.tab; renderPicker(); };
  $("text").addEventListener("paste", (e) => {
    const f = e.clipboardData?.files?.[0];
    if (f) { e.preventDefault(); sendFile(f); }
  });
  const chatEl = $("chat");
  chatEl.addEventListener("dragover", (e) => { if (active && e.dataTransfer.types.includes("Files")) { e.preventDefault(); $("drop-hint").hidden = false; } });
  chatEl.addEventListener("dragleave", (e) => { if (!chatEl.contains(e.relatedTarget)) $("drop-hint").hidden = true; });
  chatEl.addEventListener("drop", (e) => { e.preventDefault(); $("drop-hint").hidden = true; sendFile(e.dataTransfer.files[0]); });
  $("back-btn").onclick = () => { active = null; closePicker(); $("app").classList.remove("in-chat"); renderContacts(); renderChat(); };
  $("install-btn").onclick = async () => { await installPrompt?.prompt(); installPrompt = null; $("install-btn").hidden = true; };
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if ($("msg-menu")) closeMsgMenu();
    else if (!$("picker").hidden) closePicker();
    else if (!$("reply-bar").hidden) cancelReply();
  });
  $("text").addEventListener("input", onTypingInput);
  $("text").addEventListener("blur", stopTyping);
  $("reply-cancel").onclick = cancelReply;
  $("mic-btn").onclick = startRecording;
  $("rec-cancel").onclick = () => stopRecording(true);
  $("rec-send").onclick = () => stopRecording(false);
  $("new-group-btn").onclick = showNewGroup;
  // Menú de hamburguesa
  const menu = $("app-menu"), menuBtn = $("menu-btn");
  const closeMenu = () => { menu.hidden = true; menuBtn.setAttribute("aria-expanded", "false"); };
  menuBtn.onclick = (e) => {
    e.stopPropagation();
    menu.querySelector('[data-action="install"]').hidden = !installPrompt;
    menu.hidden = !menu.hidden;
    menuBtn.setAttribute("aria-expanded", String(!menu.hidden));
    if (!menu.hidden) menu.querySelector("button").focus();
  };
  document.addEventListener("pointerdown", (e) => { if (!menu.hidden && !menu.contains(e.target) && e.target !== menuBtn) closeMenu(); });
  menu.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeMenu(); menuBtn.focus(); } });
  menu.onclick = async (e) => {
    const action = e.target.closest("button")?.dataset.action;
    if (!action) return;
    closeMenu();
    if (action === "profile") showMyProfile();
    else if (action === "group") showNewGroup();
    else if (action === "settings") showSettings();
    else if (action === "backup") showBackup();
    else if (action === "install") { await installPrompt?.prompt(); installPrompt = null; }
    else if (action === "about") showAbout();
    else if (action === "logout") $("logout-btn").click();
  };
  $("messages").addEventListener("scroll", closeMsgMenu, { passive: true });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    wakeUp();
    if (active) markRead(active);
  });
  window.addEventListener("online", wakeUp);
  window.addEventListener("focus", wakeUp);
  window.addEventListener("pageshow", wakeUp);
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () =>
    window.applyTheme(document.documentElement.dataset.theme));
  $("login-code").value = store.get("sc:code") || "";
  $("use-here-btn").onclick = useHere;
  $("down-retry").onclick = async () => { if (await probe()) { showDown(false); if (client) reconnect(); } };
  const up = await probe();
  updateLoginMode();
  if (!await autoLogin()) {
    if (!up) showDown(true);
    if ($("login-name").value) $("login-pass").focus(); else $("login-name").focus();
  } else if (!up) {
    showDown(true);
  }
  if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("sw.js");
}

main();
