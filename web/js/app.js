// Interfaz web. Toda la criptografía ocurre aquí, en el navegador:
// el servidor solo recibe mensajes ya cifrados (texto, fotos, vídeos y perfiles).

import { ChatClient, ClientError, Contacts, IMAGE_MIME, MAX_MEDIA, TIMER_OPTIONS, VIDEO_MIME } from "./client.js";
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
      await startApp(name, { mustConnect: true, email: $("login-email").value.trim() || null, blob, isNew: true });
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

async function startApp(username, { mustConnect = false, email = null, blob = null, isNew = false } = {}) {
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
  chatMeta = store.get(metaKey()) || {};
  showArchived = false;
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
  // Solo al crear la cuenta: al volver a entrar o desde otro dispositivo no se pregunta
  if (isNew) showMyProfile({ welcome: true });
  if (isNew) seclog("Has creado tu cuenta en este dispositivo.");
  else if (blob) seclog("Has iniciado sesión en este dispositivo.");
  sweepExpired();
  checkInvite();
  runScheduled();
}

const sendPrivacy = () => client?.setPrivacy({ lastSeen: prefs().lastSeen, status: prefs().status });

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
  sendPrivacy();
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

// Ajustes de cada chat (fijado, silenciado, archivado…). Solo en este dispositivo.
const metaKey = () => `sc:chatmeta:${me.toLowerCase()}`;
let chatMeta = {};
let showArchived = false;
const meta = (conv) => chatMeta[conv] || {};
function setMeta(conv, patch) {
  const next = { ...meta(conv), ...patch };
  for (const k of Object.keys(next)) if (next[k] == null || next[k] === false) delete next[k];
  if (Object.keys(next).length) chatMeta[conv] = next; else delete chatMeta[conv];
  store.set(metaKey(), chatMeta);
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
  if (!entry.sys && meta(conv).hidden) setMeta(conv, { hidden: null });
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
      if (same(ev.peer, me)) break; // mi propia presencia (por mis otros dispositivos): no es un chat
      chat(ev.peer).online = ev.text === "online";
      chat(ev.peer).away = !!ev.content?.away;
      if (ev.content?.lastSeen) chat(ev.peer).lastSeen = ev.content.lastSeen;
      if (ev.text === "online") flushAll();
      if (ev.peer === active) renderHeader();
      break;
    case "session":
      chat(ev.peer).online = true;
      sysOnce(ev.peer, "Los mensajes y archivos de este chat están cifrados de extremo a extremo.");
      if (ev.peer === active) renderHeader();
      break;
    case "new_device":
      seclog("Se ha vinculado un dispositivo nuevo a tu cuenta.");
      toast("Se ha vinculado un dispositivo nuevo a tu cuenta. Si no has sido tú, desvincúlalo en Mi perfil → Tus dispositivos.");
      break;
    case "identity_changed":
      seclog(`La clave de seguridad de @${ev.peer} ha cambiado.`);
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
      groups.set(c.g, { id: c.g, name: c.name, members: c.members, admin: c.admin, admins: c.admins, muted: c.muted, v: c.v, avatar: c.avatar,
        left: !c.members.some((x) => same(x, me)), ...(existing?.invite ? { invite: existing.invite } : {}) });
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
  if (c.t === "react" || c.t === "edit" || c.t === "delete" || c.t === "vote") return applyAction(conv, me, c);
  if (c.t === "timer") return setTimer(conv, c.secs);
  if (c.t === "call" || c.t === "join") return;
  if (c.t === "typing" || c.t === "receipt" || c.t === "profile") return;
  if (c.mid && chat(conv).messages.some((m) => m.id === c.mid)) return; // ya lo tenemos
  const entry = { from: "me", content: { ...c, data: undefined }, status: "sent", to: [],
    ...(c.mid ? { id: c.mid } : {}), ...(ev.queuedAt ? { time: new Date(ev.queuedAt * 1000) } : {}),
    ...(isGroup(conv) ? { receipts: {} } : {}) };
  if (c.exp) entry.expires = (entry.time ? entry.time.getTime() : Date.now()) + c.exp * 1000;
  if (c.once) { addMsg(conv, entry); return; } // ver una vez: mis otros dispositivos no guardan la foto
  if (MEDIA_TYPES.has(c.t)) {
    const bytes = sodium.from_base64(c.data, sodium.base64_variants.ORIGINAL);
    entry.url = URL.createObjectURL(new Blob([bytes], { type: c.t === "file" ? "application/octet-stream" : c.mime }));
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
  if (c.t === "call") return onCallSignal(sender, c, ev.queuedAt);
  if (c.t === "join") return onJoinRequest(sender, c);
  if (c.t === "group") return onGroupState(sender, c);
  if (c.t === "group-leave") return onGroupLeave(sender, c.g);
  if (c.g && !memberOf(c.g, sender)) return; // grupo desconocido o no es miembro: se ignora
  if (c.g && isMutedIn(groups.get(c.g), sender) && !["typing", "receipt", "react", "vote", "delete"].includes(c.t)) return;
  const conv = c.g ? `#${c.g}` : sender;
  if (c.t === "typing") return showTyping(conv, sender, c.on);
  if (c.t === "react" || c.t === "edit" || c.t === "delete" || c.t === "vote") return applyAction(conv, sender, c);
  if (c.t === "timer") return setTimer(conv, c.secs, { who: sender });
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
  if (c.exp) entry.expires = (entry.time ? entry.time.getTime() : Date.now()) + c.exp * 1000;
  if (MEDIA_TYPES.has(c.t)) {
    const bytes = sodium.from_base64(c.data, sodium.base64_variants.ORIGINAL);
    entry.url = URL.createObjectURL(new Blob([bytes], { type: c.t === "file" ? "application/octet-stream" : c.mime }));
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
  if (c.t === "vote") {
    if (m.content?.t !== "poll") return;
    const valid = c.choices.filter((n) => n < m.content.opts.length);
    const v = m.content.multi ? valid : valid.slice(0, 1);
    m.votes ??= {};
    if (v.length) m.votes[sender.toLowerCase()] = v; else delete m.votes[sender.toLowerCase()];
  } else if (c.t === "react") {
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
  const mentioned = isGroup(conv) && content.t === "text" && mentionsMe(content.body);
  if (meta(conv).mute && !mentioned) return;
  if (!document.hidden || !prefs().notifications || !("Notification" in window) || Notification.permission !== "granted") return;
  // No mostramos el contenido: la notificación podría verse con la pantalla bloqueada.
  const title = isGroup(conv) ? convName(conv) : displayName(sender);
  const who = isGroup(conv) ? `${displayName(sender)}: ` : "";
  new Notification(title, { body: who + (mentioned ? "Te ha mencionado" : content.t === "text" ? "Nuevo mensaje" : previewOf(content)), tag: conv });
}

// ------------------------------------------------------------------- grupos

function groupState(g) {
  return { t: "group", g: g.id, name: g.name, members: g.members, admin: g.admin, admins: adminsOf(g), muted: g.muted || [],
    v: g.v, avatar: g.avatar || null };
}

/** Administradores del grupo (los grupos antiguos solo tenían uno). */
const adminsOf = (g) => (g.admins?.length ? g.admins : g.admin ? [g.admin] : []);
const isAdminOf = (g, u) => !!g && adminsOf(g).some((x) => same(x, u));
const isMutedIn = (g, u) => !!g && (g.muted || []).some((x) => same(x, u));
/** ¿Puedo escribir en esta conversación? (en un grupo me pueden haber silenciado) */
const mutedHere = (conv) => isGroup(conv) && isMutedIn(groups.get(gidOf(conv)), me);

/** Estado de un grupo recibido: solo lo acepta del administrador. */
function onGroupState(sender, c) {
  const existing = groups.get(c.g);
  const valid = existing
    ? isAdminOf(existing, sender) && c.v > existing.v
    : (same(sender, c.admin) || c.admins.some((x) => same(x, sender))) && c.members.some((x) => same(x, sender));
  if (!valid) return;
  const conv = `#${c.g}`;
  const inside = c.members.some((x) => same(x, me));
  const wasInside = existing && !existing.left;
  groups.set(c.g, { id: c.g, name: c.name, members: c.members, admin: c.admin, admins: c.admins, muted: c.muted, v: c.v,
    avatar: c.avatar, left: !inside, ...(existing?.invite ? { invite: existing.invite } : {}) });
  saveGroups();
  if (existing && inside) {
    const was = (list, u) => (list || []).some((x) => same(x, u));
    for (const u of c.admins) if (!was(adminsOf(existing), u)) addMsg(conv, { sys: `${same(u, me) ? "Ahora eres" : `${displayName(u)} ahora es`} administrador del grupo.` });
    for (const u of c.muted) if (!was(existing.muted, u)) addMsg(conv, { sys: same(u, me) ? `${displayName(sender)} te ha silenciado: solo puedes leer.` : `${displayName(sender)} ha silenciado a ${displayName(u)}.` });
    for (const u of existing.muted || []) if (!was(c.muted, u) && c.members.some((x) => same(x, u))) addMsg(conv, { sys: same(u, me) ? "Ya puedes volver a escribir en el grupo." : `${displayName(u)} ya puede escribir.` });
  }
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
  g.admins = adminsOf(g).filter((x) => !same(x, sender));
  g.muted = (g.muted || []).filter((x) => !same(x, sender));
  if (!g.admins.length && g.members.length) {
    g.admins = [[...g.members].sort((a, b) => a.localeCompare(b))[0]];
    if (same(g.admins[0], me) && !g.left) { g.v = Date.now(); queueAction(`#${gid}`, groupState(g)); }
  }
  g.admin = g.admins[0] || g.admin;
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
    chat(info.user).away = info.away;
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
  closeSearch();
  if (meta(conv).unread) setMeta(conv, { unread: null });
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
    chat(conv).away = info.away;
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
async function send(content, opts = {}) {
  if (active) return sendTo(active, content, opts);
}

async function sendTo(conv, content, { bytes = null, url = null } = {}) {
  if (isGroup(conv) && !targetsOf(conv).length) {
    addMsg(conv, { sys: groups.get(gidOf(conv))?.left ? "Ya no estás en este grupo." : "El grupo no tiene más miembros.", warn: true }, { persist: false });
    return;
  }
  const mid = newId();
  const replying = conv === active ? replyingTo : null;
  const timer = meta(conv).timer || 0;
  const full = { ...content, mid, ...(timer ? { exp: timer } : {}), ...(replying ? { reply: replying } : {}) };
  if (conv === active) cancelReply();
  const m = addMsg(conv, { id: mid, from: "me", content: { ...full, data: undefined }, status: "sending",
    ...(timer ? { expires: Date.now() + timer * 1000 } : {}),
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
      if (!m.to.length && m.status === "sending") {
        setStatus(conv, m, "sent");
        if (m.content.once) { history?.removeMedia(conv, m.id); if (m.url) URL.revokeObjectURL(m.url); delete m.url; m.hasMedia = false; save(conv, m); }
      }
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

async function sendFile(file, asDoc = false, once = false) {
  if (!file || !active) return;
  if (file.size > MAX_MEDIA) return addMsg(active, { sys: `El archivo pesa ${(file.size / 1048576).toFixed(1)} MB. El máximo es 8 MB.`, warn: true }, { persist: false });
  const isImage = IMAGE_MIME.includes(file.type), isVideo = VIDEO_MIME.includes(file.type);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!asDoc && (isImage || isVideo)) {
    await send({ t: isImage ? "image" : "video", mime: file.type, name: file.name.slice(0, 120), ...(once ? { once: true } : {}) },
      { bytes, url: URL.createObjectURL(file) });
    return;
  }
  // Cualquier otro archivo viaja como documento: nunca se abre dentro de la app, solo se descarga
  await send({ t: "file", mime: file.type || "application/octet-stream", name: file.name.slice(0, 120) || "archivo", size: file.size },
    { bytes, url: null });
}

const MEDIA_TYPES = new Set(["image", "video", "audio", "file"]);

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${Math.round(n / 1024)} KB`;
  return `${(n / 1048576).toFixed(1).replace(".", ",")} MB`;
}

function downloadBytes(bytes, name) {
  // Siempre como binario genérico: un HTML recibido nunca se ejecuta en nuestra web
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// ------------------------------------------------------------- encuestas

function showNewPoll() {
  if (!active) return;
  const q = input("", { max: 200, placeholder: "¿Qué quieres preguntar?" });
  const optsBox = text("", "div", "poll-edit");
  const more = withIcon("plus", "Añadir opción", "button", "chip");
  more.type = "button";
  const addOpt = () => {
    const i = input("", { max: 100, placeholder: `Opción ${optsBox.children.length + 1}` });
    optsBox.append(i);
    more.hidden = optsBox.children.length >= 12;
    return i;
  };
  addOpt();
  addOpt();
  more.onclick = () => addOpt().focus();
  const multi = text("", "label", "switch");
  const cb = document.createElement("input");
  cb.type = "checkbox";
  const sp = text("", "span");
  sp.append(text("Permitir varias respuestas", "strong"), text("Cada persona podrá marcar más de una opción.", "small"));
  multi.append(cb, sp);
  const err = text("", "p", "error");
  dialog("Nueva encuesta", [field("Pregunta", q), text("Opciones", "h3", "settings-h"), optsBox, more, multi, err],
    [["Cancelar"], ["Enviar encuesta", () => {
      const opts = [...new Set([...optsBox.querySelectorAll("input")].map((i) => i.value.trim()).filter(Boolean))];
      if (!q.value.trim() || opts.length < 2) {
        err.textContent = "Escribe la pregunta y al menos dos opciones distintas.";
        setTimeout(() => $("dialog").showModal());
        return;
      }
      send({ t: "poll", q: q.value.trim().slice(0, 200), opts: opts.slice(0, 12), multi: cb.checked });
    }]]);
  q.focus();
}

function buildPoll(conv, m, c) {
  const box = text("", "div", "poll");
  box.append(withIcon("poll", "Encuesta", "span", "poll-tag"), text(c.q, "strong", "poll-q"));
  const votes = m.votes || {};
  const voters = Object.keys(votes).filter((u) => votes[u]?.length);
  const mine = votes[me.toLowerCase()] || [];
  c.opts.forEach((opt, i) => {
    const who = voters.filter((u) => votes[u].includes(i));
    const b = text("", "button", `poll-opt${mine.includes(i) ? " chosen" : ""}`);
    b.type = "button";
    const bar = text("", "span", "poll-bar");
    bar.style.width = voters.length ? `${Math.round((who.length / voters.length) * 100)}%` : "0%";
    const check = text("", "span", `poll-check${c.multi ? " multi" : ""}`);
    if (mine.includes(i)) check.append(icon("check"));
    b.append(bar, check, text(opt, "span", "poll-label"), text(String(who.length), "span", "poll-count"));
    b.title = who.map((u) => (same(u, me) ? "Tú" : displayName(u))).join(", ") || "Nadie todavía";
    b.onclick = (e) => { e.stopPropagation(); myVote(conv, m, i); };
    box.append(b);
  });
  box.append(text(`${voters.length} ${voters.length === 1 ? "voto" : "votos"}${c.multi ? " · varias respuestas" : ""}`, "small", "poll-total"));
  return box;
}

function myVote(conv, m, i) {
  m.votes ??= {};
  const k = me.toLowerCase();
  let cur = m.votes[k] || [];
  if (m.content.multi) cur = cur.includes(i) ? cur.filter((x) => x !== i) : [...cur, i];
  else cur = cur[0] === i ? [] : [i];
  if (cur.length) m.votes[k] = cur; else delete m.votes[k];
  save(conv, m);
  queueAction(conv, { t: "vote", target: m.id, choices: cur });
}

// ------------------------------------------------------------- mensajes temporales

const TIMER_LABEL = { 86400: "24 horas", 604800: "7 días", 7776000: "90 días" };

function showTimer(conv) {
  const cur = meta(conv).timer || 0;
  const box = text("", "div", "timer-options");
  for (const secs of TIMER_OPTIONS) {
    const l = text("", "label", "switch");
    const r = document.createElement("input");
    r.type = "radio";
    r.name = "timer";
    r.checked = secs === cur;
    r.onchange = () => { $("dialog").close(); setTimer(conv, secs, { send: true }); };
    const sp = text("", "span");
    sp.append(text(secs ? TIMER_LABEL[secs] : "Desactivados", "strong"));
    l.append(r, sp);
    box.append(l);
  }
  dialog("Mensajes temporales", [
    text("Los mensajes nuevos de este chat se borrarán solos de todos los dispositivos cuando pase el tiempo elegido. Los que ya hay no cambian.", "p", "hint"),
    box,
    text("Ojo: nada impide que alguien haga una captura de pantalla antes de que se borren.", "p", "hint"),
  ]);
}

function setTimer(conv, secs, { who = me, send: share = false } = {}) {
  if ((meta(conv).timer || 0) === secs) return;
  setMeta(conv, { timer: secs || null });
  const what = secs ? `activado los mensajes temporales (${TIMER_LABEL[secs]})` : "desactivado los mensajes temporales";
  addMsg(conv, { sys: `${same(who, me) ? "Has" : `${displayName(who)} ha`} ${what}.` });
  if (share) queueAction(conv, { t: "timer", secs });
  if (conv === active) renderHeader();
}

/** Borra los mensajes caducados (de la pantalla y del historial cifrado). */
function sweepExpired() {
  const now = Date.now();
  let changed = false;
  for (const [conv, ch] of chats) {
    const gone = ch.messages.filter((m) => m.expires && m.expires <= now);
    if (!gone.length) continue;
    ch.messages = ch.messages.filter((m) => !(m.expires && m.expires <= now));
    for (const m of gone) {
      if (m.url) URL.revokeObjectURL(m.url);
      m.el?.remove();
      history?.remove(conv, m.id);
    }
    if (gone.some((m) => m.id === meta(conv).pinMsg)) setMeta(conv, { pinMsg: null });
    changed = true;
  }
  if (changed) { renderContacts(); updateTitle(); renderPinned(); }
}

// ------------------------------------------------------------- destacados

function showStarred(only = null) {
  const rows = [];
  for (const [conv, ch] of chats) {
    if (only && conv !== only) continue;
    for (const m of ch.messages) if (m.starred && !m.deleted) rows.push([conv, m]);
  }
  rows.sort((a, b) => b[1].time - a[1].time);
  const list = text("", "div", "starred-list");
  if (!rows.length) list.append(text("No hay mensajes destacados. Mantén pulsado un mensaje (o clic derecho) y elige «Destacar».", "p", "hint"));
  for (const [conv, m] of rows) {
    const b = text("", "button", "starred-row");
    b.type = "button";
    const who = m.from === "me" ? "Tú" : displayName(m.sender || conv);
    const head = text("", "span", "starred-head");
    head.append(text(isGroup(conv) ? `${who} · ${convName(conv)}` : m.from === "me" ? `Tú → ${convName(conv)}` : who, "strong"),
      text(shortTime(m.time), "time"));
    b.append(head, text(previewOf(m.content), "span", "starred-text"));
    b.onclick = () => { $("dialog").close(); openChat(conv); setTimeout(() => jumpTo(m.id), 250); };
    list.append(b);
  }
  dialog(only ? "Destacados de este chat" : "Mensajes destacados", [list], only ? [["Cerrar"]] : subActions());
}

// ------------------------------------------------------------- registro de seguridad

const seclogKey = () => `sc:seclog:${me.toLowerCase()}`;

function seclog(msg) {
  if (!me) return;
  const list = store.get(seclogKey()) || [];
  list.unshift({ t: Date.now(), text: msg });
  store.set(seclogKey(), list.slice(0, 200));
}

function showSecLog() {
  const list = store.get(seclogKey()) || [];
  const box = text("", "div", "seclog");
  if (!list.length) box.append(text("Todavía no hay nada registrado.", "p", "hint"));
  for (const e of list) {
    const row = text("", "div", "seclog-row");
    row.append(text(new Date(e.t).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" }), "time"), text(e.text, "span"));
    box.append(row);
  }
  const clear = text("Borrar registro", "button", "chip danger");
  clear.type = "button";
  clear.onclick = () => { store.set(seclogKey(), []); showSecLog(); };
  dialog("Registro de seguridad", [
    text("Lo importante que pasa con tu cuenta y tus claves. Se guarda solo en este dispositivo.", "p", "hint"),
    box, ...(list.length ? [clear] : []),
  ], subActions());
}

function toast(msg) {
  const t = text(msg, "div", "toast");
  t.setAttribute("role", "status");
  document.body.append(t);
  setTimeout(() => t.classList.add("out"), 7000);
  setTimeout(() => t.remove(), 7600);
}

// ------------------------------------------------------------- enlaces de invitación

const INVITE_RE = /^#unirse=([A-Za-z0-9_-]{8,32})~([0-9a-f]{32})~([^~]{1,80})$/;
const inviteUrl = (g) => `${location.origin}${location.pathname}#unirse=${g.id}~${g.invite}~${encodeURIComponent(me)}`;

function inviteBox(g) {
  const box = text("", "div", "invite-box");
  const draw = () => {
    box.replaceChildren();
    if (!g.invite) {
      const mk = withIcon("link", "Crear enlace de invitación", "button", "chip");
      mk.type = "button";
      mk.onclick = () => { g.invite = sodium.to_hex(sodium.randombytes_buf(16)); saveGroups(); draw(); };
      box.append(mk, text("Quien abra el enlace podrá pedir unirse y entrará automáticamente.", "p", "hint"));
      return;
    }
    const url = inviteUrl(g);
    const out = input(url);
    out.readOnly = true;
    out.className = "filter-input";
    out.onclick = () => out.select();
    const copy = withIcon("copy", "Copiar", "button", "chip");
    copy.type = "button";
    copy.onclick = async () => {
      try { await navigator.clipboard.writeText(url); copy.replaceChildren(icon("check", "inline-ico"), "Copiado"); }
      catch { out.select(); }
    };
    const row = text("", "div", "chip-row");
    row.append(copy);
    if (navigator.share) {
      const sh = withIcon("share", "Compartir", "button", "chip");
      sh.type = "button";
      sh.onclick = () => navigator.share({ title: `Únete a «${g.name}» en SecureChat`, url }).catch(() => {});
      row.append(sh);
    }
    const reset = text("Anular enlace", "button", "chip danger");
    reset.type = "button";
    reset.onclick = () => { delete g.invite; saveGroups(); draw(); };
    row.append(reset);
    box.append(out, row, text("Entrarán cuando tengas la app abierta. Si el enlace llega a quien no debe, anúlalo y crea otro.", "p", "hint"));
  };
  draw();
  return box;
}

/** ¿Hemos llegado con un enlace de invitación? Pedimos unirnos (cifrado) al admin. */
async function checkInvite() {
  const m = INVITE_RE.exec(location.hash);
  if (!m || !client) return;
  window.history.replaceState(null, "", location.pathname + location.search);
  const [, gid, token, rawAdmin] = m;
  let admin;
  try { admin = decodeURIComponent(rawAdmin); } catch { return; }
  if (!NAME_RE.test(admin) || same(admin, me)) return;
  if (memberOf(gid, me)) { openChat(`#${gid}`); return; }
  dialog("Invitación a un grupo", [
    text(`@${admin} te ha invitado a un grupo de SecureChat.`, "p"),
    text("Si aceptas, se le envía tu petición cifrada y entrarás en cuanto tenga la app abierta.", "p", "hint"),
  ], [["Ahora no"], ["Pedir unirme", async () => {
    try {
      const info = await client.lookup(admin);
      if (!info.exists) { toast(`No existe @${admin}.`); return; }
      queueAction(info.user, { t: "join", g: gid, token }, [info.user]);
      addMsg(info.user, { sys: "Has pedido unirte a su grupo con un enlace de invitación." });
      toast("Petición enviada. Entrarás en el grupo en cuanto la acepte su app.");
    } catch (e) { toast(e.message); }
  }]]);
}

function onJoinRequest(sender, c) {
  const g = groups.get(c.g);
  if (!g || g.left || !isAdminOf(g, me) || !g.invite || c.token !== g.invite) return;
  if (g.members.some((x) => same(x, sender))) return;
  updateGroup(c.g, { members: [...g.members, sender] });
  addMsg(`#${c.g}`, { sys: `${displayName(sender)} se ha unido con el enlace de invitación.` });
}

// ------------------------------------------------------------- llamadas (WebRTC)
// La señalización (oferta y respuesta) viaja cifrada de extremo a extremo por el chat.
// El audio y el vídeo van directos entre los dos dispositivos, cifrados con DTLS-SRTP.

const ICE_SERVERS = [{ urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] }];
const RING_MS = 45000;
let call = null;
let ringTimer = null, ringCtx = null;

function callSignal(peer, content, queue = false) {
  return client.sendContent(peer, { t: "call", ...content }, queue ? { sync: false } : { ephemeral: true, sync: false }).catch(() => {});
}

function iceGathered(pc) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { if (pc.iceGatheringState === "complete") resolve(); };
    pc.addEventListener("icegatheringstatechange", done);
    setTimeout(resolve, 3000);
  });
}

async function getCallMedia(video) {
  if (!navigator.mediaDevices?.getUserMedia || !window.RTCPeerConnection) throw new Error("Este navegador no permite llamadas aquí (hace falta HTTPS).");
  try {
    return await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true },
      video: video ? { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } } : false,
    });
  } catch {
    throw new Error(video ? "No hay permiso para usar la cámara y el micrófono." : "No hay permiso para usar el micrófono.");
  }
}

function newPeerConnection(c) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  pc.ontrack = (e) => { if (call === c) { c.remote = e.streams[0]; renderCall(); } };
  pc.onconnectionstatechange = () => {
    if (call !== c) return;
    if (pc.connectionState === "connected" && c.state !== "active") {
      c.state = "active";
      c.startedAt = Date.now();
      stopRing();
      clearTimeout(c.timeout);
      c.tick = setInterval(updateCallTime, 1000);
      renderCall();
    } else if (pc.connectionState === "failed") {
      callSignal(c.peer, { kind: "end", id: c.id });
      endCall("No se pudo conectar la llamada: la red no permite la conexión directa.");
    }
  };
  return pc;
}

async function startCall(video) {
  const peer = active;
  if (!peer || isGroup(peer) || call || gcall) return;
  if (!connected) { alert("Sin conexión: espera a que vuelva."); return; }
  let local;
  try { local = await getCallMedia(video); } catch (e) { alert(e.message); return; }
  const c = { id: newId(), peer, video, local, role: "out", state: "calling", muted: false, camOff: false };
  call = c;
  c.pc = newPeerConnection(c);
  for (const tr of local.getTracks()) c.pc.addTrack(tr, local);
  renderCall();
  startRing("out");
  try {
    await c.pc.setLocalDescription(await c.pc.createOffer());
    await iceGathered(c.pc);
    if (call !== c) return;
    // La oferta sí se guarda en cola: si el otro tiene la app cerrada le llega un aviso
    await callSignal(peer, { kind: "offer", id: c.id, sdp: c.pc.localDescription.sdp, video }, true);
  } catch {
    endCall("No se pudo iniciar la llamada.");
    return;
  }
  c.timeout = setTimeout(() => {
    if (call === c && c.state === "calling") { callSignal(peer, { kind: "end", id: c.id }); endCall("No contesta"); }
  }, RING_MS);
}

function onCallSignal(sender, c, queuedAt) {
  if (c.g) return onGroupCallSignal(sender, c, queuedAt);
  if (c.kind === "offer") {
    if (queuedAt && Date.now() / 1000 - queuedAt > RING_MS / 1000) {
      addMsg(sender, { sys: `${c.video ? "Videollamada perdida" : "Llamada perdida"} de ${displayName(sender)}` });
      return;
    }
    if (call || gcall) { if (call?.id !== c.id) callSignal(sender, { kind: "busy", id: c.id }); return; }
    const inc = { id: c.id, peer: sender, video: c.video, role: "in", state: "incoming", offer: c.sdp, muted: false, camOff: false };
    call = inc;
    renderCall();
    startRing("in");
    if (document.hidden && prefs().notifications && "Notification" in window && Notification.permission === "granted") {
      new Notification(`${c.video ? "Videollamada" : "Llamada"} de ${displayName(sender)}`, { tag: "call", body: "Abre SecureChat para contestar" });
    }
    inc.timeout = setTimeout(() => {
      if (call === inc && inc.state === "incoming") endCall(`${c.video ? "Videollamada perdida" : "Llamada perdida"} de ${displayName(sender)}`);
    }, RING_MS);
    return;
  }
  if (!call || call.id !== c.id || !same(call.peer, sender)) return;
  const cur = call;
  if (c.kind === "answer" && cur.role === "out" && cur.state === "calling") {
    cur.state = "connecting";
    stopRing();
    clearTimeout(cur.timeout);
    cur.pc.setRemoteDescription({ type: "answer", sdp: c.sdp }).catch(() => endCall("No se pudo conectar la llamada."));
    callSignal(sender, { kind: "taken", id: c.id, dev: c.dev }); // sus otros dispositivos dejan de sonar
    cur.timeout = setTimeout(() => {
      if (call === cur && cur.state === "connecting") { callSignal(sender, { kind: "end", id: cur.id }); endCall("No se pudo conectar la llamada."); }
    }, 25000);
    renderCall();
  } else if (c.kind === "taken" && cur.role === "in" && cur.state === "incoming" && c.dev !== client.device) {
    endCall(null); // he contestado desde otro dispositivo
  } else if (c.kind === "reject" && cur.role === "out") {
    callSignal(sender, { kind: "end", id: cur.id });
    endCall("Llamada rechazada");
  } else if (c.kind === "busy" && cur.role === "out" && cur.state === "calling") {
    endCall(`${displayName(sender)} está en otra llamada`);
  } else if (c.kind === "end") {
    const missed = cur.role === "in" && cur.state === "incoming";
    endCall(missed ? `${cur.video ? "Videollamada perdida" : "Llamada perdida"} de ${displayName(sender)}` : cur.startedAt ? null : "Llamada cancelada");
  }
}

async function acceptCall() {
  const c = call;
  if (!c || c.state !== "incoming") return;
  stopRing();
  clearTimeout(c.timeout);
  c.state = "connecting";
  renderCall();
  try {
    c.local = await getCallMedia(c.video);
    if (call !== c) { c.local.getTracks().forEach((t) => t.stop()); return; }
    c.pc = newPeerConnection(c);
    for (const tr of c.local.getTracks()) c.pc.addTrack(tr, c.local);
    await c.pc.setRemoteDescription({ type: "offer", sdp: c.offer });
    await c.pc.setLocalDescription(await c.pc.createAnswer());
    await iceGathered(c.pc);
    if (call !== c) return;
    callSignal(c.peer, { kind: "answer", id: c.id, sdp: c.pc.localDescription.sdp, dev: client.device });
    renderCall();
    c.timeout = setTimeout(() => {
      if (call === c && c.state === "connecting") { callSignal(c.peer, { kind: "end", id: c.id }); endCall("No se pudo conectar la llamada."); }
    }, 25000);
  } catch (e) {
    callSignal(c.peer, { kind: "reject", id: c.id });
    endCall(e.message || "No se pudo contestar.");
  }
}

function rejectCall() {
  if (!call) return;
  callSignal(call.peer, { kind: "reject", id: call.id });
  endCall(`Has rechazado una ${call.video ? "videollamada" : "llamada"} de ${displayName(call.peer)}`);
}

function hangUp() {
  if (!call) return;
  callSignal(call.peer, { kind: "end", id: call.id });
  endCall(call.startedAt ? null : "Llamada cancelada");
}

function endCall(notice = null) {
  const c = call;
  if (!c) return;
  call = null;
  stopRing();
  clearTimeout(c.timeout);
  clearInterval(c.tick);
  c.local?.getTracks().forEach((t) => t.stop());
  try { c.pc?.close(); } catch { /* ya cerrada */ }
  const line = c.startedAt ? `${c.video ? "Videollamada" : "Llamada de voz"} · ${fmtDur(Math.round((Date.now() - c.startedAt) / 1000))}` : notice;
  if (line) addMsg(c.peer, { sys: line });
  $("call-screen")?.remove();
}

function renderCall() {
  const c = call;
  if (!c) return;
  let el = $("call-screen");
  if (!el) {
    el = text("", "div", "call-screen");
    el.id = "call-screen";
    el.setAttribute("role", "dialog");
    el.setAttribute("aria-label", "Llamada");
    const remote = document.createElement("video");
    remote.id = "call-remote";
    remote.autoplay = remote.playsInline = true;
    const local = document.createElement("video");
    local.id = "call-local";
    local.autoplay = local.playsInline = local.muted = true;
    const info = text("", "div", "call-info");
    info.id = "call-info";
    const btns = text("", "div", "call-buttons");
    btns.id = "call-buttons";
    el.append(remote, local, info, btns);
    document.body.append(el);
  }
  const remote = $("call-remote"), local = $("call-local");
  if (c.remote && remote.srcObject !== c.remote) remote.srcObject = c.remote;
  if (c.local && local.srcObject !== c.local) local.srcObject = c.local;
  el.dataset.video = c.video ? "1" : "";
  el.dataset.state = c.state;
  el.classList.toggle("cam-off", !!c.camOff);
  const status = {
    calling: "Llamando…", incoming: c.video ? "Videollamada entrante" : "Llamada entrante",
    connecting: "Conectando…", active: "",
  }[c.state];
  const st = text(status, "p", "call-status");
  st.id = "call-status";
  $("call-info").replaceChildren(setAvatar(text("", "span", "avatar xl"), displayName(c.peer), avatarOf(c.peer)),
    text(displayName(c.peer), "h2"), st, text("Cifrada de extremo a extremo", "p", "call-e2e"));
  const b = (ic, label, fn, cls = "") => {
    const x = text("", "button", `call-btn ${cls}`);
    x.type = "button";
    x.title = label;
    x.setAttribute("aria-label", label);
    x.append(icon(ic));
    x.onclick = fn;
    return x;
  };
  if (c.state === "incoming") {
    $("call-buttons").replaceChildren(b("call", "Rechazar", rejectCall, "hang"), b(c.video ? "video" : "call", "Contestar", acceptCall, "accept"));
  } else {
    $("call-buttons").replaceChildren(
      b(c.muted ? "mic_off" : "mic", c.muted ? "Activar micrófono" : "Silenciar micrófono", toggleMute, c.muted ? "off" : ""),
      ...(c.video ? [b(c.camOff ? "video_off" : "video", c.camOff ? "Encender cámara" : "Apagar cámara", toggleCam, c.camOff ? "off" : "")] : []),
      b("call", "Colgar", hangUp, "hang"));
  }
  updateCallTime();
}

function updateCallTime() {
  if (call?.state === "active" && $("call-status")) $("call-status").textContent = fmtDur(Math.round((Date.now() - call.startedAt) / 1000));
}

function toggleMute() {
  call.muted = !call.muted;
  call.local?.getAudioTracks().forEach((t) => { t.enabled = !call.muted; });
  renderCall();
}

function toggleCam() {
  call.camOff = !call.camOff;
  call.local?.getVideoTracks().forEach((t) => { t.enabled = !call.camOff; });
  renderCall();
}

// ------------------------------------------------------------- llamadas en grupo
// Malla: cada participante se conecta directamente con cada uno de los demás (hasta 4 personas).
// Para cada pareja, ofrece la conexión quien tiene el @usuario menor (así nunca se cruzan dos ofertas).
// Señales: ring (el que llama avisa a todos), joined (alguien entra), here (ya estoy dentro),
// offer/answer (por pareja) y left (alguien cuelga). Todas viajan cifradas por el chat.

const GROUP_CALL_MAX = 4;
let gcall = null;
const gkey = (u) => u.toLowerCase();

function gSignal(u, content, queue = false) {
  return callSignal(u, { ...content, id: gcall?.id || content.id, g: gcall?.g || content.g }, queue);
}

async function startGroupCall(video) {
  const conv = active;
  if (!conv || !isGroup(conv) || call || gcall) return;
  const members = targetsOf(conv);
  if (!members.length) return;
  if (members.length > GROUP_CALL_MAX - 1) { alert(`Las llamadas en grupo son de hasta ${GROUP_CALL_MAX} personas.`); return; }
  if (!connected) { alert("Sin conexión: espera a que vuelva."); return; }
  let local;
  try { local = await getCallMedia(video); } catch (e) { alert(e.message); return; }
  gcall = { id: newId(), g: gidOf(conv), video, local, state: "calling", peers: new Map(), muted: false, camOff: false };
  const c = gcall;
  renderGroupCall();
  startRing("out");
  for (const u of members) gSignal(u, { kind: "ring", video }, true);
  c.timeout = setTimeout(() => {
    if (gcall === c && !c.startedAt) { for (const u of members) gSignal(u, { kind: "left" }); endGroupCall("Nadie ha contestado"); }
  }, RING_MS);
}

function onGroupCallSignal(sender, c, queuedAt) {
  if (!memberOf(c.g, sender) || !memberOf(c.g, me)) return;
  const conv = `#${c.g}`;
  if (c.kind === "ring") {
    if (queuedAt && Date.now() / 1000 - queuedAt > RING_MS / 1000) {
      addMsg(conv, { sys: `${c.video ? "Videollamada" : "Llamada"} perdida de ${displayName(sender)}` });
      return;
    }
    if (call || gcall) return; // ya estoy en otra llamada
    gcall = { id: c.id, g: c.g, video: c.video, from: sender, state: "incoming", peers: new Map(), muted: false, camOff: false };
    const inc = gcall;
    renderGroupCall();
    startRing("in");
    if (document.hidden && prefs().notifications && "Notification" in window && Notification.permission === "granted") {
      new Notification(`${c.video ? "Videollamada" : "Llamada"} en ${convName(conv)}`, { tag: "call", body: `${displayName(sender)} te está llamando` });
    }
    inc.timeout = setTimeout(() => {
      if (gcall === inc && inc.state === "incoming") endGroupCall(`${c.video ? "Videollamada" : "Llamada"} perdida de ${displayName(sender)}`);
    }, RING_MS);
    return;
  }
  const cur = gcall;
  if (!cur || cur.id !== c.id) return;
  if (c.kind === "left") {
    dropPeer(sender);
    if (cur.state === "incoming" && same(sender, cur.from)) endGroupCall(`${cur.video ? "Videollamada" : "Llamada"} perdida de ${displayName(sender)}`);
    else if (cur.startedAt && !cur.peers.size) endGroupCall(null);
    return;
  }
  if (cur.state === "incoming") return; // aún no he contestado
  if (c.kind === "joined" || c.kind === "here") {
    if (c.kind === "joined") gSignal(sender, { kind: "here" });
    if (me.toLowerCase() < sender.toLowerCase()) connectPeer(sender);
  } else if (c.kind === "offer") {
    answerPeer(sender, c.sdp);
  } else if (c.kind === "answer") {
    const p = cur.peers.get(gkey(sender));
    p?.pc.setRemoteDescription({ type: "answer", sdp: c.sdp }).catch(() => dropPeer(sender));
  }
}

function groupPeer(u) {
  const c = gcall;
  const k = gkey(u);
  if (c.peers.has(k)) return null;
  if (c.peers.size >= GROUP_CALL_MAX - 1) return null;
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  const p = { user: u, pc, stream: null, connected: false };
  c.peers.set(k, p);
  for (const tr of c.local.getTracks()) pc.addTrack(tr, c.local);
  pc.ontrack = (e) => { if (gcall === c) { p.stream = e.streams[0]; renderGroupCall(); } };
  pc.onconnectionstatechange = () => {
    if (gcall !== c || c.peers.get(k) !== p) return;
    if (pc.connectionState === "connected") {
      p.connected = true;
      if (!c.startedAt) {
        c.startedAt = Date.now();
        c.state = "active";
        stopRing();
        clearTimeout(c.timeout);
        c.tick = setInterval(updateGroupCallTime, 1000);
      }
      renderGroupCall();
    } else if (pc.connectionState === "failed" || pc.connectionState === "closed") {
      dropPeer(u);
      if (c.startedAt && !c.peers.size) endGroupCall(null);
    }
  };
  renderGroupCall();
  return p;
}

async function connectPeer(u) {
  const c = gcall;
  const p = groupPeer(u);
  if (!p) return;
  try {
    await p.pc.setLocalDescription(await p.pc.createOffer());
    await iceGathered(p.pc);
    if (gcall === c) gSignal(u, { kind: "offer", sdp: p.pc.localDescription.sdp });
  } catch { dropPeer(u); }
}

async function answerPeer(u, sdp) {
  const c = gcall;
  const p = groupPeer(u);
  if (!p) return;
  try {
    await p.pc.setRemoteDescription({ type: "offer", sdp });
    await p.pc.setLocalDescription(await p.pc.createAnswer());
    await iceGathered(p.pc);
    if (gcall === c) gSignal(u, { kind: "answer", sdp: p.pc.localDescription.sdp });
  } catch { dropPeer(u); }
}

function dropPeer(u) {
  const c = gcall;
  const p = c?.peers.get(gkey(u));
  if (!p) return;
  c.peers.delete(gkey(u));
  try { p.pc.close(); } catch { /* ya cerrada */ }
  renderGroupCall();
}

async function acceptGroupCall() {
  const c = gcall;
  if (!c || c.state !== "incoming") return;
  stopRing();
  clearTimeout(c.timeout);
  try { c.local = await getCallMedia(c.video); }
  catch (e) { endGroupCall(e.message); return; }
  if (gcall !== c) { c.local.getTracks().forEach((t) => t.stop()); return; }
  c.state = "joining";
  renderGroupCall();
  for (const u of targetsOf(`#${c.g}`)) gSignal(u, { kind: "joined" });
  c.timeout = setTimeout(() => { if (gcall === c && !c.startedAt) hangUpGroup("No se pudo conectar la llamada."); }, 30000);
}

function hangUpGroup(notice = null) {
  const c = gcall;
  if (!c) return;
  if (c.state !== "incoming") for (const u of targetsOf(`#${c.g}`)) gSignal(u, { kind: "left" });
  endGroupCall(c.state === "incoming" ? null : notice);
}

function endGroupCall(notice = null) {
  const c = gcall;
  if (!c) return;
  gcall = null;
  stopRing();
  clearTimeout(c.timeout);
  clearInterval(c.tick);
  c.local?.getTracks().forEach((t) => t.stop());
  for (const p of c.peers.values()) { try { p.pc.close(); } catch { /* ya cerrada */ } }
  const line = c.startedAt ? `${c.video ? "Videollamada" : "Llamada"} de grupo · ${fmtDur(Math.round((Date.now() - c.startedAt) / 1000))}` : notice;
  if (line) addMsg(`#${c.g}`, { sys: line });
  $("call-screen")?.remove();
}

function renderGroupCall() {
  const c = gcall;
  if (!c) return;
  let el = $("call-screen");
  if (!el) {
    el = text("", "div", "call-screen group");
    el.id = "call-screen";
    el.setAttribute("role", "dialog");
    el.setAttribute("aria-label", "Llamada de grupo");
    const info = text("", "div", "call-info");
    info.id = "call-info";
    const grid = text("", "div", "call-grid");
    grid.id = "call-grid";
    const btns = text("", "div", "call-buttons");
    btns.id = "call-buttons";
    el.append(info, grid, btns);
    document.body.append(el);
  }
  el.dataset.video = c.video ? "1" : "";
  el.dataset.state = c.state;
  const conv = `#${c.g}`;
  const status = { calling: "Llamando al grupo…", incoming: `${displayName(c.from)} te está llamando`, joining: "Entrando…", active: "" }[c.state];
  const st = text(status, "p", "call-status");
  st.id = "call-status";
  $("call-info").replaceChildren(text(convName(conv), "h2"), st,
    text(`${c.video ? "Videollamada" : "Llamada"} de grupo · cifrada de extremo a extremo`, "p", "call-e2e"));
  // Mosaico: yo y cada participante conectado
  c.videos ??= new Map();
  const tile = (name, avatar, stream, mine = false) => {
    const t = text("", "div", `call-tile${mine ? " mine" : ""}`);
    const key = mine ? " yo" : name;
    let v = c.videos.get(key);
    if (!v) {
      v = document.createElement("video");
      v.autoplay = true;
      v.playsInline = true;
      if (mine) v.muted = true;
      c.videos.set(key, v);
    }
    if (stream && v.srcObject !== stream) v.srcObject = stream;
    if (v.paused && v.srcObject) v.play().catch(() => {});
    const showVideo = c.video && stream && !(mine && c.camOff);
    v.hidden = !showVideo;
    t.append(v);
    if (!showVideo) t.append(setAvatar(text("", "span", "avatar xl"), name, avatar));
    t.append(text(name, "span", "tile-name"));
    return t;
  };
  const tiles = [];
  if (c.state !== "incoming") tiles.push(tile("Tú", profile.avatar, c.local, true));
  for (const p of c.peers.values()) tiles.push(tile(displayName(p.user), avatarOf(p.user), p.stream));
  if (c.state === "incoming") tiles.push(tile(displayName(c.from), avatarOf(c.from), null));
  // Los <video> se reutilizan entre repintados para no cortar el audio
  const grid = $("call-grid");
  grid.dataset.n = String(tiles.length);
  grid.replaceChildren(...tiles);
  const b = (ic, label, fn, cls = "") => {
    const x = text("", "button", `call-btn ${cls}`);
    x.type = "button";
    x.title = label;
    x.setAttribute("aria-label", label);
    x.append(icon(ic));
    x.onclick = fn;
    return x;
  };
  if (c.state === "incoming") {
    $("call-buttons").replaceChildren(b("call", "Rechazar", () => hangUpGroup(), "hang"),
      b(c.video ? "video" : "call", "Unirme", acceptGroupCall, "accept"));
  } else {
    $("call-buttons").replaceChildren(
      b(c.muted ? "mic_off" : "mic", c.muted ? "Activar micrófono" : "Silenciar micrófono", () => {
        c.muted = !c.muted; c.local?.getAudioTracks().forEach((t) => { t.enabled = !c.muted; }); renderGroupCall();
      }, c.muted ? "off" : ""),
      ...(c.video ? [b(c.camOff ? "video_off" : "video", c.camOff ? "Encender cámara" : "Apagar cámara", () => {
        c.camOff = !c.camOff; c.local?.getVideoTracks().forEach((t) => { t.enabled = !c.camOff; }); renderGroupCall();
      }, c.camOff ? "off" : "")] : []),
      b("call", "Colgar", () => hangUpGroup(), "hang"));
  }
  updateGroupCallTime();
}

function updateGroupCallTime() {
  if (gcall?.startedAt && $("call-status")) {
    $("call-status").textContent = `${fmtDur(Math.round((Date.now() - gcall.startedAt) / 1000))} · ${gcall.peers.size + 1} personas`;
  }
}

function startRing(dir) {
  stopRing();
  const beep = () => {
    try {
      ringCtx ??= new AudioContext();
      const t0 = ringCtx.currentTime;
      const o = ringCtx.createOscillator(), g = ringCtx.createGain();
      o.frequency.value = dir === "in" ? 660 : 425;
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(0.12, t0 + 0.04);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + (dir === "in" ? 0.8 : 1.1));
      o.connect(g).connect(ringCtx.destination);
      o.start(t0);
      o.stop(t0 + 1.2);
    } catch { /* sin audio */ }
    if (dir === "in") navigator.vibrate?.([300, 150, 300]);
  };
  beep();
  ringTimer = setInterval(beep, dir === "in" ? 2000 : 3000);
}

function stopRing() {
  clearInterval(ringTimer);
  ringTimer = null;
  navigator.vibrate?.(0);
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

function showMyProfile({ welcome = false } = {}) {
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

  const save = () => {
    profile = { name: nameIn.value.trim().slice(0, 64) || me, bio: bioIn.value.trim().slice(0, 140), avatar };
    if (!store.set(`sc:profile:${me.toLowerCase()}`, profile)) profile.avatar = null;
    client.setProfile(profile, client.contacts.all().map((c) => c.name));
    renderMe();
  };
  if (welcome) {
    // Primera vez: solo nombre visible y foto, sin distraer con lo demás
    dialog("¡Bienvenido a SecureChat!", [
      text("Elige cómo te verán los demás. Puedes cambiarlo cuando quieras desde Mi perfil.", "p", "hint"),
      head,
      field("Tu nombre", nameIn, `Es el nombre que verá la gente. Tu usuario seguirá siendo @${me}.`),
    ], [["Ahora no", save], ["Guardar", save]]);
    nameIn.select();
    return;
  }
  dialog("Mi perfil", [
    head,
    field("Nombre visible", nameIn),
    text("Tu estado", "h3", "settings-h"), statusPicker(),
    field("Frase de perfil", bioIn, "Una frase que verán tus contactos."),
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
  const devBox = text("Cargando…", "div", "member-list");
  d.append(text("Tus dispositivos", "summary"), devBox);
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
            seclog("Has desvinculado un dispositivo de tu cuenta.");
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
  const isAdmin = isAdminOf(g, me) && !g.left;
  const head = text("", "div", "profile-view");
  head.append(setAvatar(text("", "span", "avatar xl"), g.name, g.avatar), text(g.name, "h3"),
    text(`${g.members.length} miembros${g.left ? " · ya no estás en este grupo" : ""}`, "p", "muted"));
  const body = [head];
  let nameIn = null;
  if (isAdmin) { nameIn = input(g.name); body.push(field("Nombre del grupo", nameIn)); }
  const list = text("", "ul", "member-list");
  for (const u of g.members) {
    const li = document.createElement("li");
    const tags = [isAdminOf(g, u) ? "admin" : "", isMutedIn(g, u) ? "silenciado" : ""].filter(Boolean).join(" · ");
    li.append(setAvatar(text("", "span", "avatar"), same(u, me) ? (profile.name || me) : displayName(u), same(u, me) ? profile.avatar : avatarOf(u)),
      text(same(u, me) ? "Tú" : displayName(u), "span", "member-name"), text(tags, "small", "muted"));
    if (isAdmin && !same(u, me)) {
      const act = (ic, label, fn, cls = "") => {
        const b = text("", "button", `icon-btn member-act ${cls}`);
        b.type = "button";
        b.title = label;
        b.setAttribute("aria-label", `${label}: ${displayName(u)}`);
        b.append(icon(ic));
        b.onclick = () => { fn(); showGroupInfo(conv); };
        li.append(b);
      };
      const adm = isAdminOf(g, u), mut = isMutedIn(g, u);
      act("shield", adm ? "Quitar de administrador" : "Hacer administrador", () =>
        updateGroup(gid, adm ? { admins: adminsOf(g).filter((x) => !same(x, u)) }
          : { admins: [...adminsOf(g), u], muted: (g.muted || []).filter((x) => !same(x, u)) }), adm ? "on" : "");
      if (!adm) act(mut ? "mic_off" : "mic", mut ? "Permitir que escriba" : "Silenciar (solo podrá leer)", () =>
        updateGroup(gid, { muted: mut ? g.muted.filter((x) => !same(x, u)) : [...(g.muted || []), u] }), mut ? "on" : "");
      act("close", "Quitar del grupo", () => updateGroup(gid, {
        members: g.members.filter((x) => !same(x, u)), admins: adminsOf(g).filter((x) => !same(x, u)),
        muted: (g.muted || []).filter((x) => !same(x, u)) }), "danger");
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
    body.push(text("Enlace de invitación", "h3", "settings-h"), inviteBox(g));
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

function showBackup(back = false) {
  const status = text("", "p", "hint");
  const exp = withIcon("download", "Descargar copia cifrada", "button", "primary");
  exp.type = "button";
  exp.onclick = async () => {
    exp.disabled = true;
    status.textContent = "Preparando la copia…";
    try { status.textContent = `Copia descargada con ${await exportBackup()} mensajes.`; seclog("Has descargado una copia de seguridad."); }
    catch (e) { status.textContent = `No se pudo crear: ${e.message}`; }
    finally { exp.disabled = false; }
  };
  const fileIn = document.createElement("input");
  fileIn.type = "file";
  fileIn.accept = ".scbackup";
  fileIn.hidden = true;
  fileIn.onchange = async () => {
    status.textContent = "Restaurando…";
    try { status.textContent = `Restaurados ${await importBackup(fileIn.files[0])} mensajes nuevos.`; seclog("Has restaurado una copia de seguridad."); }
    catch (e) { status.textContent = e.message; }
  };
  const imp = withIcon("upload", "Restaurar una copia", "button", "chip");
  imp.type = "button";
  imp.onclick = () => fileIn.click();
  dialog("Copia de seguridad", [
    text("Guarda todo tu historial (mensajes, fotos, notas de voz, grupos y contactos) en un fichero cifrado.", "p"),
    text("Solo tu cuenta puede abrirlo: la clave sale de tu identidad. Sirve para pasar tu historial a otro móvil u ordenador: inicia sesión allí y restaura la copia.", "p", "hint"),
    exp, imp, fileIn, status,
  ], subActions(back));
}

function showAbout(back = false) {
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
  }), subActions(back));
}

function showNewGroup() {
  const nameIn = input("", { placeholder: "Amigos de clase" });
  const memberIn = input("", { max: 33, placeholder: "@usuario" });
  const chosen = [];
  const chips = text("", "div", "chosen");
  const err = text("", "p", "error");
  let draw = () => chips.replaceChildren(...chosen.map((u) => {
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

  // Gente con la que ya has hablado, por orden alfabético: se marca con un clic
  const known = new Map();
  for (const c of client.contacts.all()) known.set(c.name.toLowerCase(), c.name);
  for (const conv of chats.keys()) if (!isGroup(conv)) known.set(conv.toLowerCase(), conv);
  known.delete(me.toLowerCase());
  const people = [...known.values()].sort((a, b) => displayName(a).localeCompare(displayName(b), "es", { sensitivity: "base" }));
  const pick = text("", "div", "pick-list");
  const pickRows = people.map((u) => {
    const l = text("", "label", "pick-row");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.onchange = () => {
      const i = chosen.findIndex((x) => same(x, u));
      if (cb.checked && i < 0) chosen.push(u);
      if (!cb.checked && i >= 0) chosen.splice(i, 1);
      draw();
    };
    const names = text("", "span", "pick-names");
    names.append(text(displayName(u), "strong"), text(`@${u}`, "small"));
    l.append(cb, setAvatar(text("", "span", "avatar"), displayName(u), avatarOf(u)), names);
    l.dataset.search = `${displayName(u)} ${u}`.toLowerCase();
    return [u, l, cb];
  });
  pick.append(...pickRows.map((r) => r[1]));
  // Al escribir, la lista se filtra; si no está, se añade con «Añadir»
  memberIn.oninput = () => {
    const q = memberIn.value.trim().replace(/^@/, "").toLowerCase();
    for (const [, l] of pickRows) l.hidden = !!q && !l.dataset.search.includes(q);
  };
  const baseDraw = draw;
  draw = () => {
    baseDraw();
    for (const [u, , cb] of pickRows) cb.checked = chosen.some((x) => same(x, u));
  };

  dialog("Nuevo grupo", [
    field("Nombre del grupo", nameIn),
    text("Miembros", "h3", "settings-h"), row, err,
    people.length ? pick : text("Aún no has hablado con nadie: escribe su @usuario y pulsa Añadir.", "p", "hint"),
    chips,
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
    toggle.onclick = () => {
      client.contacts.setVerified(peer, !c.verified);
      seclog(c.verified ? `Has quitado la verificación de @${peer}.` : `Has verificado la clave de @${peer}.`);
      showPeerProfile(peer);
    };
    d.append(text(`Seguridad avanzada${c.verified ? " · verificado" : ""}`, "summary"),
      text("El servidor solo reenvía mensajes, pero si alguien lo controlara podría intentar hacerse pasar por este contacto. "
        + "Para descartarlo del todo, comparad estos números en persona o por otra app: si coinciden, nadie está en medio.", "p", "hint"),
      grid, toggle);
    body.push(d);
  }
  const clear = text("Vaciar este chat", "button", "chip danger");
  clear.type = "button";
  clear.onclick = async () => { if (await clearChat(peer)) $("dialog").close(); };
  body.push(clear);
  dialog("Perfil", body, [["Cerrar", () => { if (nickIn) client.contacts.setNick(peer, nickIn.value); }]]);
}

// ------------------------------------------------------------- personalizar

const ACCENTS = ["#4f46e5", "#7c3aed", "#db2777", "#e11d48", "#ea580c", "#ca8a04", "#16a34a", "#0d9488", "#0284c7", "#475569"];
const WALLS = [["dots", "Puntos"], ["plain", "Liso"], ["grid", "Cuadrícula"], ["diagonal", "Rayas"], ["bubbles", "Burbujas"], ["gradient", "Degradado"], ["image", "Tu foto"]];

const STATUS_OPTS = [
  ["online", "En línea", "Los demás ven que estás conectado."],
  ["away", "Ausente", "Te ven conectado pero marcado como ausente."],
  ["invisible", "Invisible", "Te ven desconectado aunque uses la app; tu última conexión no se actualiza."],
];

/** Selector En línea / Ausente / Invisible (se aplica al momento). */
function statusPicker() {
  const box = text("", "div");
  const g = text("", "div", "segmented status-seg");
  const hint = text("", "p", "hint");
  const paint = () => {
    const cur = prefs().status;
    for (const b of g.children) b.setAttribute("aria-pressed", String(b.value === cur));
    hint.textContent = STATUS_OPTS.find((o) => o[0] === cur)?.[2] || "";
  };
  for (const [value, label] of STATUS_OPTS) {
    const b = text("", "button");
    b.type = "button";
    b.value = value;
    b.append(text("", "span", `status-dot ${value}`), label);
    b.onclick = () => { window.SC_SET_PREFS({ ...prefs(), status: value }); sendPrivacy(); paint(); renderMe(); };
    g.append(b);
  }
  paint();
  box.append(g, hint);
  return box;
}

const OPTIONS = [
  ["sliders", "Apariencia", "Tema, colores, fondo y tamaño de letra", () => showSettings("appearance")],
  ["lock", "Privacidad", "Escribiendo, visto y última conexión", () => showSettings("privacy")],
  ["mail", "Chats y notificaciones", "Avisos y tecla Intro", () => showSettings("chats")],
  ["star", "Mensajes destacados", "Los mensajes que has marcado con estrella", () => showStarred()],
  ["key", "Registro de seguridad", "Dispositivos nuevos, cambios de clave…", () => showSecLog()],
  ["download", "Copia de seguridad", "Guarda o restaura tu historial cifrado", () => showBackup(true)],
  ["shield", "Cómo te protege SecureChat", "Qué ve y qué no ve el servidor", () => showAbout(true)],
];

/** Pantalla de opciones: una lista de apartados; cada uno abre el suyo. */
function showOptions() {
  dialog("Opciones", [text("", "div", "options-list")].map((list) => {
    for (const [ic, title, desc, open] of OPTIONS) {
      const b = text("", "button", "option-row");
      b.type = "button";
      const t = text("", "span", "option-text");
      t.append(text(title, "strong"), text(desc, "small"));
      b.append(icon(ic, "option-ico"), t, icon("chevron", "option-chev"));
      b.onclick = open;
      list.append(b);
    }
    return list;
  }));
}

/** Botones de un apartado de Opciones: «Atrás» vuelve a la lista. */
const subActions = (back = true) => (back ? [["Atrás", () => setTimeout(showOptions)], ["Listo"]] : [["Listo"]]);

function showSettings(section = "appearance", back = true) {
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
      if (key === "lastSeen") { sendPrivacy(); renderHeader(); }
      if (key === "notifications") { if (cb.checked) askNotifications(), setupPush(); else removePush(); }
    };
    const t = text("", "span");
    t.append(text(label, "strong"), text(hint, "small"));
    l.append(cb, t);
    return l;
  };

  if (section === "privacy") {
    return dialog("Privacidad", [
      text("Tu estado (en línea, ausente o invisible) se cambia desde Mi perfil.", "p", "hint"),
      toggle("typing", "Mostrar que estoy escribiendo", "Si lo quitas, los demás no verán «escribiendo…» cuando escribes."),
      toggle("readReceipts", "Mostrar que he leído (visto)", "Si lo quitas, los demás no verán el doble check azul cuando leas sus mensajes."),
      toggle("lastSeen", "Mostrar mi última conexión", "Si lo quitas, nadie verá a qué hora te conectaste por última vez (y tú tampoco la de los demás)."),
    ], subActions(back));
  }
  if (section === "chats") {
    return dialog("Chats y notificaciones", [
      toggle("notifications", "Notificaciones", "Aviso cuando llega un mensaje con la app en segundo plano."),
      toggle("enterSends", "Enviar con Intro", "Si lo quitas, Intro hace salto de línea en el ordenador."),
    ], subActions(back));
  }
  dialog("Apariencia", [
    text("Tema", "h3", "settings-h"), themes,
    text("Color principal", "h3", "settings-h"), colors,
    text("Fondo de los chats", "h3", "settings-h"), walls,
    text("Tamaño de letra", "h3", "settings-h"), seg([[13, "Pequeña"], [15, "Normal"], [17, "Grande"], [19, "Enorme"]], "font"),
    text("Forma de las burbujas", "h3", "settings-h"), seg([[22, "Redondas"], [14, "Suaves"], [4, "Rectas"]], "radius"),
  ], subActions(back));
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
  if (c.once) return c.t === "image" ? "Foto · ver una vez" : "Vídeo · ver una vez";
  if (c.t === "image") return c.mime === "image/gif" ? "GIF" : "Foto";
  if (c.t === "video") return "Vídeo";
  if (c.t === "audio") return `Nota de voz${c.dur ? ` · ${fmtDur(c.dur)}` : ""}`;
  if (c.t === "deleted") return "Mensaje eliminado";
  if (c.t === "file") return `Documento · ${c.name || "archivo"}`;
  if (c.t === "poll") return `Encuesta · ${c.q}`;
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
  $("me-handle").textContent = `@${me}`;
  setAvatar($("me-avatar"), profile.name || me, profile.avatar);
  const st = STATUS_OPTS.find((o) => o[0] === prefs().status) || STATUS_OPTS[0];
  $("me-status").className = `status-dot ${st[0]}`;
  $("me-status").title = st[1];
}

function renderContacts() {
  if (!client) return;
  const convs = new Set([...client.contacts.all().map((c) => c.name), ...chats.keys(), ...[...groups.keys()].map((g) => `#${g}`)]);
  const visible = (m) => m.content && !m.sys;
  const lastTime = (n) => chats.get(n)?.messages.filter(visible).at(-1)?.time || 0;
  const all = [...convs].filter((c) => !same(c, me) && (c === active || !meta(c).hidden));
  const archived = all.filter((c) => meta(c).archived);
  if (!archived.length) showArchived = false;
  const list = all.filter((c) => !!meta(c).archived === showArchived)
    .sort((a, b) => (meta(b).pin || 0) - (meta(a).pin || 0) || lastTime(b) - lastTime(a) || convName(a).localeCompare(convName(b)));
  $("contacts-empty").hidden = list.length > 0 || archived.length > 0;
  const rows = list.map((conv) => {
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
    const badges = text("", "span", "contact-badges");
    const mt = meta(conv);
    if (mt.mute) badges.append(icon("bell_off", "row-ico"));
    if (mt.pin) badges.append(icon("pin", "row-ico"));
    if (unread && isGroup(conv) && chats.get(conv)?.messages.some((x) => x.from === "them" && !x.read && x.content?.t === "text" && mentionsMe(x.content.body))) {
      badges.append(text("@", "span", "unread mention"));
    }
    if (unread) badges.append(text(String(unread), "span", `unread${mt.mute ? " muted" : ""}`));
    else if (mt.unread) badges.append(text("", "span", "unread dot"));
    side.append(badges);
    btn.append(setAvatar(text("", "span", "avatar"), convName(conv), convAvatar(conv)), main, side);
    btn.onclick = () => openChat(conv);
    // Menú del chat: clic derecho en ordenador, mantener pulsado en el móvil
    btn.oncontextmenu = (e) => { e.preventDefault(); openChatMenu(conv, e.clientX, e.clientY); };
    longPress(btn, (x, y) => openChatMenu(conv, x, y));
    li.append(btn);
    return li;
  });
  // Fila de «Archivados» (o volver a los chats)
  if (showArchived || archived.length) {
    const li = text("", "li", "archived-row");
    const b = document.createElement("button");
    b.type = "button";
    if (showArchived) {
      b.append(icon("back", "archived-ico"), text("Archivados", "strong"));
    } else {
      const n = archived.reduce((s, c) => s + unreadOf(c), 0);
      b.append(icon("archive", "archived-ico"), text("Archivados", "strong"),
        text(n ? String(n) : String(archived.length), "span", n ? "unread muted" : "archived-count"));
    }
    b.onclick = () => { showArchived = !showArchived; renderContacts(); };
    li.append(b);
    rows.unshift(li);
  }
  $("contacts").replaceChildren(...rows);
}

/** Mantener pulsado (móvil): llama a fn con la posición del dedo. */
function longPress(el, fn) {
  let timer = null;
  el.addEventListener("touchstart", (e) => {
    const t0 = e.touches[0];
    timer = setTimeout(() => { navigator.vibrate?.(15); fn(t0.clientX, t0.clientY); }, 450);
  }, { passive: true });
  for (const ev of ["touchend", "touchmove", "touchcancel"]) el.addEventListener(ev, () => clearTimeout(timer), { passive: true });
}

// ------------------------------------------------------- menú de un chat

function placeMenu(menu, x, y) {
  document.body.append(menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.max(8, Math.min(x, innerWidth - r.width - 8))}px`;
  menu.style.top = `${Math.max(8, Math.min(y, innerHeight - r.height - 8))}px`;
  setTimeout(() => document.addEventListener("pointerdown", outsideMenu, { once: true }), 0);
}

function newMenu() {
  closeMsgMenu();
  const menu = text("", "div", "msg-menu");
  menu.id = "msg-menu";
  menu.setAttribute("role", "menu");
  const item = (ic, label, fn, cls = "") => {
    const b = withIcon(ic, label, "button", `menu-item ${cls}`);
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.onclick = () => { closeMsgMenu(); fn(); };
    menu.append(b);
  };
  return [menu, item];
}

const MAX_PINNED = 3;

function openChatMenu(conv, x, y) {
  if (!conv) return;
  const [menu, item] = newMenu();
  const mt = meta(conv);
  if (conv === active) item("search", "Buscar en el chat", openSearch);
  item(isGroup(conv) ? "users" : "user", isGroup(conv) ? "Info del grupo" : "Ver perfil", () => showPeerProfile(conv));
  if (!mt.archived) {
    item("pin", mt.pin ? "Desfijar chat" : "Fijar chat", () => {
      if (!mt.pin && Object.values(chatMeta).filter((v) => v.pin).length >= MAX_PINNED) {
        alert(`Solo puedes fijar ${MAX_PINNED} chats. Desfija otro primero.`);
        return;
      }
      setMeta(conv, { pin: mt.pin ? null : Date.now() });
      renderContacts();
    });
  }
  item(mt.mute ? "bell" : "bell_off", mt.mute ? "Activar notificaciones" : "Silenciar notificaciones", () => {
    setMeta(conv, { mute: !mt.mute });
    renderContacts();
    renderHeader();
    updateTitle();
  });
  if (unreadOf(conv) || mt.unread) {
    item("checks", "Marcar como leído", () => { setMeta(conv, { unread: null }); markRead(conv); renderContacts(); updateTitle(); });
  } else {
    item("mail", "Marcar como no leído", () => { setMeta(conv, { unread: true }); if (active === conv) closeChat(); else renderContacts(); });
  }
  item("archive", mt.archived ? "Desarchivar" : "Archivar", () => {
    setMeta(conv, { archived: !mt.archived, pin: null });
    if (!mt.archived && active === conv) closeChat(); else renderContacts();
  });
  item("clock", `Mensajes temporales${mt.timer ? ` · ${TIMER_LABEL[mt.timer]}` : ""}`, () => showTimer(conv));
  item("star", "Mensajes destacados", () => showStarred(conv));
  item("image", "Fotos, documentos y enlaces", () => showGallery(conv));
  item("eraser", "Vaciar chat", () => clearChat(conv), "danger");
  item("trash", "Borrar chat", () => deleteChat(conv), "danger");
  placeMenu(menu, x, y);
}

function closeChat() {
  active = null;
  closeSearch();
  closePicker();
  $("app").classList.remove("in-chat");
  renderContacts();
  renderChat();
}

/** Borra los mensajes del chat en este dispositivo (el chat sigue en la lista). */
async function clearChat(conv, ask = true) {
  if (ask && !confirm(`¿Vaciar el chat con ${convName(conv)}? Se borran sus mensajes de este dispositivo y no se puede deshacer.`)) return false;
  await history.deleteChat(conv);
  chat(conv).messages = [];
  setMeta(conv, { pinMsg: null });
  if (active === conv) renderChat();
  renderContacts();
  updateTitle();
  return true;
}

/** Quita el chat de la lista y borra sus mensajes. Si te vuelven a escribir, reaparece. */
async function deleteChat(conv) {
  if (!confirm(`¿Borrar el chat con ${convName(conv)}? Se borran sus mensajes de este dispositivo y desaparece de la lista.`)) return;
  setMeta(conv, { hidden: true, pin: null, archived: null, unread: null, pinMsg: null });
  if (active === conv) active = null;
  await clearChat(conv, false);
  closeChat();
}

// ------------------------------------------------------- mensaje fijado

function renderPinned() {
  const bar = $("pinned-bar");
  const id = active && meta(active).pinMsg;
  const m = id && chat(active).messages.find((x) => x.id === id && !x.deleted);
  bar.hidden = !m;
  if (!m) return;
  const body = text("", "button", "pinned-body");
  body.type = "button";
  body.append(icon("pin", "pinned-ico"), text("", "span", "pinned-text"));
  body.lastChild.append(text("Mensaje fijado", "strong"),
    text(m.content.t === "text" ? m.content.body : previewOf(m.content), "span"));
  body.onclick = () => jumpTo(m.id);
  const x = text("", "button", "icon-btn");
  x.type = "button";
  x.title = "Desfijar";
  x.setAttribute("aria-label", "Desfijar mensaje");
  x.append(icon("close"));
  x.onclick = () => { setMeta(active, { pinMsg: null }); renderPinned(); };
  bar.replaceChildren(body, x);
}

// ------------------------------------------------------- reenviar

function showForward(src, m) {
  const chosen = new Set();
  const convs = [...new Set([...chats.keys(), ...client.contacts.all().map((c) => c.name), ...[...groups.keys()].map((g) => `#${g}`)])]
    .filter((c) => !meta(c).hidden && (!isGroup(c) || targetsOf(c).length))
    .sort((a, b) => (meta(b).pin || 0) - (meta(a).pin || 0) || convName(a).localeCompare(convName(b), "es", { sensitivity: "base" }));
  const filter = input("", { placeholder: "Buscar chat" });
  filter.className = "filter-input";
  const list = text("", "div", "pick-list tall");
  const count = text("", "p", "hint");
  const rows = convs.map((conv) => {
    const l = text("", "label", "pick-row");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.onchange = () => { if (cb.checked) chosen.add(conv); else chosen.delete(conv); count.textContent = chosen.size ? `${chosen.size} seleccionado${chosen.size > 1 ? "s" : ""}` : ""; };
    const names = text("", "span", "pick-names");
    names.append(text(convName(conv), "strong"), text(isGroup(conv) ? "Grupo" : `@${conv}`, "small"));
    l.append(cb, setAvatar(text("", "span", "avatar"), convName(conv), convAvatar(conv)), names);
    l.dataset.search = `${convName(conv)} ${conv}`.toLowerCase();
    list.append(l);
    return l;
  });
  filter.oninput = () => {
    const q = filter.value.trim().replace(/^@/, "").toLowerCase();
    for (const l of rows) l.hidden = !!q && !l.dataset.search.includes(q);
  };
  dialog("Reenviar a…", [filter, list, count], [["Cancelar"], ["Reenviar", () => forwardTo([...chosen], src, m)]]);
}

async function forwardTo(targets, src, m) {
  if (!targets.length) return;
  let bytes = null;
  if (m.hasMedia) {
    bytes = await history.getMedia(src, m.id);
    if (!bytes) { alert("No se encontró el archivo en este dispositivo."); return; }
  }
  const { mid, reply, g, data, fwd, ...rest } = m.content;
  for (const conv of targets) {
    const url = bytes && rest.t !== "file" ? URL.createObjectURL(new Blob([bytes], { type: rest.mime })) : null;
    await sendTo(conv, { ...rest, fwd: true }, { bytes, url });
  }
  if (targets.length === 1 && targets[0] !== active) openChat(targets[0]);
}

// ------------------------------------------------------- buscar en el chat

let searchHits = [], searchIdx = -1, searchTimer = null;
const norm = (s) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();

function openSearch() {
  $("search-bar").hidden = false;
  $("search-input").value = "";
  $("search-count").textContent = "";
  $("search-input").focus();
}

function closeSearch() {
  if ($("search-bar").hidden) return;
  $("search-bar").hidden = true;
  clearHits();
}

function clearHits() {
  for (const el of $("messages").querySelectorAll(".hit, .hit-current")) el.classList.remove("hit", "hit-current");
  searchHits = [];
  searchIdx = -1;
}

function runSearch() {
  clearHits();
  const q = norm($("search-input").value.trim());
  if (!q || !active) { $("search-count").textContent = ""; return; }
  searchHits = chat(active).messages.filter((m) => m.el && !m.deleted && m.content?.t === "text" && norm(m.content.body).includes(q));
  for (const m of searchHits) m.el.classList.add("hit");
  searchIdx = searchHits.length - 1; // empezamos por el más reciente
  showHit();
}

function showHit() {
  $("search-count").textContent = searchHits.length ? `${searchIdx + 1} de ${searchHits.length}` : "Sin resultados";
  for (const x of searchHits) x.el.classList.remove("hit-current");
  const m = searchHits[searchIdx];
  if (!m) return;
  m.el.classList.add("hit-current");
  m.el.scrollIntoView({ block: "center", behavior: "smooth" });
}

function stepHit(d) {
  if (!searchHits.length) return;
  searchIdx = (searchIdx + d + searchHits.length) % searchHits.length;
  showHit();
}

function renderHeader() {
  if (!client) return;
  const has = !!active;
  if (has) {
    $("peer-name").textContent = convName(active);
    if (meta(active).mute) $("peer-name").append(icon("bell_off", "name-ico"));
    if (meta(active).timer) $("peer-name").append(icon("clock", "name-ico"));
    const smallGroup = isGroup(active) && targetsOf(active).length >= 1 && targetsOf(active).length <= GROUP_CALL_MAX - 1;
    $("call-btn").hidden = $("video-btn").hidden = isGroup(active) && !smallGroup;
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
      const detail = online ? text(ch.away ? "ausente" : "en línea", "span", ch.away ? "away" : "lock")
        : text((prefs().lastSeen && lastSeenText(ch.lastSeen)) || c?.bio || "", "span");
      status = text("", "span", "peer-sub");
      status.append(text(`@${active}`, "span", "handle"));
      if (detail.textContent) status.append(text(" · ", "span"), detail);
    }
    $("peer-status").replaceChildren(status);
  }
  // Se puede escribir siempre que haya un chat abierto (sin conexión, el mensaje espera con 🕓)
  const silenced = has && mutedHere(active);
  for (const id of ["text", "send-btn", "emoji-btn", "attach-btn", "mic-btn"]) $(id).disabled = !has || silenced;
  $("text").placeholder = silenced ? "Un administrador te ha silenciado: solo puedes leer" : "Escribe un mensaje cifrado…";
  $("chat").classList.toggle("is-empty", !has);
  $("empty-chat").hidden = has;
}

function renderChat() {
  renderHeader();
  closeMsgMenu();
  $("messages").replaceChildren();
  $("messages").dataset.day = "";
  if (active) for (const m of chat(active).messages) appendMessage(m);
  renderPinned();
  renderSchedBar();
  if (!$("search-bar").hidden) runSearch();
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
  if (c.fwd && !m.deleted) li.append(withIcon("forward", "Reenviado", "span", "fwd-label"));
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
    li.append(richText(c.body));
    const card = linkCard(c.body);
    if (card) li.append(card);
  } else if (c.t === "file") {
    const card = text("", "button", "file-card");
    card.type = "button";
    card.title = "Descargar";
    const info = text("", "span", "file-meta");
    const ext = (c.name || "").includes(".") ? c.name.split(".").pop().toUpperCase().slice(0, 6) : "";
    info.append(text(c.name || "archivo", "strong"), text([ext, c.size ? fmtSize(c.size) : ""].filter(Boolean).join(" · "), "small"));
    card.append(icon("file", "file-ico"), info, icon("download", "file-dl"));
    card.onclick = async (e) => {
      e.stopPropagation();
      const bytes = await history?.getMedia(conv, m.id);
      if (!bytes) { alert("Este archivo ya no está en este dispositivo."); return; }
      downloadBytes(bytes, c.name || "archivo");
    };
    li.append(card);
  } else if (c.once && (c.t === "image" || c.t === "video")) {
    const what = c.t === "image" ? "Foto" : "Vídeo";
    const b = text("", "button", `once-card${m.opened || m.from === "me" ? " used" : ""}`);
    b.type = "button";
    b.append(text("1", "span", "once-badge"), text(m.from === "me" ? `${what} · ver una vez` : m.opened ? "Abierta" : `${what} · ver una vez`, "span"));
    b.disabled = m.from === "me" || !!m.opened;
    b.onclick = (e) => { e.stopPropagation(); openOnce(conv, m); };
    li.append(b);
  } else if (c.t === "poll") {
    li.append(buildPoll(conv, m, c));
  } else if (c.t === "sticker") {
    li.append(text(c.id, "span", "sticker-face"));
  } else if (c.t === "audio") {
    const a = document.createElement("audio");
    a.controls = true;
    a.preload = "metadata";
    mediaUrl(conv, m).then((u) => { if (u) a.src = u; else li.classList.add("missing"); });
    a.defaultPlaybackRate = a.playbackRate = voiceRate;
    const sp = text(rateLabel(voiceRate), "button", "speed-btn");
    sp.type = "button";
    sp.title = "Velocidad de reproducción";
    sp.onclick = (e) => {
      e.stopPropagation();
      voiceRate = { 1: 1.5, 1.5: 2, 2: 1 }[voiceRate] || 1;
      a.defaultPlaybackRate = a.playbackRate = voiceRate;
      sp.textContent = rateLabel(voiceRate);
    };
    li.append(icon("mic", "mic-icon"), a, sp);
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
  if (m.expires && !m.deleted) t.prepend(icon("clock_small", "time-ico"));
  if (m.starred && !m.deleted) t.prepend(icon("star", "time-ico star"));
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
  if (!m.deleted) swipeToReply(li, conv, m);
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

// ------------------------------------------------------------- varios archivos a la vez

let sendOnce = false;

async function sendFiles(files, once = false, asDoc = false) {
  for (const f of files.slice(0, 10)) await sendFile(f, asDoc, once);
}

// ------------------------------------------------------------- ver una vez

async function openOnce(conv, m) {
  if (m.opened || m.from === "me") return;
  const url = await mediaUrl(conv, m);
  m.opened = true;
  delete m.url;
  m.hasMedia = false;
  save(conv, m);
  history?.removeMedia(conv, m.id);
  if (!url) { alert("Esta foto ya no está disponible."); return; }
  const el = document.createElement(m.content.t === "image" ? "img" : "video");
  el.src = url;
  el.className = "viewer";
  if (m.content.t === "video") { el.controls = true; el.autoplay = true; el.playsInline = true; }
  el.oncontextmenu = (e) => e.preventDefault();
  dialog(m.content.t === "image" ? "Foto de ver una vez" : "Vídeo de ver una vez",
    [el, text("Cuando cierres esta ventana, desaparecerá de este dispositivo.", "p", "hint")]);
  $("dialog").addEventListener("close", () => { el.removeAttribute("src"); URL.revokeObjectURL(url); }, { once: true });
}

// ------------------------------------------------------------- velocidad de las notas de voz

let voiceRate = 1;
const rateLabel = (r) => `${String(r).replace(".", ",")}×`;

// ------------------------------------------------------------- deslizar para responder (móvil)

function swipeToReply(li, conv, m) {
  let sx = null, sy = 0, dx = 0;
  li.addEventListener("touchstart", (e) => { sx = e.touches[0].clientX; sy = e.touches[0].clientY; dx = 0; }, { passive: true });
  li.addEventListener("touchmove", (e) => {
    if (sx == null) return;
    const ddx = e.touches[0].clientX - sx, ddy = e.touches[0].clientY - sy;
    if (Math.abs(ddy) > 24 && Math.abs(ddy) > Math.abs(ddx)) { sx = null; li.style.transform = ""; return; }
    dx = Math.max(0, Math.min(80, ddx));
    li.style.transform = dx > 6 ? `translateX(${dx}px)` : "";
    li.classList.toggle("swipe-ready", dx > 60);
  }, { passive: true });
  const end = () => {
    if (sx == null && !dx) return;
    sx = null;
    li.style.transition = "transform .18s ease";
    li.style.transform = "";
    li.classList.remove("swipe-ready");
    setTimeout(() => { li.style.transition = ""; }, 200);
    const canWrite = (!isGroup(conv) || targetsOf(conv).length) && !mutedHere(conv);
    if (dx > 60 && canWrite && conv === active) { navigator.vibrate?.(10); startReply(m); $("text").focus(); }
    dx = 0;
  };
  li.addEventListener("touchend", end, { passive: true });
  li.addEventListener("touchcancel", end, { passive: true });
}

// ------------------------------------------------------------- mensajes programados
// Se guardan solo en este dispositivo y se envían cuando llega la hora con la app abierta:
// el servidor no sabe nada de ellos hasta ese momento.

const schedKey = () => `sc:scheduled:${me.toLowerCase()}`;
const scheduled = () => store.get(schedKey()) || [];

function showSchedule() {
  if (!active || mutedHere(active)) return;
  const conv = active;
  const body = document.createElement("textarea");
  body.className = "filter-input sched-text";
  body.rows = 3;
  body.maxLength = 4000;
  body.placeholder = "Escribe el mensaje";
  body.value = $("text").value;
  const when = document.createElement("input");
  when.type = "datetime-local";
  when.className = "filter-input";
  const pad = (n) => String(n).padStart(2, "0");
  const local = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const soon = new Date(Date.now() + 3600000);
  soon.setSeconds(0, 0);
  when.value = local(soon);
  when.min = local(new Date());
  const err = text("", "p", "error");
  dialog(`Programar para ${convName(conv)}`, [
    field("Mensaje", body), field("Cuándo", when),
    text("Se enviará a esa hora si tienes la app abierta (o en cuanto la abras después). Hasta entonces solo está en este dispositivo.", "p", "hint"),
    err,
  ], [["Cancelar"], ["Programar", () => {
    const at = new Date(when.value).getTime();
    if (!body.value.trim() || !Number.isFinite(at) || at <= Date.now()) {
      err.textContent = !body.value.trim() ? "Escribe el mensaje." : "Elige una hora futura.";
      setTimeout(() => $("dialog").showModal());
      return;
    }
    store.set(schedKey(), [...scheduled(), { id: newId(), conv, body: body.value, at }]);
    if ($("text").value === body.value) $("text").value = "";
    toast(`Mensaje programado para ${new Date(at).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" })}.`);
    renderSchedBar();
  }]]);
  body.focus();
}

function renderSchedBar() {
  const bar = $("sched-bar");
  const list = active && me ? scheduled().filter((s) => s.conv === active) : [];
  bar.hidden = !list.length;
  if (!list.length) return;
  const b = text("", "button", "pinned-body");
  b.type = "button";
  const t = text("", "span", "pinned-text");
  const next = Math.min(...list.map((s) => s.at));
  t.append(text(list.length === 1 ? "1 mensaje programado" : `${list.length} mensajes programados`, "strong"),
    text(`El próximo: ${new Date(next).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" })}`, "span"));
  b.append(icon("clock", "pinned-ico"), t);
  b.onclick = () => showScheduledList(active);
  bar.replaceChildren(b);
}

function showScheduledList(conv) {
  const list = scheduled().filter((s) => s.conv === conv).sort((a, b) => a.at - b.at);
  const box = text("", "div", "starred-list");
  for (const s of list) {
    const row = text("", "div", "sched-row");
    const info = text("", "div", "sched-info");
    info.append(text(new Date(s.at).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "short" }), "time"), text(s.body, "p"));
    const now = text("Enviar ya", "button", "chip");
    now.type = "button";
    now.onclick = () => { dropScheduled(s.id); sendTo(s.conv, { t: "text", body: s.body }); $("dialog").close(); };
    const del = text("Cancelar", "button", "chip danger");
    del.type = "button";
    del.onclick = () => { dropScheduled(s.id); showScheduledList(conv); };
    const btns = text("", "div", "chip-row");
    btns.append(now, del);
    row.append(info, btns);
    box.append(row);
  }
  if (!list.length) box.append(text("No hay mensajes programados en este chat.", "p", "hint"));
  dialog("Mensajes programados", [box]);
}

function dropScheduled(id) {
  store.set(schedKey(), scheduled().filter((s) => s.id !== id));
  renderSchedBar();
}

function runScheduled() {
  if (!me || !client) return;
  const due = scheduled().filter((s) => s.at <= Date.now());
  if (!due.length) return;
  store.set(schedKey(), scheduled().filter((s) => s.at > Date.now()));
  for (const s of due) {
    if (mutedHere(s.conv) || (isGroup(s.conv) && !targetsOf(s.conv).length)) continue;
    sendTo(s.conv, { t: "text", body: s.body });
  }
  renderSchedBar();
}

// ------------------------------------------------------------- galería del chat

function showGallery(conv) {
  const msgs = chat(conv).messages.filter((m) => !m.deleted && !m.sys && m.content && !m.content.once);
  const media = msgs.filter((m) => (m.content.t === "image" || m.content.t === "video") && (m.hasMedia || m.url)).reverse();
  const docs = msgs.filter((m) => m.content.t === "file").reverse();
  const links = [];
  for (const m of [...msgs].reverse()) {
    if (m.content.t !== "text") continue;
    for (const u of m.content.body.match(/https?:\/\/[^\s<>"]+[^\s<>".,;:!?)\]']/g) || []) links.push([m, u]);
  }
  const panes = {
    media: () => {
      const grid = text("", "div", "gallery-grid");
      if (!media.length) return text("No hay fotos ni vídeos en este chat.", "p", "hint");
      for (const m of media) {
        const cell = text("", "button", "gallery-cell");
        cell.type = "button";
        const el = document.createElement(m.content.t === "image" ? "img" : "video");
        if (m.content.t === "video") { el.muted = true; el.preload = "metadata"; cell.classList.add("is-video"); }
        el.alt = m.content.name || "";
        mediaUrl(conv, m).then((u) => { if (u) el.src = u; });
        cell.append(el);
        cell.onclick = async () => {
          const u = await mediaUrl(conv, m);
          if (!u) return;
          if (m.content.t === "image") viewImage(u, m.content.name);
          else {
            const v = document.createElement("video");
            v.src = u; v.controls = true; v.autoplay = true; v.playsInline = true; v.className = "viewer";
            dialog(m.content.name || "Vídeo", [v]);
          }
        };
        grid.append(cell);
      }
      return grid;
    },
    docs: () => {
      if (!docs.length) return text("No hay documentos en este chat.", "p", "hint");
      const box = text("", "div", "starred-list");
      for (const m of docs) {
        const b = text("", "button", "starred-row");
        b.type = "button";
        const head = text("", "span", "starred-head");
        head.append(text(m.content.name || "archivo", "strong"), text(shortTime(m.time), "time"));
        b.append(head, text(m.content.size ? fmtSize(m.content.size) : "", "span", "starred-text"));
        b.onclick = async () => {
          const bytes = await history?.getMedia(conv, m.id);
          if (bytes) downloadBytes(bytes, m.content.name || "archivo"); else alert("Este archivo ya no está en este dispositivo.");
        };
        box.append(b);
      }
      return box;
    },
    links: () => {
      if (!links.length) return text("No hay enlaces en este chat.", "p", "hint");
      const box = text("", "div", "starred-list");
      for (const [m, u] of links) {
        const a = document.createElement("a");
        a.className = "starred-row";
        a.href = u;
        a.target = "_blank";
        a.rel = "noopener noreferrer nofollow";
        const head = text("", "span", "starred-head");
        let host = u;
        try { host = new URL(u).hostname.replace(/^www\./, ""); } catch { /* se deja tal cual */ }
        head.append(text(host, "strong"), text(shortTime(m.time), "time"));
        a.append(head, text(u, "span", "starred-text"));
        box.append(a);
      }
      return box;
    },
  };
  const tabs = text("", "div", "segmented");
  const area = text("", "div", "gallery-area");
  const show = (k) => {
    for (const b of tabs.children) b.setAttribute("aria-pressed", String(b.value === k));
    area.replaceChildren(panes[k]());
  };
  for (const [k, label, n] of [["media", "Fotos y vídeos", media.length], ["docs", "Documentos", docs.length], ["links", "Enlaces", links.length]]) {
    const b = text(`${label} (${n})`, "button");
    b.type = "button";
    b.value = k;
    b.onclick = () => show(k);
    tabs.append(b);
  }
  dialog(`Archivos de ${convName(conv)}`, [tabs, area]);
  show(media.length || (!docs.length && !links.length) ? "media" : docs.length ? "docs" : "links");
}

// ------------------------------------------------------------- menciones (@usuario) en grupos

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const mentionsMe = (body) => !!me && new RegExp(`(^|[^\\p{L}\\p{N}@])@${escapeRe(me)}(?![A-Za-z0-9_.-]*[A-Za-z0-9_])`, "iu").test(body || "");
let mentionList = [];

function onMentionInput() {
  const box = $("mention-box");
  if (!active || !isGroup(active)) return hideMentions();
  const ta = $("text");
  const before = ta.value.slice(0, ta.selectionStart);
  const m = /(^|\s)@([A-Za-z0-9_.-]{0,32})$/.exec(before);
  if (!m) return hideMentions();
  const q = m[2].toLowerCase();
  mentionList = targetsOf(active)
    .filter((u) => u.toLowerCase().startsWith(q) || displayName(u).toLowerCase().includes(q))
    .sort((a, b) => displayName(a).localeCompare(displayName(b), "es"))
    .slice(0, 6);
  if (!mentionList.length) return hideMentions();
  const el = box || (() => { const d = text("", "div", "mention-box"); d.id = "mention-box"; d.setAttribute("role", "listbox"); $("composer").before(d); return d; })();
  el.replaceChildren(...mentionList.map((u, i) => {
    const b = text("", "button", `mention-item${i === 0 ? " first" : ""}`);
    b.type = "button";
    b.append(setAvatar(text("", "span", "avatar"), displayName(u), avatarOf(u)), text(displayName(u), "strong"), text(`@${u}`, "small"));
    b.onmousedown = (e) => { e.preventDefault(); insertMention(u); };
    return b;
  }));
  el.hidden = false;
}

function onMentionKey(e) {
  if (!$("mention-box") || $("mention-box").hidden || !mentionList.length) return;
  if (e.key === "Tab" || (e.key === "Enter" && !e.shiftKey)) { e.preventDefault(); e.stopImmediatePropagation(); insertMention(mentionList[0]); }
  else if (e.key === "Escape") hideMentions();
}

function insertMention(u) {
  const ta = $("text");
  const pos = ta.selectionStart;
  const before = ta.value.slice(0, pos).replace(/@([A-Za-z0-9_.-]{0,32})$/, `@${u} `);
  ta.value = before + ta.value.slice(pos);
  ta.selectionStart = ta.selectionEnd = before.length;
  ta.focus();
  hideMentions();
}

function hideMentions() {
  const b = $("mention-box");
  if (b) b.hidden = true;
  mentionList = [];
}

// *negrita*  _cursiva_  ~tachado~  `código`  y enlaces (solo http/https). Siempre con el DOM, nunca innerHTML.
const RICH_RE = /(https?:\/\/[^\s<>"]+[^\s<>".,;:!?)\]'])|`([^`\n]+)`|(?<![\p{L}\p{N}*])\*(?!\s)([^*\n]+?)(?<!\s)\*(?![\p{L}\p{N}*])|(?<![\p{L}\p{N}_])_(?!\s)([^_\n]+?)(?<!\s)_(?![\p{L}\p{N}_])|(?<![\p{L}\p{N}~])~(?!\s)([^~\n]+?)(?<!\s)~(?![\p{L}\p{N}~])|(?<![\p{L}\p{N}@])@([A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9_])/gu;

function richText(body) {
  const span = text("", "span", "body");
  let last = 0;
  for (const m of body.matchAll(RICH_RE)) {
    if (m.index > last) span.append(body.slice(last, m.index));
    let el;
    if (m[1]) {
      el = document.createElement("a");
      el.href = m[1];
      el.textContent = m[1];
      el.target = "_blank";
      el.rel = "noopener noreferrer nofollow";
      el.onclick = (e) => e.stopPropagation();
    } else if (m[2]) el = text(m[2], "code");
    else if (m[3]) el = text(m[3], "strong");
    else if (m[4]) el = text(m[4], "em");
    else if (m[5]) el = text(m[5], "s");
    else {
      el = text(`@${m[6]}`, "span", `mention${same(m[6], me) ? " me" : ""}`);
      el.title = same(m[6], me) ? "Tú" : displayName(m[6]);
    }
    span.append(el);
    last = m.index + m[0].length;
  }
  if (last < body.length) span.append(body.slice(last));
  return span;
}

/** Tarjeta del primer enlace: solo con lo que ya está en el texto (no se visita la web: no se filtra tu IP). */
function linkCard(body) {
  const raw = body.match(/https?:\/\/[^\s<>"]+[^\s<>".,;:!?)\]']/)?.[0];
  if (!raw) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  const a = document.createElement("a");
  a.className = "link-card";
  a.href = raw;
  a.target = "_blank";
  a.rel = "noopener noreferrer nofollow";
  a.onclick = (e) => e.stopPropagation();
  const info = text("", "span", "link-meta");
  const path = decodeURIComponent(u.pathname + u.search).replace(/\/$/, "");
  info.append(text(u.hostname.replace(/^www\./, ""), "strong"), text(path || "Abrir enlace", "small"));
  a.append(icon("link", "link-ico"), info);
  return a;
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
  if (!m.deleted && m.content.t !== "unsupported" && !m.content.once) item("forward", "Reenviar", () => showForward(conv, m));
  if (!m.deleted) item("star", m.starred ? "Quitar destacado" : "Destacar", () => { m.starred = !m.starred; save(conv, m); });
  if (!m.deleted) {
    const pinned = meta(conv).pinMsg === m.id;
    item("pin", pinned ? "Desfijar mensaje" : "Fijar mensaje", () => { setMeta(conv, { pinMsg: pinned ? null : m.id }); renderPinned(); });
  }
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
  const n = [...chats.keys()].filter((p) => !meta(p).mute).reduce((s, p) => s + unreadOf(p), 0);
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
  $("theme-btn").onclick = () => showSettings("appearance");
  $("login-theme-btn").onclick = () => showSettings("appearance", false);
  $("emoji-btn").onclick = togglePicker;
  $("attach-btn").onclick = (e) => {
    e.stopPropagation();
    if ($("msg-menu")) return closeMsgMenu();
    const [menu, item] = newMenu();
    item("image", "Foto o vídeo", () => { sendOnce = false; $("file-input").click(); });
    item("eye", "Foto o vídeo de ver una vez", () => { sendOnce = true; $("file-input").click(); });
    item("file", "Documento", () => $("doc-input").click());
    item("poll", "Encuesta", showNewPoll);
    item("clock", "Programar mensaje", () => showSchedule());
    const r = e.currentTarget.getBoundingClientRect();
    placeMenu(menu, r.left, r.top - 230);
  };
  $("doc-input").multiple = true;
  $("doc-input").onchange = () => { sendFiles([...$("doc-input").files], false, true); $("doc-input").value = ""; };
  $("call-btn").append(icon("call"));
  $("video-btn").append(icon("video"));
  $("call-btn").onclick = () => (isGroup(active) ? startGroupCall(false) : startCall(false));
  $("video-btn").onclick = () => (isGroup(active) ? startGroupCall(true) : startCall(true));
  setInterval(sweepExpired, 30000);
  window.addEventListener("hashchange", () => checkInvite());
  $("file-input").multiple = true;
  $("file-input").onchange = () => { sendFiles([...$("file-input").files], sendOnce); sendOnce = false; $("file-input").value = ""; };
  $("text").addEventListener("input", onMentionInput);
  $("text").addEventListener("keydown", onMentionKey, true);
  $("text").addEventListener("blur", () => setTimeout(hideMentions, 150));
  $("send-btn").addEventListener("contextmenu", (e) => { e.preventDefault(); showSchedule(); });
  longPress($("send-btn"), () => showSchedule());
  setInterval(runScheduled, 15000);
  for (const b of document.querySelectorAll(".picker-tabs button")) b.onclick = () => { pickerTab = b.dataset.tab; renderPicker(); };
  $("text").addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); sendFiles(files); }
  });
  const chatEl = $("chat");
  chatEl.addEventListener("dragover", (e) => { if (active && e.dataTransfer.types.includes("Files")) { e.preventDefault(); $("drop-hint").hidden = false; } });
  chatEl.addEventListener("dragleave", (e) => { if (!chatEl.contains(e.relatedTarget)) $("drop-hint").hidden = true; });
  chatEl.addEventListener("drop", (e) => { e.preventDefault(); $("drop-hint").hidden = true; sendFiles([...e.dataTransfer.files]); });
  $("back-btn").onclick = closeChat;
  $("search-btn").append(icon("search"));
  $("chat-menu-btn").append(icon("more"));
  $("search-prev").append(icon("up"));
  $("search-next").append(icon("down"));
  $("search-close").append(icon("close"));
  $("search-btn").onclick = () => ($("search-bar").hidden ? openSearch() : closeSearch());
  $("chat-menu-btn").onclick = (e) => {
    e.stopPropagation();
    if ($("msg-menu")) return closeMsgMenu();
    const r = e.currentTarget.getBoundingClientRect();
    openChatMenu(active, r.right - 240, r.bottom + 6);
  };
  $("search-input").oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 150); };
  $("search-input").onkeydown = (e) => {
    if (e.key === "Enter") { e.preventDefault(); stepHit(e.shiftKey ? 1 : -1); }
    if (e.key === "Escape") { e.stopPropagation(); closeSearch(); }
  };
  $("search-prev").onclick = () => stepHit(-1);
  $("search-next").onclick = () => stepHit(1);
  $("search-close").onclick = closeSearch;
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
    else if (action === "options") showOptions();
    else if (action === "install") { await installPrompt?.prompt(); installPrompt = null; }
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
