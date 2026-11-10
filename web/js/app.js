// Interfaz web. Toda la criptografía ocurre aquí, en el navegador:
// el servidor solo recibe mensajes ya cifrados (texto, fotos, vídeos y perfiles).

import { ChatClient, ClientError, Contacts, IMAGE_MIME, MAX_MEDIA, VIDEO_MIME } from "./client.js";
import { EMOJIS, STICKERS } from "./emoji.js";
import * as P from "./protocol.js";
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
const chats = new Map(); // peer -> {messages: [], online: bool|null}
let reconnectTimer = null;
let serverConfig = { code_required: false, email_required: false };
const prefs = () => window.SC_PREFS();

// ---------------------------------------------------------------- acceso

function updateLoginMode() {
  const name = $("login-name").value.trim();
  const blob = NAME_RE.test(name) && store.get(idKey(name));
  const creating = !blob && NAME_RE.test(name);
  $("login-pass2-wrap").hidden = !creating;
  $("login-pass2").required = creating;
  $("login-email-wrap").hidden = !(creating && serverConfig.email_required);
  $("login-email").required = creating && serverConfig.email_required;
  $("login-btn").textContent = blob ? "Entrar" : "Crear cuenta";
  $("login-hint").textContent = !NAME_RE.test(name) ? (name ? "3-32 caracteres: letras, números, '_', '.' o '-'." : "")
    : blob ? `Cuenta @${blob.username || name} encontrada en este dispositivo.`
    : "Tu @usuario es único. Después podrás poner tu nombre visible y una foto. Si olvidas la contraseña no se puede recuperar.";
  $("login-pass").autocomplete = blob ? "current-password" : "new-password";
  $("login-remember-wrap").hidden = !Vault.canRemember();
}

async function onLogin(ev) {
  ev.preventDefault();
  const name = $("login-name").value.trim();
  const pass = $("login-pass").value;
  $("login-error").textContent = "";
  $("login-btn").disabled = true;
  $("login-btn").textContent = "Derivando clave…";
  await new Promise((r) => setTimeout(r, 30)); // deja pintar antes de Argon2id
  try {
    let blob = store.get(idKey(name));
    const isNew = !blob;
    if (isNew) {
      if (pass !== $("login-pass2").value) throw new Error("Las contraseñas no coinciden.");
      blob = { ...P.saveIdentity(P.newIdentitySeed(), pass), username: name };
    }
    identity = P.loadIdentity(blob, pass);
    if (serverConfig.code_required) store.set("sc:code", $("login-code").value.trim());
    if (isNew) {
      // La cuenta nueva solo se guarda si el servidor acepta el nombre (y el correo)
      $("login-btn").textContent = "Creando cuenta…";
      await startApp(name, { mustConnect: true, email: $("login-email").value.trim() || null });
      store.set(idKey(me), { ...blob, username: me });
    } else {
      await startApp(blob.username || name);
    }
    if ($("login-remember").checked) await Vault.remember(me, identity.seed);
    $("login-pass").value = $("login-pass2").value = "";
  } catch (e) {
    identity = null;
    client = null;
    hideVerify();
    if (e.code === "down") return showDown(true);
    $("login-error").textContent = e instanceof P.CryptoError && /contraseña/.test(e.message) ? "Contraseña incorrecta."
      : /en uso/.test(e.message) ? `El usuario @${name} ya existe. Elige otro nombre.`
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

async function startApp(username, { mustConnect = false, email = null } = {}) {
  const contacts = new Contacts(store.get(`sc:contacts:${username.toLowerCase()}`) || {}, (data) => {
    store.set(`sc:contacts:${(me || username).toLowerCase()}`, data);
    renderContacts();
    renderHeader();
  });
  const prekeys = new P.PrekeyStore(username, identity, store.get(`sc:prekeys:${username.toLowerCase()}`),
    (data) => store.set(`sc:prekeys:${(me || username).toLowerCase()}`, data));
  client = new ChatClient(username, identity, contacts, onEvent, { prekeys, code: store.get("sc:code") });
  me = username;
  if (mustConnect) {
    await client.connect(wsUrl(), { email, onVerify: askVerifyCode });
    me = client.name;
    connected = true;
  }
  history = new Vault.History(me, identity.seed);
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
  if (!client) return;
  clearTimeout(reconnectTimer);
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
  }
}

function onConnected() {
  replaced = false;
  $("replaced-banner").hidden = true;
  setConn(true);
  showDown(false);
  renderHeader();
  flushOutbox();
  if (active) markRead(active);
}

function scheduleReconnect(ms = 3000) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(reconnect, ms);
}

/** En móvil la conexión se corta al pasar la app a segundo plano: al volver, reconectamos ya. */
function wakeUp() {
  if (client && !connected && !replaced) scheduleReconnect(50);
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
  if (!keepSession && me) await Vault.forget(me);
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

function chat(peer) {
  if (!chats.has(peer)) chats.set(peer, { messages: [], online: null });
  return chats.get(peer);
}

const unreadOf = (peer) => chats.get(peer)?.messages.filter((m) => m.from === "them" && !m.read).length || 0;

/** Añade un mensaje a la conversación, lo pinta y lo guarda cifrado. */
function addMsg(peer, entry, { persist = true } = {}) {
  const m = { id: newId(), time: new Date(), ...entry };
  chat(peer).messages.push(m);
  if (peer === active) appendMessage(m);
  renderContacts();
  updateTitle();
  if (persist) history?.put(peer, m);
  return m;
}

function sysOnce(peer, text) {
  if (!chat(peer).messages.some((m) => m.sys === text)) addMsg(peer, { sys: text });
}

const ORDER = { sending: 0, sent: 1, delivered: 2, read: 3 };
const STATUS = {
  sending: ["🕓", "Enviando…"],
  sent: ["✓", "Enviado"],
  delivered: ["✓✓", "Entregado"],
  read: ["✓✓", "Leído"],
  failed: ["⚠️", "No se pudo enviar"],
};

function setStatus(peer, m, status) {
  if (m.status === status) return;
  if (status !== "failed" && m.status in ORDER && ORDER[status] < ORDER[m.status]) return; // nunca hacia atrás
  m.status = status;
  history?.put(peer, m);
  const el = m.el?.querySelector(".tick");
  if (el) paintTick(el, status);
}

function paintTick(el, status) {
  el.textContent = STATUS[status][0];
  el.title = STATUS[status][1];
  el.className = `tick ${status}`;
}

function onEvent(ev) {
  switch (ev.kind) {
    case "message": return onIncoming(ev);
    case "receipt": {
      const byId = new Map(chat(ev.peer).messages.filter((m) => m.from === "me").map((m) => [m.id, m]));
      for (const id of ev.content.ids) {
        const m = byId.get(id);
        if (m) setStatus(ev.peer, m, ev.content.s);
      }
      break;
    }
    case "profile":
      client.contacts.setProfile(ev.peer, ev.content);
      if (ev.peer === active) renderHeader();
      break;
    case "presence":
      chat(ev.peer).online = ev.text === "online";
      if (ev.text === "online") flushOutbox(ev.peer);
      if (ev.peer === active) renderHeader();
      break;
    case "session":
      chat(ev.peer).online = true;
      sysOnce(ev.peer, "🔒 Los mensajes y archivos de este chat están cifrados de extremo a extremo.");
      if (ev.peer === active) renderHeader();
      break;
    case "identity_changed":
      addMsg(ev.peer, { sys: `⚠️ La clave de seguridad de @${ev.peer} ha cambiado. Si no ha cambiado de dispositivo, alguien podría estar suplantándole. Confírmalo con esa persona por otro medio.`, warn: true });
      break;
    case "warning":
      if (ev.peer && !/no está conectado|sesión caducada/.test(ev.text)) addMsg(ev.peer, { sys: ev.text, warn: true });
      break;
    case "disconnected":
      if (!client) break;
      connected = false;
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

async function onIncoming(ev) {
  const content = ev.content;
  const peer = ev.peer;
  if (content.mid && chat(peer).messages.some((m) => m.id === content.mid)) {
    sendReceipt(peer, [content.mid], "delivered"); // repetido (se reenvió): solo confirmamos
    return;
  }
  if (content.t === "unsupported") {
    addMsg(peer, { sys: `${displayName(peer)} envió un contenido que esta versión no puede mostrar.` });
    return;
  }
  const entry = { from: "them", content: { ...content, data: undefined }, read: false,
    ...(content.mid ? { id: content.mid } : {}), ...(ev.queuedAt ? { time: new Date(ev.queuedAt * 1000) } : {}) };
  if (content.t === "image" || content.t === "video") {
    const bytes = sodium.from_base64(content.data, sodium.base64_variants.ORIGINAL);
    entry.url = URL.createObjectURL(new Blob([bytes], { type: content.mime }));
    entry.hasMedia = true;
    const m = addMsg(peer, entry);
    history?.putMedia(peer, m.id, bytes);
  } else {
    addMsg(peer, entry);
  }
  if (content.mid) sendReceipt(peer, [content.mid], "delivered");
  if (peer === active && !document.hidden) markRead(peer);
  notify(peer, content);
}

// Confirmaciones agrupadas: si llegan 10 mensajes seguidos, mandamos una sola
const pendingReceipts = new Map(); // `${peer}|${status}` -> Set(ids)
function sendReceipt(peer, ids, status) {
  if (status === "read" && !prefs().readReceipts) return;
  const k = `${peer}|${status}`;
  const first = !pendingReceipts.has(k);
  if (first) pendingReceipts.set(k, new Set());
  for (const id of ids) pendingReceipts.get(k).add(id);
  if (!first) return;
  setTimeout(async () => {
    const set = pendingReceipts.get(k);
    pendingReceipts.delete(k);
    try { await client?.sendContent(peer, { t: "receipt", ids: [...set], s: status }); }
    catch { /* son opcionales: si falla, no pasa nada */ }
  }, 300);
}

function markRead(peer) {
  const unread = chat(peer).messages.filter((m) => m.from === "them" && !m.read);
  if (!unread.length) return;
  for (const m of unread) { m.read = true; history?.put(peer, m); }
  const ids = unread.map((m) => m.content?.mid).filter(Boolean);
  if (ids.length && connected) sendReceipt(peer, ids, "read");
  renderContacts();
  updateTitle();
}

function notify(peer, content) {
  if (!document.hidden || !prefs().notifications || !("Notification" in window) || Notification.permission !== "granted") return;
  // No mostramos el contenido: la notificación podría verse con la pantalla bloqueada.
  new Notification(displayName(peer), { body: content.t === "text" ? "Nuevo mensaje" : previewOf(content), tag: peer });
}

// --------------------------------------------------------------- acciones

async function onNewChat(ev) {
  ev.preventDefault();
  const input = $("new-chat-name");
  const name = input.value.trim().replace(/^@/, "");
  $("new-chat-error").hidden = true;
  if (!NAME_RE.test(name)) return showNewChatError("Escribe un @usuario válido.");
  if (name.toLowerCase() === me.toLowerCase()) return showNewChatError("Ese eres tú 🙂");
  if (!connected) return showNewChatError("Sin conexión: espera a que vuelva para buscar usuarios.");
  input.disabled = true;
  try {
    const info = await client.lookup(name);
    if (!info.exists) return showNewChatError(`No existe ningún usuario @${name}.`);
    input.value = "";
    chat(info.user).online = info.online;
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

async function openChat(peer) {
  active = peer;
  $("app").classList.add("in-chat");
  $("new-chat-error").hidden = true;
  closePicker();
  renderContacts();
  renderChat();
  markRead(peer);
  if (window.matchMedia("(pointer: fine)").matches) $("text").focus();
  // Si está conectado, preparamos ya la sesión en vivo
  if (connected && !client.sessions.has(peer) && chat(peer).online !== false) {
    try { await client.openSession(peer, 5000); }
    catch (e) { if (!(e instanceof P.IdentityMismatch)) { chat(peer).online = false; renderHeader(); } }
  }
}

/** Escribe un mensaje: aparece al momento con 🕓 y sale en cuanto haya conexión. */
async function send(content, { bytes = null, url = null } = {}) {
  const peer = active;
  if (!peer) return;
  const mid = newId();
  const m = addMsg(peer, { id: mid, from: "me", content: { ...content, data: undefined, mid }, status: "sending",
    ...(bytes ? { hasMedia: true, url } : {}) });
  if (bytes) await history?.putMedia(peer, mid, bytes);
  askNotifications();
  flushOutbox(peer);
}

// La bandeja de salida: mensajes con 🕓 que aún no ha recibido el servidor
const flushing = new Set();
async function flushOutbox(onlyPeer = null) {
  if (!client || !connected) return;
  for (const [peer, ch] of chats) {
    if (onlyPeer && peer !== onlyPeer) continue;
    if (flushing.has(peer)) continue;
    flushing.add(peer);
    try {
      for (const m of ch.messages.filter((x) => x.from === "me" && x.status === "sending")) {
        if (!connected) break;
        let content = m.content;
        if (m.hasMedia) {
          const bytes = await history.getMedia(peer, m.id);
          if (!bytes) { setStatus(peer, m, "failed"); continue; }
          content = { ...content, data: sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL) };
        }
        try {
          await client.sendContent(peer, content);
          setStatus(peer, m, "sent");
        } catch (e) {
          if (isConnectivity(e)) break; // se queda con 🕓 y se reintenta al reconectar
          setStatus(peer, m, "failed");
          addMsg(peer, { sys: e instanceof P.IdentityMismatch ? e.message : `No se pudo enviar: ${e.message}`, warn: true });
        }
      }
    } finally {
      flushing.delete(peer);
    }
  }
}

const isConnectivity = (e) => e instanceof ClientError && /no conectado|conexión cerrada|no responde|no respondió/.test(e.message);

async function onSend(ev) {
  ev.preventDefault();
  const t = $("text").value;
  if (!t.trim()) return;
  $("text").value = "";
  closePicker();
  await send({ t: "text", body: t });
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

function askNotifications() {
  if (prefs().notifications && "Notification" in window && Notification.permission === "default") Notification.requestPermission();
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
    client.setProfile(profile);
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
  return d;
}

function showPeerProfile(peer) {
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
    d.append(text(`Seguridad avanzada${c.verified ? " · ✔ verificado" : ""}`, "summary"),
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
  const save = (patch) => { window.SC_SET_PREFS({ ...prefs(), ...patch }); };

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
    b.onclick = () => { save({ accent: value }); for (const x of colors.children) x.setAttribute("aria-pressed", String(x === b)); };
    return b;
  };
  colors.append(mkColor(null, "A"), ...ACCENTS.map((c) => mkColor(c)));
  const picker = document.createElement("input");
  picker.type = "color";
  picker.value = p.accent || "#4f46e5";
  picker.title = "Elige cualquier color";
  picker.oninput = () => save({ accent: picker.value });
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
      save({ wall: "image", wallImage: `data:image/jpeg;base64,${img}` });
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
      save({ wall: id });
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
      b.onclick = () => { save({ [key]: value }); for (const x of g.children) x.setAttribute("aria-pressed", String(x === b)); };
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
    cb.onchange = () => save({ [key]: cb.checked });
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
  if (c.t === "image") return c.mime === "image/gif" ? "🎞️ GIF" : "📷 Foto";
  if (c.t === "video") return "🎬 Vídeo";
  return "";
}

function renderMe() {
  $("me-name").textContent = profile.name || me;
  setAvatar($("me-avatar"), profile.name || me, profile.avatar);
}

function renderContacts() {
  if (!client) return;
  const names = new Set([...client.contacts.all().map((c) => c.name), ...chats.keys()]);
  const lastTime = (n) => chats.get(n)?.messages.filter((m) => m.content).at(-1)?.time || 0;
  const list = [...names].sort((a, b) => lastTime(b) - lastTime(a) || displayName(a).localeCompare(displayName(b)));
  $("contacts-empty").hidden = list.length > 0;
  $("contacts").replaceChildren(...list.map((name) => {
    const last = chats.get(name)?.messages.filter((m) => m.content).at(-1);
    const unread = unreadOf(name);
    const li = document.createElement("li");
    if (name === active) li.className = "active";
    const btn = document.createElement("button");
    btn.type = "button";
    const main = text("", "span", "contact-main");
    const prev = text("", "span", "preview");
    if (last?.from === "me") {
      const tick = text("", "span");
      paintTick(tick, last.status || "sent");
      prev.append(tick, " ");
    }
    prev.append(last ? previewOf(last.content) : `@${name}`);
    main.append(text(displayName(name), "strong"), prev);
    const side = text("", "span", "contact-side");
    if (last) side.append(text(shortTime(last.time), "time"));
    if (unread) side.append(text(String(unread), "span", "unread"));
    btn.append(setAvatar(text("", "span", "avatar"), displayName(name), avatarOf(name)), main, side);
    btn.onclick = () => openChat(name);
    li.append(btn);
    return li;
  }));
}

function renderHeader() {
  if (!client) return;
  const has = !!active;
  if (has) {
    $("peer-name").textContent = displayName(active);
    setAvatar($("peer-avatar"), displayName(active), avatarOf(active));
    const online = client.sessions.has(active) || chat(active).online === true;
    const c = client.contacts.get(active);
    $("peer-status").replaceChildren(online ? text("en línea", "span", "lock") : text(c?.bio || `@${active}`, "span"));
  }
  $("chat").classList.toggle("is-empty", !has);
  $("empty-chat").hidden = has;
}

function renderChat() {
  renderHeader();
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

async function mediaUrl(m) {
  if (m.url) return m.url;
  const bytes = await history?.getMedia(active, m.id);
  if (!bytes) return null;
  m.url = URL.createObjectURL(new Blob([bytes], { type: m.content.mime }));
  return m.url;
}

function appendMessage(m) {
  const list = $("messages");
  // Separador de día (Hoy, Ayer, lunes…) como en WhatsApp
  const label = dayLabel(m.time);
  if (list.dataset.day !== label) {
    list.dataset.day = label;
    list.append(text(label, "li", "day"));
  }
  let li;
  if (m.sys) li = text(m.sys, "li", `sys${m.warn ? " warn" : ""}`);
  else {
    const prev = list.lastElementChild;
    const side = m.from === "me" ? "mine" : "theirs";
    const cont = prev?.classList.contains(side) ? "cont" : "first";
    const c = m.content;
    li = document.createElement("li");
    if (c.t === "text") {
      li.className = `msg ${side} ${cont}${isJumboEmoji(c.body) ? " jumbo" : ""}`;
      li.append(text(c.body, "span", "body"));
    } else if (c.t === "sticker") {
      li.className = `msg ${side} ${cont} sticker`;
      li.append(text(c.id, "span", "sticker-face"));
    } else {
      li.className = `msg ${side} ${cont} media`;
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
      mediaUrl(m).then((u) => { if (u) el.src = u; else li.classList.add("missing"); });
      li.append(el);
    }
    const t = text(hhmm(m.time), "time");
    if (m.from === "me") {
      const tick = text("", "span");
      paintTick(tick, m.status || "sent");
      t.append(" ", tick);
    }
    li.append(t);
    m.el = li;
  }
  list.append(li);
  li.scrollIntoView({ block: "end" });
}

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
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("picker").hidden) closePicker(); });
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
