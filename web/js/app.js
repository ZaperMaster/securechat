// Interfaz web. Toda la criptografía ocurre aquí, en el navegador:
// el servidor solo recibe mensajes ya cifrados (texto, fotos, vídeos y perfiles).

import { ChatClient, ClientError, Contacts, IMAGE_MIME, MAX_MEDIA, VIDEO_MIME } from "./client.js";
import { EMOJIS, STICKERS } from "./emoji.js";
import * as P from "./protocol.js";

const $ = (id) => document.getElementById(id);
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9_]$/;
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
};
const idKey = (name) => `sc:identity:${name.toLowerCase()}`;

let me = null;          // mi @usuario (grafía oficial)
let identity = null;    // {seed, publicKey, privateKey}
let profile = null;     // {name, avatar}: lo que ven los demás
let client = null;
let active = null;      // conversación abierta
const chats = new Map(); // peer -> {messages: [], unread: 0, online: bool|null}
let reconnectTimer = null;

// ---------------------------------------------------------------- acceso

function updateLoginMode() {
  const name = $("login-name").value.trim();
  const blob = NAME_RE.test(name) && store.get(idKey(name));
  $("login-pass2-wrap").hidden = !!blob || !NAME_RE.test(name);
  $("login-pass2").required = !blob;
  $("login-btn").textContent = blob ? "Entrar" : "Crear cuenta";
  $("login-hint").textContent = !NAME_RE.test(name) ? (name ? "3-32 caracteres: letras, números, '_', '.' o '-'." : "")
    : blob ? `Cuenta @${blob.username || name} encontrada en este navegador.`
    : "Tu @usuario es único. Después podrás poner tu nombre visible y una foto. Si olvidas la contraseña no se puede recuperar.";
  $("login-pass").autocomplete = blob ? "current-password" : "new-password";
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
    await startApp(blob.username || name);
    // Solo guardamos la cuenta nueva si el servidor aceptó el nombre
    if (isNew) store.set(idKey(me), { ...blob, username: me });
    store.set("sc:last", me);
    $("login-pass").value = $("login-pass2").value = "";
  } catch (e) {
    identity = null;
    $("login-error").textContent = e instanceof P.CryptoError && /contraseña/.test(e.message) ? "Contraseña incorrecta."
      : /en uso/.test(e.message) ? `El usuario @${name} ya existe. Elige otro nombre.` : e.message;
  } finally {
    $("login-btn").disabled = false;
    updateLoginMode();
  }
}

async function startApp(username) {
  const contacts = new Contacts(store.get(`sc:contacts:${username.toLowerCase()}`) || {}, (data) => {
    store.set(`sc:contacts:${me.toLowerCase()}`, data);
    renderContacts();
    renderHeader();
  });
  client = new ChatClient(username, identity, contacts, onEvent);
  try { await client.connect(wsUrl()); }
  catch (e) { client = null; throw e; }
  me = client.name;
  profile = store.get(`sc:profile:${me.toLowerCase()}`) || { name: me, avatar: null };
  client.profile = profile;
  setConn(true);
  $("login").hidden = true;
  $("app").hidden = false;
  renderMe();
  renderContacts();
  renderChat();
}

const wsUrl = () => `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/`;

async function reconnect() {
  if (!client) return;
  try {
    await client.connect(wsUrl());
    setConn(true);
  } catch {
    setConn(false);
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(reconnect, 3000);
}

function setConn(on) {
  $("conn").textContent = on ? "En línea" : "Sin conexión, reintentando…";
  $("conn").className = `conn ${on ? "on" : "off"}`;
}

function logout() {
  clearTimeout(reconnectTimer);
  const c = client;
  client = null;
  c?.close();
  for (const ch of chats.values()) for (const m of ch.messages) if (m.url) URL.revokeObjectURL(m.url);
  identity = null; me = null; active = null; profile = null;
  chats.clear();
  $("messages").replaceChildren();
  $("picker").hidden = true;
  $("app").hidden = true;
  $("login").hidden = false;
  updateLoginMode();
}

// ------------------------------------------------------------- nombres

const displayName = (peer) => client?.contacts.get(peer)?.displayName || peer;
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

// ---------------------------------------------------------------- eventos

function chat(peer) {
  if (!chats.has(peer)) chats.set(peer, { messages: [], unread: 0, online: null });
  return chats.get(peer);
}

function addMsg(peer, entry) {
  const c = chat(peer);
  const m = { time: new Date(), ...entry };
  c.messages.push(m);
  if (m.from === "them" && (peer !== active || document.hidden)) c.unread += 1;
  if (peer === active) appendMessage(m);
  renderContacts();
  updateTitle();
  return m;
}

function onEvent(ev) {
  switch (ev.kind) {
    case "message": {
      const content = ev.content;
      if (content.t === "unsupported") return addMsg(ev.peer, { sys: `${displayName(ev.peer)} envió un contenido que esta versión no puede mostrar.` });
      const entry = { from: "them", content };
      if (content.t === "image" || content.t === "video") {
        entry.url = URL.createObjectURL(new Blob([sodium.from_base64(content.data, sodium.base64_variants.ORIGINAL)], { type: content.mime }));
        delete content.data; // no guardamos dos copias en memoria
      }
      addMsg(ev.peer, entry);
      notify(ev.peer, content);
      break;
    }
    case "profile":
      client.contacts.setProfile(ev.peer, ev.content);
      if (ev.peer === active) renderChat();
      break;
    case "session":
      chat(ev.peer).online = true;
      if (ev.text === "sesión iniciada" && !chat(ev.peer).messages.some((m) => m.sys)) {
        addMsg(ev.peer, { sys: "🔒 Los mensajes y archivos de este chat están cifrados de extremo a extremo." });
      }
      renderHeader();
      break;
    case "identity_changed":
      addMsg(ev.peer, { sys: `⚠️ La clave de seguridad de @${ev.peer} ha cambiado. Si no ha cambiado de dispositivo, alguien podría estar suplantándole. Confírmalo con esa persona por otro medio.`, warn: true });
      break;
    case "warning":
      if (ev.peer) {
        if (/no está conectado/.test(ev.text)) { chat(ev.peer).online = false; renderHeader(); }
        addMsg(ev.peer, { sys: ev.text, warn: true });
      }
      break;
    case "disconnected":
      if (client) { setConn(false); scheduleReconnect(); }
      break;
  }
}

function notify(peer, content) {
  if (!document.hidden || !("Notification" in window) || Notification.permission !== "granted") return;
  // No mostramos el contenido: la notificación podría verse con la pantalla bloqueada.
  new Notification(displayName(peer), { body: content.t === "text" ? "Nuevo mensaje" : previewOf(content), tag: peer });
}

// --------------------------------------------------------------- acciones

async function onNewChat(ev) {
  ev.preventDefault();
  const input = $("new-chat-name");
  const name = input.value.trim().replace(/^@/, "");
  const err = $("new-chat-error");
  err.hidden = true;
  if (!NAME_RE.test(name)) return showNewChatError("Escribe un @usuario válido.");
  if (name.toLowerCase() === me.toLowerCase()) return showNewChatError("Ese eres tú 🙂");
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

function showNewChatError(text) {
  $("new-chat-error").textContent = text;
  $("new-chat-error").hidden = false;
}

async function openChat(peer) {
  active = peer;
  chat(peer).unread = 0;
  $("app").classList.add("in-chat");
  $("new-chat-error").hidden = true;
  closePicker();
  renderContacts();
  renderChat();
  updateTitle();
  $("text").focus();
  if (!client.sessions.has(peer)) {
    try { await client.openSession(peer); }
    catch (e) {
      const offline = /no está conectado|no respondió/.test(e.message);
      chat(peer).online = offline ? false : chat(peer).online;
      renderHeader();
      if (offline) addMsg(peer, { sys: `${displayName(peer)} no está conectado ahora. Podrás escribirle cuando se conecte.` });
      else addMsg(peer, { sys: e.message, warn: true });
    }
  }
}

async function send(content, local = {}) {
  const peer = active;
  if (!peer) return;
  try {
    await client.sendContent(peer, content);
    if (content.t === "image" || content.t === "video") delete content.data;
    addMsg(peer, { from: "me", content, ...local });
    askNotifications();
    return true;
  } catch (e) {
    if (local.url) URL.revokeObjectURL(local.url);
    const offline = /no está conectado|no respondió|conexión cerrada/.test(e.message);
    if (offline) { chat(peer).online = false; renderHeader(); }
    addMsg(peer, { sys: offline ? `No se pudo enviar: ${displayName(peer)} no está conectado.` : `No se pudo enviar: ${e.message}`, warn: true });
    return false;
  }
}

async function onSend(ev) {
  ev.preventDefault();
  const text = $("text").value;
  if (!text.trim()) return;
  $("text").value = "";
  closePicker();
  if (!await send({ t: "text", body: text })) $("text").value = text;
}

async function sendFile(file) {
  if (!file || !active) return;
  const isImage = IMAGE_MIME.includes(file.type), isVideo = VIDEO_MIME.includes(file.type);
  if (!isImage && !isVideo) return addMsg(active, { sys: "Solo puedes enviar fotos (PNG, JPG, GIF, WebP) o vídeos (MP4, WebM, MOV).", warn: true });
  if (file.size > MAX_MEDIA) return addMsg(active, { sys: `El archivo pesa ${(file.size / 1048576).toFixed(1)} MB. El máximo es 8 MB.`, warn: true });
  const bytes = new Uint8Array(await file.arrayBuffer());
  const content = { t: isImage ? "image" : "video", mime: file.type, name: file.name.slice(0, 120),
    data: sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL) };
  await send(content, { url: URL.createObjectURL(file) });
}

function askNotifications() {
  if ("Notification" in window && Notification.permission === "default") Notification.requestPermission();
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
    for (const [group, list] of EMOJIS) {
      body.append(text(group, "p", "picker-group"));
      const grid = text("", "div", "emoji-grid");
      for (const e of list) {
        const b = text(e, "button", "emoji");
        b.type = "button";
        b.onclick = () => insertAtCursor($("text"), e);
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
    try { avatar = await resizeAvatar(fileIn.files[0]); setAvatar(preview, nameIn.value || me, avatar); }
    catch { change.textContent = "Imagen no válida"; }
  };

  const nameIn = document.createElement("input");
  nameIn.value = profile.name || me;
  nameIn.maxLength = 64;
  nameIn.placeholder = me;
  const nameField = text("", "label", "field");
  nameField.append(text("Nombre visible", "span"), nameIn);

  const head = text("", "div", "profile-head");
  const btns = text("", "div", "profile-photo-btns");
  btns.append(change, remove, fileIn);
  head.append(preview, btns);

  dialog("Mi perfil", [
    head,
    nameField,
    text(`Tu usuario es @${me}. Es único y es lo que otros escriben para encontrarte.`, "p", "hint"),
    text("Tu nombre y tu foto viajan cifrados: solo los ven tus contactos, nunca el servidor.", "p", "hint"),
    advancedSecurityMine(),
  ], [["Cancelar"], ["Guardar", () => {
    profile = { name: nameIn.value.trim().slice(0, 64) || me, avatar };
    if (!store.set(`sc:profile:${me.toLowerCase()}`, profile)) profile.avatar = null;
    client.setProfile(profile);
    renderMe();
  }]]);
}

/** Recorta la foto a un cuadrado de 256 px en JPEG: pocos KB y sin metadatos (EXIF/GPS). */
async function resizeAvatar(file) {
  const bmp = await createImageBitmap(file);
  const size = 256, side = Math.min(bmp.width, bmp.height);
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  canvas.getContext("2d").drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, size, size);
  const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.85));
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
    text(displayName(peer), "h3"), text(`@${peer}`, "p", "muted"));
  const body = [head];
  if (c) {
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
  dialog("Perfil", body);
}

// -------------------------------------------------------------- renderizado

function text(t, tag = "p", cls = "") {
  const el = document.createElement(tag);
  el.textContent = t; // siempre textContent: nunca interpretamos HTML recibido
  if (cls) el.className = cls;
  return el;
}

const hhmm = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

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
  const list = [...names].sort((a, b) => {
    const ta = chats.get(a)?.messages.at(-1)?.time || 0, tb = chats.get(b)?.messages.at(-1)?.time || 0;
    return tb - ta || displayName(a).localeCompare(displayName(b));
  });
  $("contacts-empty").hidden = list.length > 0;
  $("contacts").replaceChildren(...list.map((name) => {
    const ch = chats.get(name);
    const last = ch?.messages.filter((m) => m.content).at(-1);
    const li = document.createElement("li");
    if (name === active) li.className = "active";
    const btn = document.createElement("button");
    btn.type = "button";
    const main = text("", "span", "contact-main");
    main.append(text(displayName(name), "strong"),
      text(last ? `${last.from === "me" ? "Tú: " : ""}${previewOf(last.content)}` : `@${name}`, "span", "preview"));
    const side = text("", "span", "contact-side");
    if (last) side.append(text(hhmm(last.time), "time"));
    if (ch?.unread) side.append(text(String(ch.unread), "span", "unread"));
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
    const online = client.sessions.has(active) || chat(active).online;
    const status = $("peer-status");
    status.replaceChildren(text(`@${active}`, "span"), text("·", "span"),
      client.sessions.has(active) ? text("🔒 cifrado", "span", "lock")
        : text(online === false ? "desconectado" : "conectando…", "span"));
  }
  for (const id of ["text", "send-btn", "emoji-btn", "attach-btn"]) $(id).disabled = !has;
  $("chat").classList.toggle("is-empty", !has);
  $("empty-chat").hidden = has;
}

function renderChat() {
  renderHeader();
  $("messages").replaceChildren();
  if (active) for (const m of chat(active).messages) appendMessage(m);
}

const segmenter = "Segmenter" in Intl ? new Intl.Segmenter() : null;
function isJumboEmoji(s) {
  if (!segmenter || !/^[\p{Extended_Pictographic}\p{Emoji_Component}‍️\s]+$/u.test(s) || /[0-9#*]/.test(s.trim()[0])) return false;
  const n = [...segmenter.segment(s.trim())].length;
  return n >= 1 && n <= 3;
}

function appendMessage(m) {
  let li;
  if (m.sys) li = text(m.sys, "li", `sys${m.warn ? " warn" : ""}`);
  else {
    const prev = $("messages").lastElementChild;
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
      let el;
      if (c.t === "image") {
        el = document.createElement("img");
        el.alt = c.name || "imagen";
        el.onclick = () => viewImage(m.url, c.name);
        el.onload = () => li.scrollIntoView({ block: "end" });
      } else {
        el = document.createElement("video");
        el.controls = true;
        el.playsInline = true;
        el.preload = "metadata";
      }
      el.src = m.url;
      li.append(el);
    }
    li.append(text(hhmm(m.time), "time"));
  }
  $("messages").append(li);
  li.scrollIntoView({ block: "end" });
}

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
  const n = [...chats.values()].reduce((s, c) => s + c.unread, 0);
  document.title = n ? `(${n}) SecureChat` : "SecureChat";
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

function showThemes() {
  const current = document.documentElement.dataset.theme;
  const grid = text("", "div", "themes");
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
      for (const el of grid.children) el.setAttribute("aria-pressed", String(el === card));
    };
    grid.append(card);
  }
  dialog("Tema", [grid]);
}

async function main() {
  await P.ready();
  const last = store.get("sc:last");
  $("login-name").value = last || "";
  $("login-name").addEventListener("input", updateLoginMode);
  $("login-form").addEventListener("submit", onLogin);
  $("composer").addEventListener("submit", onSend);
  $("new-chat").addEventListener("submit", onNewChat);
  $("new-chat-name").addEventListener("input", () => { $("new-chat-error").hidden = true; });
  $("profile-btn").onclick = showMyProfile;
  $("peer-btn").onclick = () => active && showPeerProfile(active);
  $("logout-btn").onclick = logout;
  $("theme-btn").onclick = showThemes;
  $("login-theme-btn").onclick = showThemes;
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
    if (!document.hidden && active) { chat(active).unread = 0; renderContacts(); updateTitle(); }
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () =>
    window.applyTheme(document.documentElement.dataset.theme));
  updateLoginMode();
  if ($("login-name").value) $("login-pass").focus(); else $("login-name").focus();
  if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("sw.js");
}

main();
