// Interfaz web. Toda la criptografía ocurre aquí, en el navegador:
// el servidor solo recibe mensajes ya cifrados.

import { ChatClient, ClientError, Contacts } from "./client.js";
import * as P from "./protocol.js";

const $ = (id) => document.getElementById(id);
const NAME_RE = /^[a-z0-9_]{3,32}$/;
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* modo privado */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
};

let me = null;          // nombre de usuario
let identity = null;    // {seed, publicKey, privateKey}
let client = null;
let active = null;      // conversación abierta
const chats = new Map(); // peer -> {messages: [], unread: 0}
let reconnectTimer = null;

// ---------------------------------------------------------------- acceso

function updateLoginMode() {
  const name = $("login-name").value.trim();
  const exists = NAME_RE.test(name) && store.get(`sc:identity:${name}`);
  $("login-pass2-wrap").hidden = !!exists || !NAME_RE.test(name);
  $("login-pass2").required = !exists;
  $("login-btn").textContent = exists ? "Entrar" : "Crear identidad";
  $("login-hint").textContent = !NAME_RE.test(name) ? ""
    : exists ? "Identidad encontrada en este navegador."
    : "Se generará una clave nueva en este navegador. Si olvidas la contraseña no se puede recuperar.";
  $("login-pass").autocomplete = exists ? "current-password" : "new-password";
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
    let blob = store.get(`sc:identity:${name}`);
    if (!blob) {
      if (pass !== $("login-pass2").value) throw new Error("Las contraseñas no coinciden.");
      blob = P.saveIdentity(P.newIdentitySeed(), pass);
      identity = P.loadIdentity(blob, pass);
      store.set(`sc:identity:${name}`, blob);
    } else {
      identity = P.loadIdentity(blob, pass);
    }
    me = name;
    store.set("sc:last", name);
    $("login-pass").value = $("login-pass2").value = "";
    await startApp();
  } catch (e) {
    identity = null;
    $("login-error").textContent = e instanceof P.CryptoError && /contraseña/.test(e.message)
      ? "Contraseña incorrecta." : e.message;
  } finally {
    $("login-btn").disabled = false;
    updateLoginMode();
  }
}

async function startApp() {
  const contacts = new Contacts(store.get(`sc:contacts:${me}`) || {}, (data) => {
    store.set(`sc:contacts:${me}`, data);
    renderContacts();
    renderHeader();
  });
  client = new ChatClient(me, identity, contacts, onEvent);
  await connect();
  $("login").hidden = true;
  $("app").hidden = false;
  $("me-name").textContent = me;
  setAvatar($("me-avatar"), me);
  renderContacts();
  renderChat();
}

async function connect() {
  const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/`;
  try {
    await client.connect(url);
    setConn(true);
  } catch (e) {
    setConn(false);
    if (!$("app").hidden) scheduleReconnect();
    else { client = null; throw e; }
  }
}

function scheduleReconnect() {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => client && connect(), 3000);
}

function setConn(on) {
  $("conn").textContent = on ? "conectado" : "sin conexión, reintentando…";
  $("conn").className = `conn ${on ? "on" : "off"}`;
}

function logout() {
  clearTimeout(reconnectTimer);
  const c = client;
  client = null;
  c?.close();
  identity = null; me = null; active = null;
  chats.clear();
  $("messages").replaceChildren();
  $("app").hidden = true;
  $("login").hidden = false;
  updateLoginMode();
}

// ---------------------------------------------------------------- eventos

function chat(peer) {
  if (!chats.has(peer)) chats.set(peer, { messages: [], unread: 0 });
  return chats.get(peer);
}

function addMsg(peer, entry) {
  const c = chat(peer);
  c.messages.push({ time: new Date(), ...entry });
  if (peer !== active || document.hidden) c.unread += entry.from === "them" ? 1 : 0;
  if (peer === active) appendMessage(c.messages.at(-1));
  renderContacts();
  renderHeader();
  updateTitle();
}

function onEvent(ev) {
  switch (ev.kind) {
    case "message":
      addMsg(ev.peer, { from: "them", text: ev.text });
      if (document.hidden && "Notification" in window && Notification.permission === "granted") {
        // No mostramos el texto: la notificación podría verse en la pantalla bloqueada.
        new Notification("SecureChat", { body: `Nuevo mensaje de ${ev.peer}`, tag: ev.peer });
      }
      break;
    case "session": {
      const c = client.contacts.get(ev.peer);
      addMsg(ev.peer, { sys: `🔒 ${ev.text}. ${c?.verified ? "Contacto verificado." : "Sin verificar: compara el número de seguridad."}` });
      break;
    }
    case "identity_changed":
      addMsg(ev.peer, { sys: `⚠️ ${ev.text} Puede ser un ataque man-in-the-middle o que ${ev.peer} cambió de dispositivo. Confírmalo por otro canal.`, warn: true });
      break;
    case "warning":
      if (ev.peer) addMsg(ev.peer, { sys: ev.text, warn: true });
      break;
    case "disconnected":
      if (client) { setConn(false); scheduleReconnect(); }
      break;
  }
}

// --------------------------------------------------------------- acciones

async function openChat(peer) {
  active = peer;
  chat(peer).unread = 0;
  $("app").classList.add("in-chat");
  renderContacts();
  renderChat();
  updateTitle();
  if (!client.sessions.has(peer)) {
    try { await client.openSession(peer); }
    catch (e) { addMsg(peer, { sys: `No se pudo abrir la sesión: ${e.message}`, warn: true }); }
  }
  $("text").focus();
}

async function onSend(ev) {
  ev.preventDefault();
  const text = $("text").value;
  if (!text.trim() || !active) return;
  const peer = active;
  $("text").value = "";
  try {
    await client.sendText(peer, text);
    addMsg(peer, { from: "me", text });
    askNotifications();
  } catch (e) {
    $("text").value = text;
    addMsg(peer, { sys: e instanceof ClientError ? e.message : `Error: ${e.message}`, warn: true });
  }
}

function askNotifications() {
  if ("Notification" in window && Notification.permission === "default") Notification.requestPermission();
}

function showSafety(peer) {
  const c = client.contacts.get(peer);
  if (!c) return dialog("Sin clave", [text(`Todavía no conoces la clave de ${peer}. Abre antes una sesión.`)]);
  const num = P.safetyNumber(me, identity.publicKey, peer, c.key);
  const grid = document.createElement("div");
  grid.className = "safety";
  for (const g of num.split(" ")) grid.append(text(g, "span"));
  const actions = c.verified
    ? [["Quitar verificación", () => client.contacts.setVerified(peer, false)], ["Cerrar"]]
    : [["Cerrar"], ["Coinciden: marcar verificado", () => client.contacts.setVerified(peer, true)]];
  dialog(`Número de seguridad con ${peer}`, [
    text(c.verified ? "✔ Verificado" : "Compara estos 60 dígitos con los que ve tu contacto, en persona o por otro canal. Si coinciden, nadie está interceptando la conversación."),
    grid,
    text(`Huella de ${peer}: ${P.fingerprint(c.key)}`, "p", "small muted mono"),
  ], actions);
  renderChat();
}

function showMe() {
  const blob = store.get(`sc:identity:${me}`);
  dialog("Tu identidad", [
    text("Tu huella (compártela si alguien quiere comprobar tu clave):"),
    text(P.fingerprint(identity.publicKey), "p", "mono"),
    text("La clave privada está guardada en este navegador, cifrada con tu contraseña. Puedes exportarla para usarla en la versión de terminal (identity.json).", "p", "small muted"),
  ], [["Exportar identidad", () => download(`${me}-identity.json`, JSON.stringify(blob, null, 2))], ["Cerrar"]]);
}

// -------------------------------------------------------------- renderizado

function text(t, tag = "p", cls = "") {
  const el = document.createElement(tag);
  el.textContent = t; // siempre textContent: nunca interpretamos HTML recibido
  if (cls) el.className = cls;
  return el;
}

const hhmm = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

/** Avatar con la inicial y un color estable derivado del nombre. */
function setAvatar(el, name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)) % 360;
  el.textContent = name[0] || "?";
  el.style.setProperty("--h", h); // CSSOM: permitido por la CSP (no es un atributo style inline)
  return el;
}

function shieldIcon(ok) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", `shield ${ok ? "ok" : "no"}`);
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", ok ? "M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z M8.5 12l2.5 2.5 4.5-5"
    : "M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z M12 8v5 M12 16.5v.01");
  svg.append(path);
  const title = document.createElementNS(NS, "title");
  title.textContent = ok ? "Verificado" : "Sin verificar";
  svg.append(title);
  return svg;
}

function renderContacts() {
  if (!client) return;
  const names = new Set([...client.contacts.all().map((c) => c.name), ...chats.keys()]);
  const list = [...names].sort((a, b) => {
    const ta = chats.get(a)?.messages.at(-1)?.time || 0, tb = chats.get(b)?.messages.at(-1)?.time || 0;
    return tb - ta || a.localeCompare(b);
  });
  $("contacts-empty").hidden = list.length > 0;
  $("contacts").replaceChildren(...list.map((name) => {
    const c = client.contacts.get(name);
    const ch = chats.get(name);
    const last = ch?.messages.filter((m) => m.text).at(-1);
    const li = document.createElement("li");
    if (name === active) li.className = "active";
    const btn = document.createElement("button");
    btn.type = "button";

    const top = text("", "span", "contact-top");
    top.append(text(name, "strong"));
    if (c) top.append(shieldIcon(c.verified));
    const main = text("", "span", "contact-main");
    main.append(top, text(last ? `${last.from === "me" ? "Tú: " : ""}${last.text}`
      : client.sessions.has(name) ? "🔒 Sesión cifrada lista" : "Sin mensajes", "span", "preview"));

    const side = text("", "span", "contact-side");
    if (last) side.append(text(hhmm(last.time), "time"));
    if (ch?.unread) side.append(text(String(ch.unread), "span", "unread"));

    btn.append(setAvatar(text("", "span", "avatar"), name), main, side);
    btn.onclick = () => openChat(name);
    li.append(btn);
    return li;
  }));
}

function renderHeader() {
  if (!client) return;
  const has = !!active;
  const c = active && client.contacts.get(active);
  const online = active && client.sessions.has(active);
  $("peer-name").textContent = active || "";
  $("peer-avatar").hidden = !has;
  if (has) setAvatar($("peer-avatar"), active);
  const status = $("peer-status");
  status.replaceChildren();
  if (has) {
    status.append(online ? text("🔒 Cifrado E2E", "span", "lock") : text("Conectando…", "span"));
    status.append(text("·", "span"), text(c?.verified ? "verificado" : "sin verificar", "span"));
  }
  $("verify-btn").hidden = !c;
  $("verify-btn").textContent = c?.verified ? "✔ Verificado" : "Verificar";
  $("verify-btn").classList.toggle("ok", !!c?.verified);
  $("text").disabled = $("send-btn").disabled = !has;
  $("chat").classList.toggle("is-empty", !has);
  $("empty-chat").hidden = has;
}

function renderChat() {
  renderHeader();
  $("messages").replaceChildren();
  if (active) for (const m of chat(active).messages) appendMessage(m);
}

function appendMessage(m) {
  let li;
  if (m.sys) li = text(m.sys, "li", `sys${m.warn ? " warn" : ""}`);
  else {
    // Agrupa mensajes seguidos del mismo autor (burbujas más compactas)
    const prev = $("messages").lastElementChild;
    const side = m.from === "me" ? "mine" : "theirs";
    const cont = prev?.classList.contains(side);
    li = text(m.text, "li", `msg ${side} ${cont ? "cont" : "first"}`);
    li.append(text(hhmm(m.time), "time"));
  }
  $("messages").append(li);
  li.scrollIntoView({ block: "end" });
}

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
    b.onclick = () => { fn?.(); renderChat(); };
    return b;
  }));
  $("dialog").showModal();
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

async function main() {
  await P.ready();
  $("login-name").value = store.get("sc:last") || "";
  $("login-name").addEventListener("input", updateLoginMode);
  $("login-form").addEventListener("submit", onLogin);
  $("composer").addEventListener("submit", onSend);
  $("new-chat").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = $("new-chat-name").value.trim().toLowerCase();
    if (!NAME_RE.test(name) || name === me) return;
    $("new-chat-name").value = "";
    openChat(name);
  });
  $("verify-btn").onclick = () => showSafety(active);
  $("me-btn").onclick = showMe;
  $("theme-btn").onclick = showThemes;
  $("login-theme-btn").onclick = showThemes;
  // Con el tema "Sistema", sigue los cambios de claro/oscuro del dispositivo
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () =>
    window.applyTheme(document.documentElement.dataset.theme));
  $("logout-btn").onclick = logout;
  $("back-btn").onclick = () => { active = null; $("app").classList.remove("in-chat"); renderContacts(); renderChat(); };
  $("install-btn").onclick = async () => { await installPrompt?.prompt(); installPrompt = null; $("install-btn").hidden = true; };
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && active) { chat(active).unread = 0; renderContacts(); updateTitle(); }
  });
  updateLoginMode();
  if ($("login-name").value) $("login-pass").focus(); else $("login-name").focus();
  if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("sw.js");
}

main();
