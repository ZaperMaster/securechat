// Service worker: permite instalar SecureChat como app y abrirla sin red
// (la interfaz carga; para enviar mensajes hace falta el servidor).
const CACHE = "securechat-v36";
const SHELL = [
  "./", "index.html", "styles.css", "manifest.webmanifest", "icon.svg", "lock.svg", "icon-192.png", "icon-512.png",
  "js/theme.js", "js/lang-en.js", "js/i18n.js", "js/app.js", "js/emoji.js", "js/vault.js", "js/ratchet.js", "js/senderkeys.js", "js/icons.js", "js/client.js", "js/protocol.js",
  "vendor/libsodium-sumo.js", "vendor/libsodium-wrappers.js", "vendor/noble-pq.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE && k !== "securechat-lang").map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// Red primero (para recibir siempre la última versión del código) y caché como respaldo.
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  // config.json dice si el servidor está vivo: nunca desde la caché
  if (url.pathname.endsWith("/config.json")) return;
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
        return res;
      })
      .catch(() => caches.match(e.request)),
  );
});

// Idioma de los avisos: la página nos lo dice y lo guardamos (el service worker no ve localStorage)
const TEXTS = {
  es: { one: "Tienes un mensaje nuevo 🔒", many: (n) => `Tienes ${n} mensajes nuevos 🔒`, call: "📞 Te están llamando. Toca para abrir y contestar." },
  en: { one: "You have a new message 🔒", many: (n) => `You have ${n} new messages 🔒`, call: "📞 Someone is calling you. Tap to open and answer." },
};
self.addEventListener("message", (e) => {
  if (e.data?.type === "lang" && TEXTS[e.data.lang]) {
    e.waitUntil(caches.open("securechat-lang").then((c) => c.put("lang", new Response(e.data.lang))));
  }
});
const langTexts = () => caches.open("securechat-lang").then((c) => c.match("lang")).then((r) => (r ? r.text() : "es"))
  .then((l) => TEXTS[l] || TEXTS.es).catch(() => TEXTS.es);

// Aviso con la app cerrada. No lleva contenido: solo "tienes un mensaje nuevo".
self.addEventListener("push", (e) => e.waitUntil(langTexts().then((T) => onPush(e, T))));

function onPush(e, T) {
  let data = { title: "SecureChat", body: T.one };
  try { data = { ...data, ...e.data.json() }; } catch { /* sin datos */ }
  if (data.body === "Tienes un mensaje nuevo 🔒") data.body = T.one; // el servidor lo manda en español
  return self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((wins) => {
    // Si la app está abierta y a la vista, ya lo ve ella: no molestamos
    if (wins.some((w) => w.visibilityState === "visible")) return;
    // Llamada entrante: aviso que no se agrupa, vibra y se queda hasta que lo toques
    if (data.kind === "call") {
      return self.registration.showNotification("SecureChat", {
        body: T.call, icon: "icon-192.png", badge: "icon-192.png",
        tag: "call", renotify: true, requireInteraction: true, vibrate: [400, 200, 400, 200, 400], data: { call: true },
      });
    }
    return self.registration.getNotifications({ tag: "securechat-new" }).then((prev) => {
      const count = (prev[0]?.data?.count || 0) + 1;
      return self.registration.showNotification(data.title, {
        body: count > 1 ? T.many(count) : data.body,
        icon: "icon-192.png", badge: "icon-192.png", tag: "securechat-new", renotify: true, data: { count },
      });
    });
  });
}

// Al pulsar una notificación:
//  * «Responder» con texto escrito en la notificación: lo envía la app abierta (sin traerla al frente).
//  * «Responder» sin texto (navegadores sin respuesta en línea) o pulsar el aviso: abre ese chat.
//  * «Marcar como leído»: avisa a la app y cierra la notificación.
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const data = e.notification.data || {};
  const msg = e.action === "read" ? { type: "notif-read" }
    : e.action === "reply" && e.reply ? { type: "notif-reply", text: e.reply }
    : e.action === "reply" ? { type: "notif-reply" } : { type: "notif-open" };
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(async (cs) => {
    const win = cs[0];
    if (win && data.conv) win.postMessage({ ...msg, conv: data.conv, account: data.account });
    if (msg.type === "notif-read" || (msg.type === "notif-reply" && msg.text)) return;
    if (win) return win.focus();
    return self.clients.openWindow("./");
  }));
});
