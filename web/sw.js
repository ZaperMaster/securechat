// Service worker: permite instalar SecureChat como app y abrirla sin red
// (la interfaz carga; para enviar mensajes hace falta el servidor).
const CACHE = "securechat-v8";
const SHELL = [
  "./", "index.html", "styles.css", "manifest.webmanifest", "icon.svg", "lock.svg", "icon-192.png", "icon-512.png",
  "js/theme.js", "js/app.js", "js/emoji.js", "js/vault.js", "js/client.js", "js/protocol.js",
  "vendor/libsodium-sumo.js", "vendor/libsodium-wrappers.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
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

// Al pulsar una notificación, enfocamos la ventana abierta.
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window" }).then((cs) => cs[0]?.focus() || self.clients.openWindow("./")));
});
