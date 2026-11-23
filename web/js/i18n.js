// Idioma de la interfaz. La app está escrita en español; en inglés se traduce lo que
// aparece en pantalla con el diccionario de lang-en.js (textos exactos y plantillas con
// {0}, {1}…). Así no hace falta tocar cada texto del código y lo nuevo que falte se ve
// en español en vez de romperse.
//
// Nunca se traduce lo que escriben las personas (mensajes, nombres, perfiles): solo la interfaz.
(function () {
  let pref = "auto";
  try { pref = localStorage.getItem("sc:lang") || "auto"; } catch { /* sin almacenamiento */ }
  const lang = pref === "es" || pref === "en" ? pref : /^es\b/i.test(navigator.language || "es") ? "es" : "en";
  self.SC_LANG = lang;
  self.SC_LANG_PREF = pref;
  self.SC_SET_LANG = (value) => {
    try { localStorage.setItem("sc:lang", value); } catch { /* */ }
    navigator.serviceWorker?.controller?.postMessage({ type: "lang", lang: value === "auto" ? lang : value });
    location.reload();
  };
  // El service worker (avisos con la app cerrada) también necesita saberlo
  navigator.serviceWorker?.ready?.then((r) => r.active?.postMessage({ type: "lang", lang })).catch(() => {});

  if (lang === "es" || !self.SC_EN) { self.t = (s) => s; return; }
  document.documentElement.lang = "en";

  // ----------------------------------------------------------- diccionario
  const exact = new Map();
  const patterns = [];
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  for (const [es, en] of Object.entries(self.SC_EN)) {
    if (/\{\d\}/.test(es)) {
      const order = [];
      const src = es.split(/(\{\d\})/).map((part) => {
        const m = /^\{(\d)\}$/.exec(part);
        if (!m) return escape(part);
        order.push(Number(m[1]));
        return "([\\s\\S]*?)";
      }).join("");
      patterns.push({ re: new RegExp(`^${src}$`), order, en, weight: es.replace(/\{\d\}/g, "").length });
    } else {
      exact.set(es, en);
    }
  }
  patterns.sort((a, b) => b.weight - a.weight); // primero las plantillas más concretas
  // Frases largas que el código a veces junta con otras en un mismo texto
  const long = [...exact.keys()].filter((k) => k.length >= 24).sort((a, b) => b.length - a.length);
  const longRe = long.length ? new RegExp(long.map(escape).join("|"), "g") : null;

  const cache = new Map();
  function tr(s, depth = 0) {
    if (typeof s !== "string" || !s.trim() || depth > 3) return s;
    const hit = cache.get(s);
    if (hit !== undefined) return hit;
    const lead = s.match(/^\s*/)[0], tail = s.match(/\s*$/)[0];
    const core = s.trim();
    let out = exact.get(core);
    if (out === undefined) {
      for (const p of patterns) {
        const m = p.re.exec(core);
        if (!m) continue;
        const vals = [];
        p.order.forEach((n, i) => { vals[n] = tr(m[i + 1], depth + 1); });
        out = p.en.replace(/\{(\d)\}/g, (_, n) => vals[n] ?? "");
        break;
      }
    }
    if (out === undefined && longRe && core.length >= 24) {
      const replaced = core.replace(longRe, (x) => exact.get(x));
      if (replaced !== core) out = replaced;
    }
    const res = out === undefined ? s : lead + out + tail;
    if (cache.size > 5000) cache.clear();
    cache.set(s, res);
    return res;
  }
  self.t = tr;

  // ----------------------------------------------------------- la pantalla
  // Lo que escribe la gente no se toca: mensajes, nombres y perfiles
  const USER = ".msg .body, .msg .author, .msg .quote, .msg .file-meta, #reply-text, .contact-name, #peer-name, .profile-view h3, "
    + ".bio, .link-card, .poll-q, .poll-label, .sticker-face, input, textarea, [contenteditable], .no-i18n";
  const ATTRS = ["placeholder", "title", "aria-label"];

  function textNode(n) {
    const p = n.parentElement;
    if (!p || p.closest(USER) || p.closest("script, style")) return;
    const v = tr(n.data);
    if (v !== n.data) n.data = v;
  }

  function element(el) {
    if (el.closest?.(".no-i18n")) return;
    for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (v) { const x = tr(v); if (x !== v) el.setAttribute(a, x); }
    }
  }

  function walk(root) {
    if (root.nodeType === 3) return textNode(root);
    if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
    if (root.nodeType === 1) element(root);
    const it = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    for (let n = it.nextNode(); n; n = it.nextNode()) {
      if (n.nodeType === 3) textNode(n); else element(n);
    }
  }

  const obs = new MutationObserver((list) => {
    for (const m of list) {
      if (m.type === "characterData") textNode(m.target);
      else if (m.type === "attributes") element(m.target);
      else for (const n of m.addedNodes) walk(n);
    }
  });
  const start = () => {
    walk(document.body);
    obs.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  };
  if (document.body) start(); else document.addEventListener("DOMContentLoaded", start, { once: true });

  // Título de la pestaña, ventanas del navegador y notificaciones
  new MutationObserver(() => { const v = tr(document.title); if (v !== document.title) document.title = v; })
    .observe(document.querySelector("title") || document.head, { childList: true, subtree: true, characterData: true });
  for (const fn of ["alert", "confirm", "prompt"]) {
    const orig = self[fn];
    if (typeof orig === "function") self[fn] = function (msg, ...rest) { return orig.call(self, tr(String(msg ?? "")), ...rest); };
  }
  const notifOpts = (o) => (o ? { ...o, body: tr(o.body), actions: o.actions?.map((a) => ({ ...a, title: tr(a.title) })) } : o);
  if (self.ServiceWorkerRegistration?.prototype?.showNotification) {
    const orig = ServiceWorkerRegistration.prototype.showNotification;
    ServiceWorkerRegistration.prototype.showNotification = function (title, opts) { return orig.call(this, tr(title), notifOpts(opts)); };
  }
  if (typeof self.Notification === "function") {
    const N = self.Notification;
    const Wrapped = function (title, opts) { return new N(tr(title), notifOpts(opts)); };
    Wrapped.prototype = N.prototype;
    Object.defineProperty(Wrapped, "permission", { get: () => N.permission });
    Wrapped.requestPermission = (...a) => N.requestPermission(...a);
    self.Notification = Wrapped;
  }
})();
