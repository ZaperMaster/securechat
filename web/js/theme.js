// Temas y preferencias de la interfaz. Script clásico (no módulo) para aplicarse
// antes de pintar y evitar parpadeos.
window.SC_THEMES = [
  { id: "system", name: "Sistema", desc: "Claro u oscuro según tu dispositivo", swatch: ["#f6f7fb", "#4f46e5", "#0f1220"] },
  { id: "light", name: "Claro", desc: "Limpio y luminoso", swatch: ["#f6f7fb", "#4f46e5", "#ffffff"] },
  { id: "dark", name: "Oscuro", desc: "Suave para la vista", swatch: ["#0f1220", "#818cf8", "#1a1e30"] },
  { id: "midnight", name: "Medianoche", desc: "Azul profundo y violeta", swatch: ["#070b1d", "#a78bfa", "#131a3a"] },
  { id: "forest", name: "Bosque", desc: "Verdes tranquilos", swatch: ["#eef4ee", "#2f7d4f", "#ffffff"] },
  { id: "sunset", name: "Atardecer", desc: "Cálido, coral y melocotón", swatch: ["#fff4ec", "#e8573f", "#ffffff"] },
  { id: "sakura", name: "Sakura", desc: "Rosa pastel", swatch: ["#fdf2f6", "#d63f7a", "#ffffff"] },
  { id: "terminal", name: "Terminal", desc: "Verde fósforo sobre negro", swatch: ["#030803", "#33ff66", "#0a140b"] },
  { id: "contrast", name: "Alto contraste", desc: "Máxima legibilidad", swatch: ["#000000", "#ffd400", "#000000"] },
];

window.applyTheme = function (id) {
  const t = window.SC_THEMES.find((x) => x.id === id) || window.SC_THEMES[0];
  const root = document.documentElement;
  // Sin transiciones durante el cambio: el tema nuevo se aplica de golpe y entero
  root.classList.add("theme-switching");
  root.dataset.theme = t.id;
  void root.offsetWidth; // fuerza el recálculo de estilos antes de reactivarlas
  setTimeout(() => root.classList.remove("theme-switching"), 50);
  // Color de la barra del sistema en móvil / ventana de la app instalada
  const meta = document.querySelector('meta[name="theme-color"]');
  const dark = t.id === "system" ? matchMedia("(prefers-color-scheme: dark)").matches : null;
  if (meta) meta.content = t.id === "system" ? (dark ? "#0f1220" : "#f6f7fb") : t.swatch[0];
  return t.id;
};

// ---------------------------------------------------------------- preferencias

const DEFAULT_PREFS = {
  accent: null,        // null = el color del tema
  wall: "dots",        // fondo de los chats
  wallImage: null,     // data: URL de la foto de fondo (redimensionada)
  font: 15,            // px
  radius: null,        // px de las burbujas (null = el del tema)
  readReceipts: true,  // doble check azul
  notifications: true,
  enterSends: true,
};

function readPrefs() {
  try { return { ...DEFAULT_PREFS, ...JSON.parse(localStorage.getItem("sc:prefs")) }; }
  catch { return { ...DEFAULT_PREFS }; }
}

/** Texto blanco o negro según lo claro que sea el color de fondo. */
function inkFor(hex) {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.45 ? "#111111" : "#ffffff";
}

window.applyPrefs = function (p) {
  const s = document.documentElement.style; // CSSOM: permitido por la CSP
  if (p.accent && /^#[0-9a-f]{6}$/i.test(p.accent)) {
    const ink = inkFor(p.accent);
    s.setProperty("--accent", p.accent);
    s.setProperty("--accent-2", `color-mix(in srgb, ${p.accent} 75%, ${ink === "#ffffff" ? "#000" : "#fff"})`);
    s.setProperty("--accent-ink", ink);
    s.setProperty("--mine-text", ink);
    s.setProperty("--accent-soft", `color-mix(in srgb, ${p.accent} 18%, var(--panel))`);
  } else {
    for (const v of ["--accent", "--accent-2", "--accent-ink", "--mine-text", "--accent-soft"]) s.removeProperty(v);
  }
  s.setProperty("--font-size", `${p.font}px`);
  if (p.radius) s.setProperty("--radius", `${p.radius}px`); else s.removeProperty("--radius");
  document.documentElement.dataset.wall = p.wall;
  if (p.wall === "image" && p.wallImage && p.wallImage.startsWith("data:image/")) {
    s.setProperty("--wall-image", `url("${p.wallImage}")`);
  } else {
    s.removeProperty("--wall-image");
  }
};

window.SC_PREFS = readPrefs;
window.SC_SET_PREFS = function (p) {
  try { localStorage.setItem("sc:prefs", JSON.stringify(p)); }
  catch { if (p.wallImage) { p = { ...p, wallImage: null, wall: "dots" }; } }
  window.applyPrefs(p);
};

(function () {
  let saved = "system";
  try { saved = JSON.parse(localStorage.getItem("sc:theme")) || "system"; } catch { /* sin almacenamiento */ }
  window.applyTheme(saved);
  window.applyPrefs(readPrefs());
})();
