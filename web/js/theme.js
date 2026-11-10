// Temas de la interfaz. Script clásico (no módulo) para aplicarse antes de pintar.
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

(function () {
  let saved = "system";
  try { saved = JSON.parse(localStorage.getItem("sc:theme")) || "system"; } catch { /* sin almacenamiento */ }
  window.applyTheme(saved);
})();
