// Iconos de línea (24x24, trazo 1.8) para la interfaz. Se crean con el DOM, nunca con innerHTML.

const PATHS = {
  user: ["M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z", "M4 20c.8-3.6 4-6 8-6s7.2 2.4 8 6"],
  users: ["M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z", "M2.5 20c.7-3.3 3.2-5.5 6.5-5.5s5.8 2.2 6.5 5.5", "M16 4.3a3.5 3.5 0 0 1 0 6.4", "M17.5 14.6c2.1.6 3.6 2.6 4 5.4"],
  sliders: ["M4 6h10", "M18 6h2", "M4 12h4", "M12 12h8", "M4 18h12", "M20 18h0", "M16 4v4", "M10 10v4", "M18 16v4"],
  download: ["M12 4v11", "M7 10l5 5 5-5", "M5 20h14"],
  upload: ["M12 20V9", "M7 14l5-5 5 5", "M5 4h14"],
  install: ["M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z", "M12 8v6", "M9.5 11.5 12 14l2.5-2.5", "M11 18h2"],
  shield: ["M12 3 5 6v5.5c0 4.4 3 7.8 7 9.5 4-1.7 7-5.1 7-9.5V6l-7-3Z", "M9 12l2 2 4-4"],
  logout: ["M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3", "M10 16l-4-4 4-4", "M6 12h10"],
  reply: ["M10 8 5 12l5 4", "M5 12h9a5 5 0 0 1 5 5v1"],
  copy: ["M9 9h10v11H9z", "M15 9V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h4"],
  edit: ["M14.5 5.5l4 4", "M5 19l1-4L16 5a2.1 2.1 0 0 1 3 3L9 18l-4 1Z"],
  trash: ["M4 7h16", "M9 7V4h6v3", "M6 7l1 13h10l1-13", "M10 11v6", "M14 11v6"],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 7v5l3 2"],
  check: ["M5 12.5 10 17 19 7.5"],
  checks: ["M2.5 12.5 7 17 16 7.5", "M11.5 15.5 13 17 22 7.5"],
  alert: ["M12 4 2.5 20h19L12 4Z", "M12 10v4.5", "M12 17.5v.01"],
  lock: ["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"],
  key: ["M14.5 9.5a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0Z", "M13.2 12.8 20 19.6", "M17 16.6l2-2"],
  mic: ["M12 3a3 3 0 0 1 3 3v6a3 3 0 0 1-6 0V6a3 3 0 0 1 3-3Z", "M5.5 11a6.5 6.5 0 0 0 13 0", "M12 17.5V21"],
  phone: ["M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z", "M11 18h2"],
  laptop: ["M5 5h14v10H5z", "M3 19h18"],
  mail: ["M4 6h16v12H4z", "M4 7l8 6 8-6"],
  offline: ["M3 3l18 18", "M8.5 16.5a5 5 0 0 1 7 0", "M5 12.6a10 10 0 0 1 4.2-2.4", "M14.8 10.2A10 10 0 0 1 19 12.6", "M12 20h.01"],
  chevron: ["M9 6l6 6-6 6"],
  close: ["M6 6l12 12", "M18 6 6 18"],
  ban: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M5.6 5.6l12.8 12.8"],
  image: ["M4 5h16v14H4z", "M4 16l5-5 4 4 3-3 4 4", "M15 9h.01"],
  video: ["M4 6h11v12H4z", "M15 10l5-3v10l-5-3"],
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M12 11v5", "M12 8h.01"],
  clock_small: ["M12 20a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z", "M12 8v4.5l2.5 1.5"],
};

/** Devuelve un <svg> con el icono pedido. */
export function icon(name, cls = "") {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", `ico${cls ? ` ${cls}` : ""}`);
  for (const d of PATHS[name] || PATHS.info) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}
