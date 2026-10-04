// Small DOM helpers. Report content comes from scanned repositories and is untrusted,
// so text always goes in as text nodes. Nothing here, or anywhere in the app, parses a
// string as HTML.

/**
 * h("button", { class: "x", onclick }, "label", child…)
 * Attributes set to null/undefined/false are skipped; `true` sets an empty attribute.
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

function setAttrs(el, attrs) {
  for (const [key, value] of Object.entries(attrs ?? {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value);
    } else if (key === "dataset") {
      Object.assign(el.dataset, value);
    } else {
      el.setAttribute(key, value === true ? "" : String(value));
    }
  }
}

function append(el, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(el, child);
    else el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

/** Replace an element's children. */
export function replace(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

// ------------------------------------------------------------------ icons
// 24×24 outline icons, as lists of SVG elements.

const ICONS = {
  search: [["circle", { cx: 11, cy: 11, r: 7 }], ["path", { d: "M20 20l-3.6-3.6" }]],
  folder: [["path", { d: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" }]],
  file: [["path", { d: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" }], ["path", { d: "M14 3v5h5M9 13h6M9 17h6" }]],
  user: [["circle", { cx: 12, cy: 8, r: 4 }], ["path", { d: "M4 21a8 8 0 0 1 16 0" }]],
  users: [["circle", { cx: 9, cy: 8, r: 3.5 }], ["path", { d: "M2.5 20a6.5 6.5 0 0 1 13 0M16 4.6a3.5 3.5 0 0 1 0 6.8M18 13.5a6.5 6.5 0 0 1 3.5 6.5" }]],
  org: [["path", { d: "M4 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16M16 9h2a2 2 0 0 1 2 2v10M3 21h18M8 7h4M8 11h4M8 15h4" }]],
  repo: [["path", { d: "M5 4.5A2.5 2.5 0 0 1 7.5 2H19v16H7.5A2.5 2.5 0 0 0 5 20.5z" }], ["path", { d: "M5 20.5A1.5 1.5 0 0 0 6.5 22H19v-4" }]],
  close: [["path", { d: "M18 6L6 18M6 6l12 12" }]],
  chevronDown: [["path", { d: "M6 9l6 6 6-6" }]],
  chevronUp: [["path", { d: "M18 15l-6-6-6 6" }]],
  sort: [["path", { d: "M8 9l4-4 4 4M16 15l-4 4-4-4" }]],
  external: [["path", { d: "M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7" }]],
  checkCircle: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M8 12.5l2.8 2.8L16.5 9.5" }]],
  xCircle: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M15 9l-6 6M9 9l6 6" }]],
  minusCircle: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M8 12h8" }]],
  helpCircle: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6v.3M12 17h.01" }]],
  alert: [["path", { d: "M10.3 4.2L2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z" }], ["path", { d: "M12 9.5v4M12 17h.01" }]],
  info: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 11v5M12 8h.01" }]],
  shield: [["path", { d: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" }]],
  shieldCheck: [["path", { d: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" }], ["path", { d: "M8.8 12.2l2.2 2.2 4.2-4.4" }]],
  key: [["circle", { cx: 8, cy: 15, r: 4 }], ["path", { d: "M10.8 12.2L20 3M16 7l3 3M14 9l2 2" }]],
  package: [["path", { d: "M21 8l-9-5-9 5 9 5zM3 8v8l9 5 9-5V8M12 13v8" }]],
  code: [["path", { d: "M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14" }]],
  workflow: [["circle", { cx: 6, cy: 6, r: 2.5 }], ["circle", { cx: 6, cy: 18, r: 2.5 }], ["circle", { cx: 18, cy: 12, r: 2.5 }], ["path", { d: "M6 8.5v7M8.5 6H12a3 3 0 0 1 3 3v.5M8.5 18H12a3 3 0 0 0 3-3v-.5" }]],
  bot: [["rect", { x: 4, y: 8, width: 16, height: 12, rx: 3 }], ["path", { d: "M12 8V4M9 13h.01M15 13h.01M9.5 16.5h5" }]],
  sliders: [["path", { d: "M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1" }], ["circle", { cx: 15, cy: 6, r: 2 }], ["circle", { cx: 9, cy: 12, r: 2 }], ["circle", { cx: 17, cy: 18, r: 2 }]],
  sparkle: [["path", { d: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z" }], ["path", { d: "M19 16l.7 1.8 1.8.7-1.8.7L19 21l-.7-1.8-1.8-.7 1.8-.7z" }]],
  clock: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 7v5l3 2" }]],
  history: [["path", { d: "M3.5 12a8.5 8.5 0 1 0 2.5-6L3.5 8.5" }], ["path", { d: "M3.5 3.5v5h5M12 7.5V12l3 2" }]],
  download: [["path", { d: "M12 4v11M7 10l5 5 5-5M5 20h14" }]],
  play: [["path", { d: "M7 4.5v15l12-7.5z" }]],
  stop: [["rect", { x: 6, y: 6, width: 12, height: 12, rx: 2 }]],
  refresh: [["path", { d: "M20 11a8 8 0 0 0-14.5-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.5 4.5L20 16M20 20v-4h-4" }]],
  filter: [["path", { d: "M4 5h16l-6 7.5V19l-4 2v-8.5z" }]],
  layers: [["path", { d: "M12 3l9 5-9 5-9-5zM3 13l9 5 9-5" }]],
  commit: [["circle", { cx: 12, cy: 12, r: 3.5 }], ["path", { d: "M3 12h5.5M15.5 12H21" }]],
  link: [["path", { d: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" }]],
};

const SVG = "http://www.w3.org/2000/svg";

function svgElement(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
  return el;
}

/** An inline SVG icon; decorative (hidden from screen readers). */
export function icon(name, extraClass = "") {
  const svg = svgElement("svg", {
    viewBox: "0 0 24 24",
    class: extraClass ? `icon ${extraClass}` : "icon",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": 1.8,
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
  });
  for (const [tag, attrs] of ICONS[name] ?? []) svg.append(svgElement(tag, attrs));
  return svg;
}

/** The app's logo: a shield with a magnifying glass (as in app/icon.svg). */
export function logo() {
  const svg = svgElement("svg", { viewBox: "0 0 1024 1024", class: "logo", "aria-hidden": "true" });
  const id = `logo-bg-${Math.random().toString(36).slice(2)}`;
  const defs = svgElement("defs", {});
  const gradient = svgElement("linearGradient", { id, x1: 0, y1: 0, x2: 0.7, y2: 1 });
  gradient.append(svgElement("stop", { offset: 0, "stop-color": "#3a74d6" }));
  gradient.append(svgElement("stop", { offset: 1, "stop-color": "#15306a" }));
  defs.append(gradient);
  svg.append(
    defs,
    svgElement("rect", { x: 40, y: 40, width: 944, height: 944, rx: 212, fill: `url(#${id})` }),
    svgElement("path", {
      d: "M512 168 L800 270 V500 C800 676 680 804 512 868 C344 804 224 676 224 500 V270 Z",
      fill: "#f4f7fc",
    }),
    svgElement("circle", { cx: 488, cy: 484, r: 124, fill: "none", stroke: "#1b3f86", "stroke-width": 64 }),
    svgElement("path", { d: "M580 576 L676 672", stroke: "#1b3f86", "stroke-width": 76, "stroke-linecap": "round" }),
  );
  return svg;
}

// ------------------------------------------------------------------ formatting

export function plural(n, word, words = `${word}s`) {
  return `${n.toLocaleString()} ${n === 1 ? word : words}`;
}

/** "2 Oct 2026, 17:44" in the user's locale. */
export function formatDate(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** "0.4 s", "12 s", "3 min 05 s", "1 h 02 min" */
export function formatDuration(ms) {
  const seconds = ms / 1000;
  if (seconds < 10) return `${seconds.toFixed(1)} s`;
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min ${String(Math.round(seconds % 60)).padStart(2, "0")} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}

// ------------------------------------------------------------------ toast

let toastTimer;

/** A short message at the bottom of the window. */
export function toast(message, { error = false } = {}) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.toggle("error", error);
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), error ? 7000 : 3500);
}
