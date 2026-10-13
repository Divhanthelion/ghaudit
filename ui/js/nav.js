// The Back button on phones. The Android app's activity asks the page first, through
// window.ghauditBack(): every view below the start page or the report's Overview (the
// "page") and every overlay above it (sheets, dialogs, a finding's details) is recorded
// here, and Back closes the top one. With nothing open, Back leaves the app as usual.
// History entries are not used for this: Chromium lets Back skip entries a page pushed
// without a tap, and would close the app with a sheet still open. On the desktop the
// same bookkeeping serves the in-app back arrow.

import { h, icon } from "./dom.js";

/** The non-root view: { back() }, or null on the start page and a report's Overview. */
let page = null;
/** Overlays above the page, bottom to top: { back() }. */
const layers = [];
/** Whether the system Back button comes to the page (the mobile app). */
let systemBack = false;
const listeners = new Set();

function changed() {
  for (const listener of listeners) listener();
}

/** Close the top overlay, or else the page. */
function closeTop() {
  const top = layers.pop();
  if (top) {
    top.back();
  } else if (page) {
    const p = page;
    page = null;
    changed();
    p.back();
  }
}

/** For the Android activity: close what is on top. False when nothing is open. */
window.ghauditBack = () => {
  if (!canGoBack()) return false;
  closeTop();
  return true;
};

/** Say whether the system Back button comes to the page (the mobile app). */
export function useSystemBack(on) {
  systemBack = Boolean(on);
}

/**
 * The view on screen. `back` is what Back does there; null for the start page and a
 * report's Overview, where Back leaves the app. Open overlays are closed first.
 */
export function setPage(back) {
  const closed = layers.splice(0);
  for (const layer of closed.reverse()) layer.back();
  if (back) {
    if (page) page.back = back;
    else page = { back };
  } else {
    page = null;
  }
  changed();
}

/** Whether the system Back button comes to the page. */
export function systemBackEnabled() {
  return systemBack;
}

/** Whether Back stays in the app (a page or an overlay is open). */
export function canGoBack() {
  return Boolean(page) || layers.length > 0;
}

/** Go back, as the system Back button does: the in-app back arrow. */
export function back() {
  closeTop();
}

/** Call `listener` when the page changes (to show or hide the back arrow). */
export function onChange(listener) {
  listeners.add(listener);
}

/**
 * Open an overlay. `back` closes it when Back is pressed. Returns a handle for
 * closeLayer() when the page closes it itself (a Close button, Escape).
 */
export function openLayer(back) {
  const layer = { back };
  layers.push(layer);
  return layer;
}

/** The page closed an overlay itself. */
export function closeLayer(layer) {
  const i = layers.indexOf(layer);
  if (i !== -1) layers.splice(i, 1);
}

/**
 * Show a modal <dialog> as an overlay: Back, Escape and the returned function all close
 * and remove it. `onClose` runs once, however it was closed.
 */
export function showDialog(dialog, { onClose } = {}) {
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    if (dialog.open) dialog.close();
    dialog.remove();
    onClose?.();
  };
  const layer = openLayer(finish);
  dialog.addEventListener("close", () => {
    // Escape, or dialog.close() from elsewhere.
    if (done) return;
    closeLayer(layer);
    finish();
  });
  document.body.append(dialog);
  dialog.showModal();
  return () => {
    closeLayer(layer);
    finish();
  };
}

let sheets = 0;

/**
 * A sheet: a dialog that rises from the bottom of the screen, or fills it (`full`, with
 * a back arrow). Returns the function that closes it.
 */
export function openSheet({ title, subtitle = null, content, full = false, className = "", onClose }) {
  const id = `sheet-title-${++sheets}`;
  const closeButton = h(
    "button",
    { type: "button", class: "icon-btn", "aria-label": full ? "Back" : "Close" },
    icon(full ? "arrowLeft" : "close"),
  );
  const dialog = h(
    "dialog",
    { class: ["sheet", full ? "full" : "", className].filter(Boolean).join(" "), "aria-labelledby": id },
    full ? null : h("span", { class: "grabber", "aria-hidden": "true" }),
    h(
      "div",
      { class: "sheet-head" },
      full ? closeButton : null,
      h("div", { class: "sheet-title" }, h("h2", { id }, title), subtitle ? h("p", {}, subtitle) : null),
      full ? null : closeButton,
    ),
    h("div", { class: "sheet-body" }, content),
  );
  const close = showDialog(dialog, { onClose });
  closeButton.addEventListener("click", close);
  if (!full) {
    // A tap on the dimmed backdrop lands on the dialog itself.
    dialog.addEventListener("click", (e) => {
      if (e.target === dialog) close();
    });
  }
  return close;
}
