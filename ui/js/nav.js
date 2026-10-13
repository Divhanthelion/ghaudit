// The Back button on phones. Android's WebView turns the system Back button and gesture
// into a step back in the page's history, and closes the app when there is none. So
// every view below the start page or the report's Overview (the "page") and every
// overlay above it (sheets, dialogs, a finding's details) gets a history entry, and Back
// closes the top one. On the desktop the same bookkeeping runs without history entries.

import { h, icon } from "./dom.js";

/** The non-root view: { back() }, or null on the start page and a report's Overview. */
let page = null;
/** Overlays above the page, bottom to top: { back() }. */
const layers = [];
/** Whether Back goes through history entries (true in the mobile app). */
let enabled = false;
const listeners = new Set();

// History calls run one after another: a step back is asynchronous, and an entry pushed
// before it lands would be the one it removes.
let queue = Promise.resolve();
/** Resolves our own step back when its popstate arrives. */
let ownStep = null;

function run(task) {
  queue = queue.then(task).catch(() => {});
}

function pushEntry() {
  if (enabled) run(() => history.pushState({ ghaudit: true }, ""));
}

function stepBack(count) {
  if (!enabled || count < 1) return;
  run(
    () =>
      new Promise((resolve) => {
        const done = () => {
          clearTimeout(timer);
          ownStep = null;
          resolve();
        };
        // A step back that has nothing to undo never fires popstate.
        const timer = setTimeout(done, 400);
        ownStep = done;
        history.go(-count);
      }),
  );
}

function changed() {
  for (const listener of listeners) listener();
}

window.addEventListener("popstate", () => {
  if (ownStep) {
    ownStep();
    return;
  }
  // Back was pressed: its entry is already gone, so drop ours before acting on it.
  const top = layers.pop();
  if (top) {
    top.back();
  } else if (page) {
    const p = page;
    page = null;
    changed();
    p.back();
  }
});

/**
 * Use history entries (in the mobile app). Entries for anything already open are
 * added now.
 */
export function enableHistory(on) {
  if (on === enabled) return;
  enabled = on;
  if (on) {
    history.replaceState({ ghaudit: true }, "");
    for (let i = 0; i < (page ? 1 : 0) + layers.length; i++) pushEntry();
  }
}

/**
 * The view on screen. `back` is what Back does there; null for the start page and a
 * report's Overview, where Back leaves the app. Open overlays are closed first.
 */
export function setPage(back) {
  const closed = layers.splice(0);
  for (const layer of closed.reverse()) layer.back();
  if (back) {
    stepBack(closed.length);
    if (page) page.back = back;
    else {
      page = { back };
      pushEntry();
    }
  } else {
    stepBack(closed.length + (page ? 1 : 0));
    page = null;
  }
  changed();
}

/** Whether Back goes through history entries. */
export function historyEnabled() {
  return enabled;
}

/** Whether Back stays in the app (a page or an overlay is open). */
export function canGoBack() {
  return Boolean(page) || layers.length > 0;
}

/** Go back, as the system Back button does: the in-app back arrow. */
export function back() {
  if (enabled) {
    history.back();
    return;
  }
  const top = layers.pop();
  if (top) top.back();
  else if (page) {
    const p = page;
    page = null;
    changed();
    p.back();
  }
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
  pushEntry();
  return layer;
}

/** The page closed an overlay itself: drop its history entry. */
export function closeLayer(layer) {
  const i = layers.indexOf(layer);
  if (i === -1) return;
  layers.splice(i, 1);
  stepBack(1);
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
