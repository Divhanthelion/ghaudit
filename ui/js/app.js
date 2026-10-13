// ghaudit desktop: the start page, scanning, and the report views. Below 700 px wide
// (a phone) the report tabs move to a bar at the bottom, the report's actions to a
// "More" sheet, and the system Back button works through nav.js.

import { h, replace, icon, logo, toast, formatDate, plural, phone } from "./dom.js";
import * as backend from "./backend.js";
import * as nav from "./nav.js";
import { CATEGORIES } from "./explain.js";
import { prepare } from "./report.js";
import { renderOverview } from "./overview.js";
import { createFindingsView } from "./findings.js";
import { renderCoverage } from "./coverage.js";
import { createSettingsView } from "./settings.js";
import { renderSetup, loadOptions, saveOptions, scanRequest, scanLabel, TARGETS, capabilities, effectiveOptions } from "./scan.js";
import { createProgressView } from "./progress.js";

const app = document.getElementById("app");
const main = document.getElementById("main");
const tabsEl = document.getElementById("tabs");
const tabbar = document.getElementById("tabbar");
const reportbar = document.getElementById("reportbar");
const actions = document.getElementById("topbar-actions");
const navBack = document.getElementById("nav-back");
const pageTitle = document.getElementById("page-title");
const moreButton = document.getElementById("more");

const state = {
  catalog: null,
  /** What scans can use (GitHub access, osv-scanner, git); null while checking. */
  env: null,
  /** The folder chosen for folder scans (the backend holds the real one). */
  folder: null,
  /** "home", "setup", "scanning", "failed" (a scan that couldn't finish) or "report". */
  view: "home",
  /** The report on screen, from report.prepare(): `base`, or with "only what's new",
   * the comparison's. */
  report: null,
  /** The report as opened or scanned. */
  base: null,
  /** An earlier report to compare with: { name, scanned, prepared }. */
  compare: null,
  /** With a comparison, show only what's new. */
  onlyNew: true,
  /** Where it came from: { kind: "file", name } or { kind: "scan" }. */
  source: null,
  /** The file the report was last exported to as JSON. */
  saved: null,
  tab: "overview",
  findings: null,
  /** Built on the first visit to the Settings tab: a large grid costs time. */
  settings: null,
  /** Where the setup page was opened from, for Back: "home" or "report". */
  setupFrom: "home",
  /** The progress page of the running scan. */
  progress: null,
};

const TABS = [
  { id: "overview", label: "Overview", icon: "shield" },
  { id: "findings", label: "Findings", icon: "list", count: (r) => r.findings.length },
  {
    id: "settings",
    label: "Settings",
    icon: "sliders",
    count: (r) => (r.settings.length ? r.settings.filter((s) => s.status === "fail").length : undefined),
  },
  { id: "coverage", label: "Coverage", icon: "checkCircle" },
];

/** The title in a phone's top bar. */
const VIEW_TITLES = { home: "", setup: "New scan", scanning: "", failed: "" };

function showError(message) {
  toast(message, { error: true });
}

// ------------------------------------------------------------------ top bar

function renderTopbar() {
  const scanning = state.view === "scanning";
  replace(
    actions,
    h(
      "button",
      { type: "button", class: "btn", onclick: showSetup, disabled: scanning, title: "Set up a new scan (Ctrl+N)" },
      icon("search"),
      h("span", { class: "btn-label" }, "New scan"),
    ),
    h(
      "button",
      { type: "button", class: "btn", onclick: openReport, disabled: scanning, title: "Open a saved report (Ctrl+O)", "aria-label": "Open a saved report" },
      icon("file"),
      h("span", { class: "btn-label" }, "Open report…"),
    ),
  );
  renderTabs();
  renderReportbar();
  renderPhoneBar();
}

/** The phone's top bar: back arrow, the view's title, and More on a report. */
function renderPhoneBar() {
  const report = state.view === "report" && state.report;
  app.dataset.view = state.view;
  pageTitle.textContent = report ? (TABS.find((t) => t.id === state.tab)?.label ?? "") : (VIEW_TITLES[state.view] ?? "");
  moreButton.hidden = !report;
  syncBack();
}

function syncBack() {
  navBack.hidden = state.view === "scanning" || !nav.canGoBack();
}

function renderTabs() {
  const shown = state.view === "report" && state.report;
  tabsEl.hidden = !shown;
  tabbar.hidden = !shown;
  if (!shown) return;
  replace(
    tabbar,
    TABS.map((t) => {
      const count = t.count?.(state.report);
      return h(
        "button",
        { type: "button", class: "tabbar-tab", "aria-current": state.tab === t.id ? "page" : null, onclick: () => showTab(t.id) },
        h("span", { class: "tabbar-icon" }, icon(t.icon), count ? h("span", { class: "tabbar-count" }, count > 999 ? "999+" : count.toLocaleString()) : null),
        h("span", { class: "tabbar-label" }, t.label),
      );
    }),
  );
  replace(
    tabsEl,
    TABS.map((t) => {
      const selected = state.tab === t.id;
      const count = t.count?.(state.report);
      return h(
        "button",
        {
          type: "button",
          class: "tab",
          role: "tab",
          id: `tab-${t.id}`,
          "aria-selected": String(selected),
          "aria-controls": "main",
          tabindex: selected ? 0 : -1,
          onclick: () => showTab(t.id),
          onkeydown: tabKeys,
        },
        h("span", { class: "label-long" }, t.label),
        count !== undefined ? h("span", { class: "count" }, count.toLocaleString()) : null,
      );
    }),
  );
}

function tabKeys(e) {
  const i = TABS.findIndex((t) => t.id === state.tab);
  const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
  if (next === undefined) return;
  e.preventDefault();
  const tab = TABS[(next + TABS.length) % TABS.length];
  showTab(tab.id);
  document.getElementById(`tab-${tab.id}`)?.focus();
}

/** "user:octocat" → "Repositories of octocat", and so on. */
function targetLabel(target) {
  if (target.startsWith("user:")) return `Repositories of ${target.slice(5)}`;
  if (target.startsWith("org:")) return `Organization ${target.slice(4)}`;
  if (target.startsWith("search:")) return `Search: ${target.slice(7)}`;
  if (/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+$/.test(target)) return target;
  return `Folder ${target}`;
}

function renderReportbar() {
  const shown = state.view === "report" && state.report;
  reportbar.hidden = !shown;
  if (!shown) return;
  const r = state.base.raw;
  const unsaved = state.source?.kind === "scan" && !state.saved;
  const parts = [
    h("span", { class: "target" }, targetLabel(r.target ?? "")),
    h("span", { class: "when" }, `Scanned ${formatDate(r.started_at)}`),
    state.saved
      ? h("span", { class: "source" }, `Saved as ${state.saved}`)
      : state.source?.kind === "file"
        ? h("span", { class: "source" }, `Opened from ${state.source.name}`)
        : h("span", { class: "unsaved" }, "Not saved yet"),
  ];
  replace(
    reportbar,
    parts.flatMap((p, i) => (i ? [h("span", { class: "sep", "aria-hidden": "true" }, "·"), p] : [p])),
    // Phones: the comparison's switch is in the More sheet; say here what is shown.
    state.compare && state.onlyNew ? h("span", { class: "compare-note phone-only" }, `Only what's new since ${state.compare.name}`) : null,
    h("div", { class: "reportbar-actions" }, compareControls(), h(
      "button",
      { type: "button", class: unsaved ? "btn primary" : "btn", onclick: exportDialog, title: "Save or export the report (Ctrl+S)" },
      icon("download"),
      unsaved ? "Save report…" : "Export…",
    )),
  );
}

function compareControls() {
  if (!state.compare) {
    return h(
      "button",
      { type: "button", class: "btn quiet", onclick: compareWith, title: "Show only what's new since an earlier report" },
      icon("history"),
      "Compare with earlier…",
    );
  }
  const toggle = h("input", { type: "checkbox", checked: state.onlyNew });
  toggle.addEventListener("change", () => {
    state.onlyNew = toggle.checked;
    showReport();
  });
  const baselined = state.compare.prepared.raw.stats?.findings_baselined ?? 0;
  return h(
    "div",
    { class: "compare" },
    h(
      "label",
      { class: "check", title: `${plural(baselined, "finding")} from ${state.compare.name} hidden` },
      toggle,
      `Only what's new since ${state.compare.name} (${formatDate(state.compare.scanned)})`,
    ),
    h(
      "button",
      { type: "button", class: "btn quiet icon-only", onclick: clearCompare, "aria-label": "Stop comparing", title: "Stop comparing" },
      icon("close"),
    ),
  );
}

// ------------------------------------------------------------------ views

function setView(view) {
  state.view = view;
  main.className = "";
  main.removeAttribute("role");
  main.removeAttribute("aria-labelledby");
  renderTopbar();
}

function showHome() {
  setView("home");
  nav.setPage(null);
  const env = state.env;
  const caps = capabilities(env);
  const login = env?.github?.login;
  const mineText = !env
    ? "Checking GitHub access…"
    : login
      ? `Everything ${login} owns on GitHub, private repositories included.`
      : "Needs GitHub access: set it up on the next page.";
  replace(
    main,
    h(
      "div",
      { class: "home" },
      h(
        "div",
        { class: "hero" },
        logo(),
        h(
          "div",
          {},
          h("h1", {}, "Check your GitHub repositories for security problems"),
          h(
            "p",
            {},
            caps.dependencies
              ? "ghaudit finds leaked passwords and keys, vulnerable dependencies, risky code and workflows, and weak repository settings, and explains in plain language what to fix first."
              : "ghaudit finds leaked passwords and keys, risky code and workflows, and weak repository settings, and explains in plain language what to fix first.",
          ),
        ),
      ),
      h(
        "div",
        { class: "choices" },
        h(
          "button",
          { type: "button", class: "choice primary", onclick: scanMine, disabled: !env },
          h("span", { class: "icon-wrap" }, icon("user")),
          h("h2", {}, "Scan my repositories"),
          h("p", {}, mineText),
        ),
        h(
          "button",
          { type: "button", class: "choice", onclick: showSetup },
          h("span", { class: "icon-wrap" }, icon("search")),
          h("h2", {}, "Scan something else"),
          h("p", {}, caps.folders ? "One repository, a folder on this computer, an organization or a search." : "One repository, an organization, someone's repositories or a search."),
        ),
        h(
          "button",
          { type: "button", class: "choice", onclick: openReport },
          h("span", { class: "icon-wrap" }, icon("file")),
          h("h2", {}, "Open a saved report"),
          h("p", {}, "Browse a report saved earlier by this app, or made with ghaudit -f json."),
        ),
      ),
      h(
        "div",
        { class: "card explainer" },
        h("h3", {}, "What ghaudit checks"),
        CATEGORIES.filter((c) => c.id !== "ai").map((c) =>
          h(
            "div",
            { class: "item" },
            icon(c.icon),
            h(
              "div",
              {},
              h("b", {}, c.label),
              h("span", {}, c.id === "dependency" && !caps.dependencies ? `${c.text} Checked only by the computer version.` : c.text),
            ),
          ),
        ),
      ),
      state.catalog
        ? h(
            "p",
            { class: "home-footer" },
            `ghaudit ${env?.mobile ? "app" : "desktop"} ${state.catalog.app_version} · scanner ${state.catalog.scanner_version} · reads from GitHub, never changes anything`,
          )
        : null,
    ),
  );
}

function showSetup() {
  if (state.view === "home" || state.view === "report") state.setupFrom = state.view;
  setView("setup");
  nav.setPage(setupBack);
  replace(
    main,
    renderSetup({
      env: state.env,
      folder: state.folder,
      setFolder: (path) => {
        state.folder = path;
      },
      refreshEnvironment: async () => {
        state.env = null;
        showSetup();
        await refreshEnvironment();
        if (state.view === "setup") showSetup();
      },
      start: runScan,
    }),
  );
  main.scrollTop = 0;
}

/** Back from the setup page: to the report it was opened from, or the start page. */
function setupBack() {
  if (state.setupFrom === "report" && state.report) {
    state.view = "report";
    renderTopbar();
    showTab(state.tab);
  } else {
    showHome();
  }
}

/** "Scan my repositories" from the start page, with the saved options. */
function scanMine() {
  const saved = { ...loadOptions(), kind: "mine" };
  saveOptions(saved);
  const options = effectiveOptions(saved, state.env);
  if (!state.env?.github?.login) {
    showSetup();
    return;
  }
  if (options.checks.sca && !state.env.osv_scanner) {
    // The setup page explains what's missing and offers to scan without it.
    showSetup();
    return;
  }
  runScan(scanRequest(options), scanLabel(options, state.env, null), options);
}

/** Owner of the repositories a scan lists, to shorten their names on a phone. */
function scanOwner(options) {
  if (options.kind === "mine") return state.env?.github?.login ?? null;
  if (options.kind === "user") return options.user.trim();
  if (options.kind === "org") return options.org.trim();
  return null;
}

async function runScan(request, label, options) {
  setView("scanning");
  nav.setPage(scanningBack);
  const caps = capabilities(state.env);
  const multi = Boolean(TARGETS.find((t) => t.kind === options.kind)?.multi);
  const view = createProgressView({
    label,
    options,
    multi,
    onCancel: () => backend.cancelScan().catch((e) => showError(e.message)),
    onBack: showSetup,
    unavailable: new Set([caps.dependencies ? null : "sca", caps.history ? null : "history"].filter(Boolean)),
    owner: scanOwner(options),
    keepOpen: state.env?.mobile
      ? `Keep ghaudit open until the scan finishes. If you switch to another app, ${state.env.platform === "android" ? "Android" : "the phone"} may stop it.`
      : null,
  });
  state.progress = view;
  replace(main, view.element);
  try {
    const result = await backend.startScan(request, (event) => view.handle(event));
    view.stop();
    if (result.outcome === "cancelled") {
      toast("Scan cancelled.");
      showSetup();
      return;
    }
    loadReport(result.report, { kind: "scan" });
  } catch (e) {
    view.stop();
    view.fail(e.message);
    setView("failed");
    nav.setPage(showSetup);
    replace(main, view.element);
  } finally {
    state.progress = null;
  }
}

/** Back during a scan asks first: leaving the page would lose the scan. */
function scanningBack() {
  nav.setPage(scanningBack);
  const dialog = h(
    "dialog",
    { class: "confirm", "aria-labelledby": "stop-title" },
    h("h2", { id: "stop-title" }, "Stop the scan?"),
    h("p", {}, "What ghaudit has found so far will be discarded."),
    h(
      "div",
      { class: "confirm-actions" },
      h("button", { type: "button", class: "btn", onclick: () => close() }, "Keep scanning"),
      h(
        "button",
        {
          type: "button",
          class: "btn primary",
          onclick: () => {
            close();
            state.progress?.cancel();
          },
        },
        "Stop the scan",
      ),
    ),
  );
  const close = nav.showDialog(dialog);
}

function showTab(id) {
  state.tab = id;
  state.view = "report";
  nav.setPage(id === "overview" ? null : () => showTab("overview"));
  renderTabs();
  renderPhoneBar();
  const r = state.report;
  main.setAttribute("role", "tabpanel");
  main.setAttribute("aria-labelledby", `tab-${id}`);
  main.className = id === "findings" ? "fill" : "";
  const go = {
    findings: (filter) => {
      state.findings.applyFilter(filter);
      showTab("findings");
    },
    coverage: () => showTab("coverage"),
  };
  if (id === "overview") replace(main, renderOverview(r, go));
  else if (id === "findings") replace(main, state.findings.element);
  else if (id === "settings") replace(main, settingsView().element);
  else if (id === "coverage") replace(main, renderCoverage(r));
  main.scrollTop = 0;
}

// ------------------------------------------------------------------ phone: More sheet

/** The report bar's actions, and New scan and Open, in a sheet. */
function openMore() {
  if (!state.report) return;
  let close = () => {};
  const unsaved = state.source?.kind === "scan" && !state.saved;
  const item = (name, label, text, action, cls = "") =>
    h(
      "button",
      {
        type: "button",
        class: `sheet-item ${cls}`.trim(),
        onclick: () => {
          close();
          action();
        },
      },
      icon(name),
      h("span", { class: "sheet-item-text" }, h("b", {}, label), text ? h("span", {}, text) : null),
    );
  const compare = [];
  if (!state.compare) {
    compare.push(item("history", "Compare with earlier…", "Show only what's new since an earlier report.", compareWith));
  } else {
    const baselined = state.compare.prepared.raw.stats?.findings_baselined ?? 0;
    const toggle = h("input", { type: "checkbox", checked: state.onlyNew });
    toggle.addEventListener("change", () => {
      close();
      state.onlyNew = toggle.checked;
      showReport();
    });
    compare.push(
      h(
        "label",
        { class: "sheet-item sheet-switch" },
        icon("layers"),
        h(
          "span",
          { class: "sheet-item-text" },
          h("b", {}, `Only what's new since ${state.compare.name}`),
          h("span", {}, `${formatDate(state.compare.scanned)}. ${plural(baselined, "finding")} from it ${baselined === 1 ? "is" : "are"} hidden.`),
        ),
        toggle,
      ),
      item("close", "Stop comparing", null, clearCompare),
    );
  }
  close = nav.openSheet({
    title: targetLabel(state.base.raw.target ?? ""),
    subtitle: [
      `Scanned ${formatDate(state.base.raw.started_at)}`,
      state.saved ? `Saved as ${state.saved}` : state.source?.kind === "file" ? `Opened from ${state.source.name}` : null,
    ]
      .filter(Boolean)
      .join(" · "),
    className: "more-sheet",
    content: [
      item("download", unsaved ? "Save report…" : "Export…", "As a ghaudit report, SARIF or text.", exportDialog, unsaved ? "accent" : ""),
      compare,
      h("hr", {}),
      item("search", "New scan", null, showSetup),
      item("file", "Open a saved report…", null, openReport),
    ],
  });
}

function loadReport(report, source) {
  state.base = prepare(report);
  state.compare = null;
  state.onlyNew = true;
  state.saved = null;
  state.source = source;
  state.tab = "overview";
  showReport();
}

/** Show `base`, or the comparison's report when only what's new is wanted. */
function showReport() {
  state.report = state.compare && state.onlyNew ? state.compare.prepared : state.base;
  state.findings = createFindingsView(state.report, { onError: showError });
  state.settings = null;
  state.view = "report";
  renderTopbar();
  showTab(state.tab);
}

function settingsView() {
  state.settings ??= createSettingsView(state.report, {
    rules: new Map((state.catalog?.rules ?? []).map((r) => [r.id, r])),
    onError: showError,
    showFindings: (filter) => {
      state.findings.applyFilter(filter);
      showTab("findings");
    },
  });
  return state.settings;
}

async function compareWith() {
  try {
    const compared = await backend.compareWith();
    if (!compared) return;
    state.compare = { name: compared.name, scanned: compared.scanned, prepared: prepare(compared.report) };
    state.onlyNew = true;
    showReport();
    const hidden = compared.report.stats?.findings_baselined ?? 0;
    toast(`${plural(hidden, "finding")} from ${compared.name} hidden; ${plural(compared.report.findings.length, "new one")} left.`);
  } catch (e) {
    showError(e.message);
  }
}

async function clearCompare() {
  try {
    await backend.clearComparison();
  } catch (e) {
    showError(e.message);
  }
  state.compare = null;
  showReport();
}

const FORMATS = [
  {
    id: "json",
    label: "ghaudit report (JSON)",
    text: "Everything in the report. Open it here again later, or compare a new scan with it.",
  },
  {
    id: "sarif",
    label: "SARIF",
    text: "For GitHub code scanning and other security tools.",
  },
  {
    id: "text",
    label: "Text",
    text: "A readable summary to share or print.",
  },
];

function exportDialog() {
  if (!state.report || document.querySelector("dialog[open]")) return;
  let format = "json";
  const comparing = Boolean(state.compare);
  const onlyNew = h("input", { type: "checkbox", checked: comparing && state.onlyNew });
  const radios = FORMATS.map((f) => {
    const input = h("input", { type: "radio", name: "export-format", value: f.id, checked: f.id === format });
    input.addEventListener("change", () => {
      format = f.id;
    });
    return h("label", { class: "format-option" }, input, h("span", {}, h("b", {}, f.label), h("span", { class: "muted" }, f.text)));
  });
  const message = h("p", { class: "form-message", role: "status" });
  const save = h("button", { type: "button", class: "btn primary" }, "Save…");
  let dismiss = () => {};
  const dialog = h(
    "dialog",
    { class: "confirm export-dialog", "aria-labelledby": "export-title" },
    h("h2", { id: "export-title" }, "Save the report"),
    h("div", { class: "format-options", role: "radiogroup", "aria-labelledby": "export-title" }, radios),
    comparing ? h("label", { class: "check" }, onlyNew, `Only what's new since ${state.compare.name}`) : null,
    message,
    h("div", { class: "confirm-actions" }, h("button", { type: "button", class: "btn", onclick: () => dismiss() }, "Cancel"), save),
  );
  save.addEventListener("click", async () => {
    save.disabled = true;
    try {
      const name = await backend.exportReport(format, comparing && onlyNew.checked);
      if (name) {
        if (format === "json" && !(comparing && onlyNew.checked)) state.saved = name;
        dismiss();
        renderReportbar();
        toast(`Saved ${name}.`);
      }
    } catch (e) {
      replace(message, h("span", { class: "error-text" }, e.message));
    } finally {
      save.disabled = false;
    }
  });
  dismiss = nav.showDialog(dialog);
}

async function openReport() {
  if (state.view === "scanning") return;
  try {
    const opened = await backend.openReport();
    if (opened) loadReport(opened.report, { kind: "file", name: opened.name });
  } catch (e) {
    showError(e.message);
  }
}

// ------------------------------------------------------------------ start

async function refreshEnvironment() {
  try {
    state.env = await backend.environment();
    document.documentElement.dataset.platform = state.env.platform ?? "";
    // Android's Back button closes what the page has open first (see nav.js).
    nav.useSystemBack(state.env.mobile);
  } catch (e) {
    showError(e.message);
  }
}

// Android draws the page under the status and navigation bars, and its WebView may not
// report their size to CSS, so the app's activity passes them in (CSS pixels).
function syncAndroidInsets() {
  let insets;
  try {
    insets = JSON.parse(window.AndroidInsets.get());
  } catch {
    return;
  }
  for (const side of ["top", "right", "bottom", "left"]) {
    const px = Number(insets[side]);
    if (Number.isFinite(px)) document.documentElement.style.setProperty(`--native-inset-${side}`, `${px}px`);
  }
}

/** Between the phone layout and the wider one, views that differ are redrawn. */
phone.addEventListener("change", () => {
  renderTopbar();
  if (state.view !== "report" || !state.report) return;
  state.settings = null;
  state.findings?.relayout();
  if (state.tab !== "findings") showTab(state.tab);
});

nav.onChange(syncBack);
navBack.append(icon("arrowLeft"));
navBack.addEventListener("click", () => nav.back());
moreButton.append(icon("more"));
moreButton.addEventListener("click", openMore);

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  // No shortcuts behind an open dialog, or while a scan runs.
  if (!mod || state.view === "scanning" || document.querySelector("dialog[open]")) return;
  const key = e.key.toLowerCase();
  if (key === "o") {
    e.preventDefault();
    openReport();
  } else if (key === "n") {
    e.preventDefault();
    showSetup();
  } else if ((key === "s" || key === "e") && state.view === "report") {
    e.preventDefault();
    exportDialog();
  } else if (key === "f" && state.view === "report") {
    e.preventDefault();
    showTab("findings");
    state.findings.focusSearch();
  }
});

async function start() {
  if (window.AndroidInsets) {
    syncAndroidInsets();
    window.addEventListener("androidinsets", syncAndroidInsets);
    window.addEventListener("resize", syncAndroidInsets);
  }
  replace(document.getElementById("brand"), logo(), "ghaudit");
  showHome();
  const [catalog] = await Promise.all([backend.catalog().catch((e) => showError(e.message)), refreshEnvironment()]);
  state.catalog = catalog ?? null;
  if (state.view === "home") showHome();
  // The setup page depends on what this device can do.
  else if (state.view === "setup") showSetup();
}

start();
