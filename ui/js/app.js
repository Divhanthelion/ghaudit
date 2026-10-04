// ghaudit desktop: the start page, scanning, and the report views.

import { h, replace, icon, logo, toast, formatDate } from "./dom.js";
import * as backend from "./backend.js";
import { CATEGORIES } from "./explain.js";
import { prepare } from "./report.js";
import { renderOverview } from "./overview.js";
import { createFindingsView } from "./findings.js";
import { renderCoverage } from "./coverage.js";
import { renderSetup, loadOptions, saveOptions, scanRequest, scanLabel, TARGETS } from "./scan.js";
import { createProgressView } from "./progress.js";

const main = document.getElementById("main");
const tabsEl = document.getElementById("tabs");
const reportbar = document.getElementById("reportbar");
const actions = document.getElementById("topbar-actions");

const state = {
  catalog: null,
  /** What scans can use (GitHub access, osv-scanner, git); null while checking. */
  env: null,
  /** The folder chosen for folder scans (the backend holds the real one). */
  folder: null,
  /** "home", "setup", "scanning" or "report". */
  view: "home",
  /** The report on screen, from report.prepare(). */
  report: null,
  /** Where it came from: { kind: "file", name } or { kind: "scan" }. */
  source: null,
  tab: "overview",
  findings: null,
};

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings", count: (r) => r.findings.length },
  { id: "coverage", label: "Coverage" },
];

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
}

function renderTabs() {
  const shown = state.view === "report" && state.report;
  tabsEl.hidden = !shown;
  if (!shown) return;
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
  const r = state.report.raw;
  const parts = [
    h("span", { class: "target" }, targetLabel(r.target ?? "")),
    `Scanned ${formatDate(r.started_at)}`,
    state.source?.kind === "file" ? `Opened from ${state.source.name}` : "Not saved yet",
  ];
  replace(
    reportbar,
    parts.flatMap((p, i) => (i ? [h("span", { class: "sep", "aria-hidden": "true" }, "·"), p] : [p])),
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
  const env = state.env;
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
            "ghaudit finds leaked passwords and keys, vulnerable dependencies, risky code and workflows, and weak repository settings, and explains in plain language what to fix first.",
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
          h("p", {}, "One repository, a folder on this computer, an organization or a search."),
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
          h("div", { class: "item" }, icon(c.icon), h("div", {}, h("b", {}, c.label), h("span", {}, c.text))),
        ),
      ),
      state.catalog
        ? h("p", { class: "home-footer" }, `ghaudit desktop ${state.catalog.app_version} · scanner ${state.catalog.scanner_version} · reads from GitHub, never changes anything`)
        : null,
    ),
  );
}

function showSetup() {
  setView("setup");
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

/** "Scan my repositories" from the start page, with the saved options. */
function scanMine() {
  const options = { ...loadOptions(), kind: "mine" };
  saveOptions(options);
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

async function runScan(request, label, options) {
  setView("scanning");
  const multi = Boolean(TARGETS.find((t) => t.kind === options.kind)?.multi);
  const view = createProgressView({
    label,
    options,
    multi,
    onCancel: () => backend.cancelScan().catch((e) => showError(e.message)),
    onBack: showSetup,
  });
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
    replace(main, view.element);
  }
}

function showTab(id) {
  state.tab = id;
  state.view = "report";
  renderTabs();
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
  else if (id === "coverage") replace(main, renderCoverage(r));
  main.scrollTop = 0;
}

function loadReport(report, source) {
  state.report = prepare(report);
  state.source = source;
  state.findings = createFindingsView(state.report, { onError: showError });
  state.view = "report";
  renderTopbar();
  showTab("overview");
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
  } catch (e) {
    showError(e.message);
  }
}

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (!mod || state.view === "scanning") return;
  const key = e.key.toLowerCase();
  if (key === "o") {
    e.preventDefault();
    openReport();
  } else if (key === "n") {
    e.preventDefault();
    showSetup();
  } else if (key === "f" && state.view === "report") {
    e.preventDefault();
    showTab("findings");
    state.findings.focusSearch();
  }
});

async function start() {
  replace(document.getElementById("brand"), logo(), "ghaudit");
  showHome();
  const [catalog] = await Promise.all([backend.catalog().catch((e) => showError(e.message)), refreshEnvironment()]);
  state.catalog = catalog ?? null;
  if (state.view === "home") showHome();
}

start();
