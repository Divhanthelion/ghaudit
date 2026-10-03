// ghaudit desktop: the start page and the report views.

import { h, replace, icon, logo, toast, formatDate } from "./dom.js";
import * as backend from "./backend.js";
import { CATEGORIES } from "./explain.js";
import { prepare } from "./report.js";
import { renderOverview } from "./overview.js";
import { createFindingsView } from "./findings.js";
import { renderCoverage } from "./coverage.js";

const main = document.getElementById("main");
const tabsEl = document.getElementById("tabs");
const reportbar = document.getElementById("reportbar");
const actions = document.getElementById("topbar-actions");

const state = {
  catalog: null,
  /** The report on screen, from report.prepare(). */
  report: null,
  /** Where it came from: { kind: "file", name }. */
  source: null,
  tab: "overview",
  findings: null,
};

const TABS = [
  { id: "overview", label: "Overview", icon: "shield" },
  { id: "findings", label: "Findings", icon: "alert", count: (r) => r.findings.length },
  { id: "coverage", label: "Coverage", icon: "layers" },
];

function showError(message) {
  toast(message, { error: true });
}

// ------------------------------------------------------------------ top bar

function renderTopbar() {
  replace(document.getElementById("brand"), logo(), "ghaudit");
  replace(
    actions,
    h(
      "button",
      { type: "button", class: "btn", onclick: openReport, title: "Open a saved report (Ctrl+O)" },
      icon("file"),
      h("span", { class: "btn-label" }, "Open report…"),
    ),
  );
}

function renderTabs() {
  tabsEl.hidden = !state.report;
  if (!state.report) return;
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
  reportbar.hidden = !state.report;
  if (!state.report) return;
  const r = state.report.raw;
  const parts = [
    h("span", { class: "target" }, targetLabel(r.target ?? "")),
    `Scanned ${formatDate(r.started_at)}`,
    state.source?.kind === "file" ? `Opened from ${state.source.name}` : null,
  ].filter(Boolean);
  replace(
    reportbar,
    parts.flatMap((p, i) => (i ? [h("span", { class: "sep", "aria-hidden": "true" }, "·"), p] : [p])),
  );
}

// ------------------------------------------------------------------ views

function showHome() {
  state.report = null;
  state.findings = null;
  renderTabs();
  renderReportbar();
  main.className = "";
  main.removeAttribute("role");
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

function showTab(id) {
  state.tab = id;
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
  renderReportbar();
  showTab("overview");
}

async function openReport() {
  try {
    const opened = await backend.openReport();
    if (opened) loadReport(opened.report, { kind: "file", name: opened.name });
  } catch (e) {
    showError(e.message);
  }
}

// ------------------------------------------------------------------ start

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === "o") {
    e.preventDefault();
    openReport();
  } else if (mod && e.key.toLowerCase() === "f" && state.report) {
    e.preventDefault();
    showTab("findings");
    state.findings.focusSearch();
  }
});

async function start() {
  renderTopbar();
  showHome();
  try {
    state.catalog = await backend.catalog();
    if (!state.report) showHome();
  } catch (e) {
    showError(e.message);
  }
}

start();
