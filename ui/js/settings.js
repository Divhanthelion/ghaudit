// The Settings tab: each repository's security settings as a grid of passed, needs
// attention and couldn't check. A setting ghaudit couldn't read is a gap in what was
// checked, shown with its reason, and never counted as a pass.

import { h, replace, icon, plural } from "./dom.js";
import { SETTINGS_AREAS, CHECK_STATUS, ANALYZER_STATE } from "./explain.js";
import * as backend from "./backend.js";

const CELL = {
  pass: { cls: "pass", icon: "check" },
  fail: { cls: "fail", icon: "close" },
  not_assessable: { cls: "na", icon: "helpCircle" },
};

/** Widths of the grid's columns, in pixels (the table has a fixed layout). */
const ROW_HEAD_WIDTH = 220;
const CHECK_WIDTH = 30;
/** Areas narrower than this many columns go unlabeled (their columns say enough). */
const LABEL_MIN_COLUMNS = 3;

const OWNER_REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const ALLOWED = /^https:\/\/github\.com\//;

function targetName(target) {
  return target.startsWith("org:") ? `Organization ${target.slice(4)}` : target;
}

/**
 * prepared: from report.prepare(); rules: Map of rule id to catalog entry;
 * showFindings(filter), onError(message). Returns { element }.
 */
export function createSettingsView(prepared, { rules, showFindings, onError }) {
  const entries = prepared.settings;
  if (!entries.length) return { element: notChecked(prepared) };

  // Columns: the checks this report has, in the order of SETTINGS_AREAS.
  const present = new Set(entries.map((e) => e.check));
  const known = new Set(SETTINGS_AREAS.flatMap((a) => a.checks.map(([id]) => id)));
  const areas = SETTINGS_AREAS.map((a) => ({ ...a, checks: a.checks.filter(([id]) => present.has(id)) })).filter((a) => a.checks.length);
  const unknown = [...present].filter((id) => !known.has(id)).sort();
  if (unknown.length) areas.push({ id: "other", label: "Other", checks: unknown.map((id) => [id, rules.get(id)?.name ?? id]) });
  const columns = areas.flatMap((a, ai) =>
    a.checks.map(([id, label], i) => ({ id, label, area: a.id, name: rules.get(id)?.name ?? label, first: ai > 0 && i === 0 })),
  );

  // Rows: one per repository (and organization), most failures first.
  const byTarget = new Map();
  for (const e of entries) {
    if (!byTarget.has(e.target)) byTarget.set(e.target, new Map());
    byTarget.get(e.target).set(e.check, e);
  }
  const rows = [...byTarget.entries()].map(([target, cells]) => {
    const counts = { pass: 0, fail: 0, not_assessable: 0 };
    for (const e of cells.values()) counts[e.status] = (counts[e.status] ?? 0) + 1;
    return { target, cells, counts };
  });
  rows.sort(
    (a, b) =>
      Number(b.target.startsWith("org:")) - Number(a.target.startsWith("org:")) ||
      b.counts.fail - a.counts.fail ||
      b.counts.not_assessable - a.counts.not_assessable ||
      a.target.localeCompare(b.target),
  );
  const totals = { pass: 0, fail: 0, not_assessable: 0 };
  for (const e of entries) totals[e.status] = (totals[e.status] ?? 0) + 1;

  const state = { show: "all", text: "", selected: null };

  // ---------------------------------------------------------------- controls

  const showSelect = h(
    "select",
    { class: "select", "aria-label": "Which repositories" },
    h("option", { value: "all" }, `All (${rows.length.toLocaleString()})`),
    h("option", { value: "fail" }, `Needing attention (${rows.filter((r) => r.counts.fail).length.toLocaleString()})`),
    h("option", { value: "na" }, `With checks that couldn't run (${rows.filter((r) => r.counts.not_assessable).length.toLocaleString()})`),
    h("option", { value: "clean" }, `Everything passed (${rows.filter((r) => !r.counts.fail && !r.counts.not_assessable).length.toLocaleString()})`),
  );
  showSelect.addEventListener("change", () => {
    state.show = showSelect.value;
    renderGrid();
  });
  const search = h("input", { class: "input", type: "search", placeholder: "Find a repository", "aria-label": "Find a repository", spellcheck: "false" });
  search.addEventListener("input", () => {
    state.text = search.value.trim().toLowerCase();
    renderGrid();
  });

  // ---------------------------------------------------------------- grid

  const gridWrap = h("div", { class: "settings-grid-wrap" });
  const detail = h("aside", { class: "settings-detail card", "aria-live": "polite" });

  function visibleRows() {
    return rows.filter((r) => {
      if (state.text && !r.target.toLowerCase().includes(state.text)) return false;
      if (state.show === "fail") return r.counts.fail > 0;
      if (state.show === "na") return r.counts.not_assessable > 0;
      if (state.show === "clean") return !r.counts.fail && !r.counts.not_assessable;
      return true;
    });
  }

  function renderGrid() {
    const shown = visibleRows();
    if (!shown.length) {
      replace(gridWrap, h("div", { class: "empty" }, icon("filter"), h("h3", {}, "No repositories match")));
      return;
    }
    const head = h(
      "thead",
      {},
      h(
        "tr",
        { class: "areas" },
        h("th", { class: "row-head", scope: "col" }, ""),
        areas.map((a) =>
          h(
            "th",
            { colspan: a.checks.length, class: "area", scope: "colgroup", title: a.label },
            a.checks.length >= LABEL_MIN_COLUMNS ? a.label : "",
          ),
        ),
      ),
      h(
        "tr",
        { class: "checks" },
        h("th", { class: "row-head", scope: "col" }, "Repository"),
        columns.map((c) => h("th", { scope: "col", class: `col${c.first ? " first-of-area" : ""}`, title: c.label }, h("span", {}, c.label))),
      ),
    );
    const body = h(
      "tbody",
      {},
      shown.map((r, ri) =>
        h(
          "tr",
          {},
          h(
            "th",
            { scope: "row", class: "row-head" },
            h("span", { class: "f-repo" }, targetName(r.target)),
            h(
              "span",
              { class: "row-counts" },
              r.counts.fail ? h("span", { class: "c-fail" }, `${r.counts.fail} to fix`) : null,
              r.counts.not_assessable ? h("span", { class: "c-na" }, `${r.counts.not_assessable} unchecked`) : null,
              !r.counts.fail && !r.counts.not_assessable ? h("span", { class: "c-pass" }, "all passed") : null,
            ),
          ),
          columns.map((c, ci) => cell(r, c, ri, ci)),
        ),
      ),
    );
    const table = h(
      "table",
      { class: "settings-grid", "aria-label": "Settings by repository" },
      h("colgroup", {}, h("col", { class: "row" }), columns.map(() => h("col", { class: "check" }))),
      head,
      body,
    );
    table.style.width = `${ROW_HEAD_WIDTH + columns.length * CHECK_WIDTH}px`;
    replace(gridWrap, table);
    const first = gridWrap.querySelector("button.cell");
    if (first) first.tabIndex = 0;
  }

  function cell(row, column, ri, ci) {
    const e = row.cells.get(column.id);
    const edge = column.first ? "first-of-area" : null;
    if (!e) {
      return h(
        "td",
        { class: edge ? `cell-none ${edge}` : "cell-none", title: `${column.label}: doesn't apply to ${targetName(row.target)}` },
        h("span", { "aria-hidden": "true" }, "·"),
      );
    }
    const kind = CELL[e.status] ?? CELL.not_assessable;
    const status = CHECK_STATUS[e.status] ?? CHECK_STATUS.not_assessable;
    const selected = state.selected?.target === row.target && state.selected?.check === column.id;
    return h(
      "td",
      { class: edge },
      h(
        "button",
        {
          type: "button",
          class: `cell ${kind.cls}`,
          tabindex: -1,
          "aria-label": `${targetName(row.target)}: ${column.label}: ${status.label}`,
          "aria-pressed": String(selected),
          title: `${column.label}: ${status.label}${e.detail ? ` (${e.detail})` : ""}`,
          dataset: { r: ri, c: ci, target: row.target, check: column.id },
        },
        icon(kind.icon),
      ),
    );
  }

  gridWrap.addEventListener("click", (e) => {
    const button = e.target.closest("button.cell");
    if (button) select(button);
  });
  gridWrap.addEventListener("keydown", (e) => {
    const button = e.target.closest("button.cell");
    if (!button) return;
    const move = { ArrowRight: [0, 1], ArrowLeft: [0, -1], ArrowDown: [1, 0], ArrowUp: [-1, 0] }[e.key];
    if (!move) return;
    e.preventDefault();
    let r = Number(button.dataset.r);
    let c = Number(button.dataset.c);
    // Skip over checks that don't apply, in the direction of travel.
    for (let i = 0; i < Math.max(columns.length, rows.length); i++) {
      r += move[0];
      c += move[1];
      const next = gridWrap.querySelector(`button.cell[data-r="${r}"][data-c="${c}"]`);
      if (next) {
        button.tabIndex = -1;
        next.tabIndex = 0;
        next.focus();
        select(next);
        return;
      }
      if (r < 0 || c < 0 || c >= columns.length || r >= rows.length) return;
    }
  });

  function select(button) {
    for (const b of gridWrap.querySelectorAll('button.cell[aria-pressed="true"]')) b.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-pressed", "true");
    state.selected = { target: button.dataset.target, check: button.dataset.check };
    renderDetail();
  }

  // ---------------------------------------------------------------- detail

  function renderDetail() {
    if (!state.selected) {
      replace(
        detail,
        h("div", { class: "empty" }, icon("sliders"), h("h3", {}, "Select a square"), h("p", {}, "See what the setting does, why it failed or couldn't be checked, and where to change it.")),
      );
      return;
    }
    const { target, check } = state.selected;
    const e = byTarget.get(target).get(check);
    const column = columns.find((c) => c.id === check);
    const status = CHECK_STATUS[e.status] ?? CHECK_STATUS.not_assessable;
    const kind = CELL[e.status] ?? CELL.not_assessable;
    const finding = prepared.findings.find((f) => f.rule_id === check && (f.repository ?? prepared.singleRepo) === (target.startsWith("org:") ? null : target));
    const settingsPage = finding?.help_url ?? (OWNER_REPO.test(target) ? `https://github.com/${target}/settings` : null);
    replace(
      detail,
      h(
        "div",
        { class: "detail-inner" },
        h("div", { class: "badges" }, h("span", { class: `check-badge ${kind.cls}` }, icon(kind.icon), status.label)),
        h("div", {}, h("h2", {}, column.label), h("div", { class: "rule-id" }, `Fails as “${column.name}” · ${check}`)),
        h("dl", { class: "facts" }, h("dt", {}, target.startsWith("org:") ? "Organization" : "Repository"), h("dd", {}, targetName(target))),
        h("p", {}, status.text),
        e.detail ? h("section", {}, h("h3", {}, e.status === "fail" ? "What was found" : "Why"), h("p", { class: "prose" }, e.detail)) : null,
        finding?.remediation ? h("section", {}, h("h3", {}, "How to fix it"), h("div", { class: "fix" }, finding.remediation)) : null,
        h(
          "div",
          { class: "links" },
          settingsPage && ALLOWED.test(settingsPage)
            ? h(
                "button",
                { type: "button", class: "link", title: settingsPage, onclick: () => backend.openLink(settingsPage).catch((err) => onError(err.message)) },
                "Open the settings page",
                icon("external"),
              )
            : null,
          finding
            ? h(
                "button",
                { type: "button", class: "link", onclick: () => showFindings({ repository: finding.repository ?? "", category: "settings", text: check }) },
                "See it in Findings",
              )
            : null,
        ),
      ),
    );
  }

  // ---------------------------------------------------------------- page

  const element = h(
    "div",
    { class: "page settings-page" },
    h(
      "div",
      { class: "section-head" },
      h("h2", {}, "Repository settings"),
      h("p", {}, "Security settings on GitHub, for each repository. Select a square for details."),
    ),
    h(
      "div",
      { class: "settings-summary" },
      summaryChip("pass", totals.pass),
      summaryChip("fail", totals.fail),
      summaryChip("not_assessable", totals.not_assessable),
    ),
    totals.not_assessable
      ? h(
          "div",
          { class: "banner warn" },
          icon("helpCircle"),
          h(
            "div",
            { class: "banner-body" },
            h("h2", {}, `${plural(totals.not_assessable, "check")} couldn't run`),
            h(
              "p",
              {},
              "ghaudit couldn't read these settings, so they may or may not be safe: count them as gaps in what was checked, not as passes. Select one to see why. Often the token isn't an admin of the repository, or GitHub doesn't offer the feature there.",
            ),
          ),
        )
      : null,
    h("div", { class: "filters settings-filters" }, h("div", { class: "search" }, icon("search"), search), showSelect, legend()),
    h("div", { class: "settings-layout" }, h("div", { class: "card settings-grid-card" }, gridWrap), detail),
  );

  function summaryChip(status, n) {
    const s = CHECK_STATUS[status];
    return h("span", { class: `summary-chip ${CELL[status].cls}` }, icon(CELL[status].icon), h("b", {}, n.toLocaleString()), ` ${s.label.toLowerCase()}`);
  }

  function legend() {
    return h(
      "div",
      { class: "legend", "aria-hidden": "true" },
      ["pass", "fail", "not_assessable"].map((s) => h("span", {}, h("span", { class: `cell mini ${CELL[s].cls}` }, icon(CELL[s].icon)), CHECK_STATUS[s].label)),
      h("span", {}, h("span", { class: "cell mini none" }, "·"), "Doesn't apply"),
    );
  }

  renderGrid();
  renderDetail();
  return { element };
}

/** The Settings tab when the report has no settings checks: say why. */
function notChecked(prepared) {
  const status = (prepared.raw.analyzers ?? []).find((a) => a.analyzer === "settings");
  const why =
    status?.state === "skipped"
      ? status.detail === "disabled"
        ? "The settings check was turned off for this scan."
        : `The settings check didn't run: ${status.detail}.`
      : status?.state === "failed"
        ? `The settings check failed: ${status.detail}.`
        : "This report has no settings checks.";
  const s = ANALYZER_STATE[status?.state] ?? ANALYZER_STATE.skipped;
  return h(
    "div",
    { class: "page" },
    h("div", { class: "section-head" }, h("h2", {}, "Repository settings")),
    h("div", { class: "banner" }, icon(s.icon), h("div", { class: "banner-body" }, h("h2", {}, "Settings weren't checked"), h("p", {}, why))),
  );
}
