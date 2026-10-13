// The Findings tab: a filterable, sortable table of findings and the selected one in
// detail. Every string from the report is inserted as text (see dom.js).

import { h, replace, icon, plural, phone, shortRepo, reportOwner } from "./dom.js";
import { SEVERITIES, SEVERITY, CATEGORIES, CONFIDENCE, categoryLabel } from "./explain.js";
import { filterFindings, sortFindings, githubLinks, repositoryOf, repositoryRows } from "./report.js";
import * as backend from "./backend.js";
import * as nav from "./nav.js";

/** Rows rendered at a time; "Show more" adds another page. */
const PAGE = 300;

const COLUMNS = [
  { key: "severity", label: "Severity", col: "c-sev", defaultDir: "desc" },
  { key: "rule", label: "Problem", col: "c-title", defaultDir: "asc" },
  { key: "repository", label: "Repository", col: "c-repo", defaultDir: "asc", multiOnly: true },
  { key: "location", label: "Where", col: "c-loc", defaultDir: "asc" },
];

/** The phone's sort choices (wider screens sort by the column headings). */
const SORT_LABELS = {
  severity: "Most severe first",
  rule: "Problem, A to Z",
  repository: "Repository, A to Z",
  location: "File, A to Z",
};

const ALLOWED_LINK = /^https:\/\/(github\.com|osv\.dev)\//;

/** Where the details cover the list instead of sitting beside it (as in styles.css). */
const DETAIL_OVERLAY = window.matchMedia("(max-width: 1040px)");

/**
 * prepared: from report.prepare(). onError(message) shows a failure.
 * Returns { element, applyFilter(filter) }.
 */
export function createFindingsView(prepared, { onError }) {
  const allColumns = COLUMNS.filter((c) => !c.multiOnly || prepared.multi);
  /** Grouped by repository, the repository column would only repeat the group. */
  const columns = () => allColumns.filter((c) => !(state.group && c.key === "repository"));
  /** Groups come worst first, as on the Overview. */
  const groupOrder = new Map(repositoryRows(prepared).map((r, i) => [r.name, i]));
  const state = {
    text: "",
    severities: new Set(),
    category: "",
    repository: "",
    group: false,
    sort: { key: "severity", dir: "desc" },
    limit: PAGE,
    selected: null,
    detailOpen: false,
  };
  let visible = [];
  const byId = new Map(prepared.findings.map((f) => [f.id, f]));
  const owner = reportOwner(prepared.raw.target);

  // ---------------------------------------------------------------- toolbar

  const search = h("input", {
    class: "input",
    type: "search",
    placeholder: "Search title, file, package, CVE…",
    "aria-label": "Search findings",
    spellcheck: "false",
    autocapitalize: "off",
    autocorrect: "off",
    enterkeyhint: "search",
  });
  let searchTimer;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.text = search.value;
      update({ resetLimit: true });
    }, 120);
  });
  search.addEventListener("keydown", (e) => {
    // Phones: the keyboard's search key hides the keyboard, so the results show.
    if (e.key === "Enter" && phone.matches) search.blur();
  });

  const sevChips = SEVERITIES.filter((s) => prepared.bySeverity[s.id]).map((s) => {
    const chip = h(
      "button",
      {
        type: "button",
        class: `toggle-chip sev-${s.id}`,
        "aria-pressed": "false",
        title: `${s.label}: ${s.advice}`,
        onclick: () => {
          if (state.severities.has(s.id)) state.severities.delete(s.id);
          else state.severities.add(s.id);
          update({ resetLimit: true });
        },
      },
      h("span", { class: "dot", "aria-hidden": "true" }),
      s.label,
      h("span", { class: "n" }, prepared.bySeverity[s.id].toLocaleString()),
    );
    chip.dataset.severity = s.id;
    return chip;
  });

  const categorySelect = h(
    "select",
    { class: "select", "aria-label": "Kind of problem" },
    h("option", { value: "" }, "All kinds"),
    CATEGORIES.filter((c) => prepared.byCategory[c.id]).map((c) =>
      h("option", { value: c.id }, `${c.label} (${prepared.byCategory[c.id].toLocaleString()})`),
    ),
  );
  categorySelect.addEventListener("change", () => {
    state.category = categorySelect.value;
    update({ resetLimit: true });
  });

  let repoSelect = null;
  let groupBox = null;
  if (prepared.multi) {
    const counts = new Map();
    for (const f of prepared.findings) counts.set(f.repository, (counts.get(f.repository) ?? 0) + 1);
    const names = [...counts.keys()].filter(Boolean).sort((a, b) => a.localeCompare(b));
    repoSelect = h(
      "select",
      { class: "select", "aria-label": "Repository" },
      h("option", { value: "" }, "All repositories"),
      names.map((n) => h("option", { value: n }, `${n} (${counts.get(n).toLocaleString()})`)),
    );
    repoSelect.addEventListener("change", () => {
      state.repository = repoSelect.value;
      update({ resetLimit: true });
    });
    groupBox = h("input", { type: "checkbox" });
    groupBox.addEventListener("change", () => {
      state.group = groupBox.checked;
      update({ resetLimit: true });
    });
  }

  // Phones sort in the Filters sheet: their list has no column headings.
  const sortSelect = h(
    "select",
    { class: "select", "aria-label": "Sort by" },
    allColumns.map((c) => h("option", { value: c.key }, SORT_LABELS[c.key])),
  );
  sortSelect.addEventListener("change", () => {
    const column = allColumns.find((c) => c.key === sortSelect.value);
    if (column) state.sort = { key: column.key, dir: column.defaultDir };
    update({});
  });

  const chipBox = h("div", { class: "toggle-chips", role: "group", "aria-label": "Severity" }, sevChips);
  const groupLabel = groupBox ? h("label", { class: "check" }, groupBox, "Group by repository") : null;
  /** The controls a phone shows in the Filters sheet, and wider screens in the bar. */
  const controlNodes = [chipBox, categorySelect, repoSelect, groupLabel].filter(Boolean);
  const controls = h("div", { class: "filter-controls" }, controlNodes);
  const filterBadge = h("span", { class: "filter-count" });
  const filtersButton = h(
    "button",
    { type: "button", class: "btn filters-button phone-only", "aria-haspopup": "dialog", onclick: () => openFilters() },
    icon("filter"),
    "Filters",
    filterBadge,
  );

  const filters = h(
    "div",
    { class: "filters", role: "search" },
    h("div", { class: "search" }, icon("search"), search),
    filtersButton,
    controls,
  );

  const countLine = h("div", { class: "result-count", role: "status", "aria-live": "polite" });

  // ---------------------------------------------------------------- table

  const headCells = allColumns.map((c) => {
    const th = h("th", { scope: "col" });
    const button = h("button", { type: "button", onclick: () => sortBy(c) }, c.label);
    th.append(button);
    return { column: c, th, button };
  });
  const colgroup = h("colgroup", {});
  const headRow = h("tr", {});
  const tbody = h("tbody", {});
  const table = h("table", { class: "findings-table", "aria-label": "Findings" }, colgroup, h("thead", {}, headRow), tbody);
  const cards = h("ul", { class: "finding-cards", "aria-label": "Findings", hidden: true });
  const more = h("div", { class: "more" });
  const listScroll = h("div", { class: "list-scroll" }, table, cards, more);

  cards.addEventListener("click", (e) => {
    const card = e.target.closest("button.finding-card");
    if (card) select(Number(card.dataset.id), { open: true });
  });

  tbody.addEventListener("click", (e) => {
    const row = e.target.closest("tr.finding");
    if (row) select(Number(row.dataset.id), { open: true });
  });
  tbody.addEventListener("keydown", (e) => {
    const row = e.target.closest("tr.finding");
    if (!row) return;
    const rows = [...tbody.querySelectorAll("tr.finding")];
    const i = rows.indexOf(row);
    const target = { ArrowDown: rows[i + 1], ArrowUp: rows[i - 1], Home: rows[0], End: rows[rows.length - 1] }[e.key];
    if (target) {
      e.preventDefault();
      select(Number(target.dataset.id), { focus: true });
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      select(Number(row.dataset.id), { open: true });
    }
  });

  const detail = h("aside", { class: "detail closed", "aria-label": "Finding details" });

  const element = h(
    "div",
    { class: "findings" },
    h("div", { class: "findings-list" }, filters, countLine, listScroll),
    detail,
  );

  // Escape closes the details where they cover the list (narrow windows).
  element.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || !state.detailOpen) return;
    closeDetail();
  });

  /** In the mobile app, where the details cover the list, Back closes them. */
  let detailLayer = null;

  function openDetail() {
    state.detailOpen = true;
    if (!detailLayer && DETAIL_OVERLAY.matches && nav.systemBackEnabled()) {
      detailLayer = nav.openLayer(() => {
        detailLayer = null;
        hideDetail();
      });
    }
  }

  function closeDetail() {
    if (detailLayer) nav.closeLayer(detailLayer);
    detailLayer = null;
    hideDetail();
  }

  function hideDetail() {
    state.detailOpen = false;
    detail.classList.add("closed");
    const current = phone.matches
      ? cards.querySelector(`button.finding-card[data-id="${state.selected}"]`)
      : tbody.querySelector('tr.finding[aria-selected="true"]');
    for (const c of cards.querySelectorAll('button.finding-card[aria-current="true"]')) c.removeAttribute("aria-current");
    current?.focus({ preventScroll: phone.matches });
  }

  // ---------------------------------------------------------------- filters sheet

  function openFilters() {
    const field = (label, control) => h("div", { class: "sheet-field" }, h("span", { class: "sheet-label" }, label), control);
    let close = () => {};
    const content = [
      field("Severity", chipBox),
      field("Kind of problem", categorySelect),
      repoSelect ? field("Repository", repoSelect) : null,
      field("Sort by", sortSelect),
      groupLabel ? h("div", { class: "sheet-field" }, groupLabel) : null,
      h(
        "div",
        { class: "sheet-actions" },
        h("button", { type: "button", class: "btn", onclick: clearFilters }, "Clear filters"),
        h("button", { type: "button", class: "btn primary", onclick: () => close() }, "Show results"),
      ),
    ];
    close = nav.openSheet({ title: "Filter and sort", content, className: "filters-sheet", onClose: restoreControls });
  }

  /** Put the controls back in the bar when the sheet closes. */
  function restoreControls() {
    controls.replaceChildren(...controlNodes);
  }

  // ---------------------------------------------------------------- behaviour

  function sortBy(column) {
    if (state.sort.key === column.key) state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
    else state.sort = { key: column.key, dir: column.defaultDir };
    update({});
  }

  function filtersActive() {
    return Boolean(state.text || state.severities.size || state.category || state.repository);
  }

  function clearFilters() {
    state.text = "";
    state.severities.clear();
    state.category = "";
    state.repository = "";
    search.value = "";
    update({ resetLimit: true });
  }

  function update({ resetLimit = false }) {
    if (resetLimit) state.limit = PAGE;
    visible = sortFindings(filterFindings(prepared.findings, state), {
      ...state.sort,
      group: state.group ? groupOrder : null,
    });
    if (state.selected !== null && !visible.some((f) => f.id === state.selected)) state.selected = null;
    if (state.selected === null && visible.length) state.selected = visible[0].id;
    syncControls();
    renderRows();
    renderDetail();
  }

  function syncControls() {
    for (const chip of sevChips) chip.setAttribute("aria-pressed", String(state.severities.has(chip.dataset.severity)));
    categorySelect.value = state.category;
    if (repoSelect) repoSelect.value = state.repository;
    if (groupBox) groupBox.checked = state.group;
    const sortColumn = allColumns.find((c) => c.key === state.sort.key);
    sortSelect.value = sortColumn && state.sort.dir === sortColumn.defaultDir ? sortColumn.key : "";
    const active = state.severities.size + Number(Boolean(state.category)) + Number(Boolean(state.repository));
    filterBadge.textContent = active ? String(active) : "";
    filtersButton.setAttribute("aria-label", active ? `Filters, ${active} on` : "Filters");
    const shown = columns();
    colgroup.replaceChildren(...shown.map((c) => h("col", { class: c.col })));
    headRow.replaceChildren(...headCells.filter((c) => shown.includes(c.column)).map((c) => c.th));
    for (const { column, th, button } of headCells) {
      const active = state.sort.key === column.key;
      th.setAttribute("aria-sort", active ? (state.sort.dir === "asc" ? "ascending" : "descending") : "none");
      replace(button, column.label, icon(active ? (state.sort.dir === "asc" ? "chevronUp" : "chevronDown") : "sort"));
    }
    const total = prepared.findings.length;
    replace(
      countLine,
      visible.length === total ? `${plural(total, "finding")}` : `${visible.length.toLocaleString()} of ${plural(total, "finding")}`,
      filtersActive() ? h("button", { type: "button", class: "link", onclick: clearFilters }, "Clear filters") : null,
    );
  }

  function renderRows() {
    const onPhone = phone.matches;
    table.hidden = onPhone;
    cards.hidden = !onPhone;
    if (onPhone) renderCards();
    else renderTable();
    replace(
      more,
      visible.length > state.limit
        ? h(
            "button",
            {
              type: "button",
              class: "btn",
              onclick: () => {
                state.limit += PAGE;
                renderRows();
              },
            },
            `Show ${Math.min(PAGE, visible.length - state.limit).toLocaleString()} more`,
          )
        : null,
    );
  }

  function emptyState() {
    return prepared.findings.length
      ? h(
          "div",
          { class: "empty" },
          icon("filter"),
          h("h3", {}, "No findings match these filters"),
          h("button", { type: "button", class: "btn", onclick: clearFilters }, "Clear filters"),
        )
      : h("div", { class: "empty" }, icon("shieldCheck"), h("h3", {}, "Nothing was found"), h("p", {}, "See the Overview for what was checked."));
  }

  /** Phones: a card per finding, under a heading per repository when grouped. */
  function renderCards() {
    tbody.replaceChildren();
    const items = [];
    const perGroup = new Map();
    if (state.group) for (const f of visible) perGroup.set(f.repository, (perGroup.get(f.repository) ?? 0) + 1);
    let group = undefined;
    for (const f of visible.slice(0, state.limit)) {
      if (state.group && f.repository !== group) {
        group = f.repository;
        items.push(
          h("li", { class: "group" }, group ? shortRepo(group, owner) : "Organization", h("span", { class: "n" }, plural(perGroup.get(group), "finding"))),
        );
      }
      items.push(h("li", {}, card(f)));
    }
    cards.replaceChildren(...items);
    if (!visible.length) cards.append(h("li", {}, emptyState()));
  }

  function card(f) {
    const sev = SEVERITY[f.severity];
    const repo = !state.group && f.repository ? shortRepo(f.repository, owner) : null;
    return h(
      "button",
      {
        type: "button",
        class: "finding-card",
        "aria-current": f.id === state.selected && state.detailOpen ? "true" : null,
        dataset: { id: f.id },
      },
      h(
        "span",
        { class: "fc-top" },
        h("span", { class: `badge sev-${f.severity}` }, sev?.label ?? f.severity),
        h("span", { class: "chip" }, categoryLabel(f.category)),
        f.commit ? h("span", { class: "chip" }, "In git history") : null,
      ),
      h("span", { class: "fc-title" }, f.title),
      // The category chip already says "Repository settings".
      h("span", { class: "fc-where" }, repo ? h("span", { class: "fc-repo" }, repo) : null, f.category === "settings" ? null : whereShort(f)),
    );
  }

  function renderTable() {
    cards.replaceChildren();
    const shown = visible.slice(0, state.limit);
    const rows = [];
    const span = columns().length;
    const perGroup = new Map();
    if (state.group) for (const f of visible) perGroup.set(f.repository, (perGroup.get(f.repository) ?? 0) + 1);
    let group = undefined;
    for (const f of shown) {
      if (state.group && f.repository !== group) {
        group = f.repository;
        rows.push(
          h(
            "tr",
            { class: "group" },
            h("td", { colspan: span }, group ?? "Organization", h("span", { class: "n" }, plural(perGroup.get(group), "finding"))),
          ),
        );
      }
      rows.push(row(f));
    }
    tbody.replaceChildren(...rows);
    if (!visible.length) tbody.append(h("tr", {}, h("td", { colspan: span }, emptyState())));
  }

  function row(f) {
    const sev = SEVERITY[f.severity];
    const cells = {
      severity: h("td", {}, h("span", { class: `badge sev-${f.severity}` }, sev?.label ?? f.severity)),
      rule: h(
        "td",
        {},
        h("span", { class: "f-title", title: f.title }, f.title),
        h("span", { class: "f-rule" }, `${categoryLabel(f.category)} · ${f.rule_id}`),
      ),
      repository: h("td", {}, h("span", { class: "f-repo" }, f.repository ?? "")),
      location: h("td", {}, whereShort(f)),
    };
    return h(
      "tr",
      {
        class: "finding",
        tabindex: f.id === state.selected ? 0 : -1,
        "aria-selected": String(f.id === state.selected),
        dataset: { id: f.id },
      },
      columns().map((c) => cells[c.key]),
    );
  }

  function whereShort(f) {
    if (f.category === "settings") return h("span", { class: "muted" }, "Repository settings");
    const line = f.location?.start_line;
    return h("span", { class: "f-loc" }, `${f.location?.path ?? ""}${line ? `:${line}` : ""}`, f.commit ? h("span", { class: "muted" }, ` @ ${f.commit.slice(0, 7)}`) : null);
  }

  function select(id, { focus = false, open = false } = {}) {
    state.selected = id;
    if (open) openDetail();
    for (const c of cards.querySelectorAll("button.finding-card")) {
      if (Number(c.dataset.id) === id && state.detailOpen) c.setAttribute("aria-current", "true");
      else c.removeAttribute("aria-current");
    }
    for (const tr of tbody.querySelectorAll("tr.finding")) {
      const on = Number(tr.dataset.id) === id;
      tr.setAttribute("aria-selected", String(on));
      tr.tabIndex = on ? 0 : -1;
      if (on && focus) {
        tr.focus();
        tr.scrollIntoView({ block: "nearest" });
      }
    }
    renderDetail();
    // Phones: the details fill the screen, so focus moves into them.
    if (open && phone.matches) detail.querySelector(".detail-bar .icon-btn")?.focus({ preventScroll: true });
  }

  // ---------------------------------------------------------------- detail

  function renderDetail() {
    const f = byId.get(state.selected);
    detail.classList.toggle("closed", !state.detailOpen);
    detail.scrollTop = 0;
    if (!f) {
      replace(detail, h("div", { class: "empty detail-empty" }, icon("info"), h("h3", {}, "No finding selected"), h("p", {}, "Select a finding to see what it means and how to fix it.")));
      return;
    }
    replace(detail, detailView(f));
  }

  function detailView(f) {
    const sev = SEVERITY[f.severity] ?? { label: f.severity, advice: "", text: "" };
    const links = githubLinks(prepared, f);
    const close = h("button", { type: "button", class: "btn quiet detail-close desktop-only", onclick: closeDetail }, icon("close"), "Close");
    const inner = h(
      "div",
      { class: `detail-inner sev-${f.severity}` },
      close,
      h(
        "div",
        { class: "badges" },
        h("span", { class: `badge sev-${f.severity}` }, sev.label),
        h("span", { class: "chip" }, categoryLabel(f.category)),
        f.commit ? h("span", { class: "chip" }, "In git history") : null,
      ),
      h("div", {}, h("h2", {}, f.title), h("div", { class: "rule-id" }, [f.rule_id, ...(f.cwe ?? [])].join(" · "))),
      h("p", { class: "explain" }, h("b", {}, `${sev.label}: ${sev.advice}. `), sev.text),
      section("What was found", h("p", { class: "prose" }, f.message)),
      whereSection(f, links),
      f.snippet?.lines?.length ? section("The code", snippetView(f), f.category === "secret" || f.commit ? h("p", { class: "note" }, "Secret values are masked: only their first characters are shown.") : null) : null,
      f.dependency ? section("The package", dependencyFacts(f.dependency)) : null,
      f.remediation ? section("How to fix it", h("div", { class: "fix" }, f.remediation)) : null,
      section("How sure", h("p", {}, CONFIDENCE[f.confidence] ?? f.confidence)),
    );
    return [detailBar(f), inner];
  }

  /** Phones: Back, where this finding is in the list, and the previous and next ones. */
  function detailBar(f) {
    const i = visible.findIndex((v) => v.id === f.id);
    const step = (d) => {
      const next = visible[i + d];
      if (!next) return;
      if (i + d >= state.limit) {
        state.limit += PAGE;
        renderRows();
      }
      select(next.id);
      cards.querySelector(`button.finding-card[data-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
      detail.querySelector(d < 0 ? ".detail-prev" : ".detail-next")?.focus({ preventScroll: true });
    };
    return h(
      "div",
      { class: "detail-bar phone-only" },
      h("button", { type: "button", class: "icon-btn", "aria-label": "Back to the list", onclick: closeDetail }, icon("arrowLeft")),
      h("span", { class: "detail-pos" }, i >= 0 ? `${(i + 1).toLocaleString()} of ${visible.length.toLocaleString()}` : ""),
      h("button", { type: "button", class: "icon-btn detail-prev", "aria-label": "Previous finding", disabled: i <= 0, onclick: () => step(-1) }, icon("chevronUp")),
      h("button", { type: "button", class: "icon-btn detail-next", "aria-label": "Next finding", disabled: i < 0 || i >= visible.length - 1, onclick: () => step(1) }, icon("chevronDown")),
    );
  }

  function whereSection(f, links) {
    const repo = repositoryOf(prepared, f);
    const facts = [];
    if (repo) facts.push(["Repository", repo]);
    if (f.category === "settings") {
      facts.push(["Setting", "Repository settings on GitHub"]);
    } else {
      const loc = f.location ?? {};
      facts.push(["File", h("span", { class: "mono" }, loc.path ?? "")]);
      if (loc.start_line) facts.push(["Line", loc.start_column > 1 ? `${loc.start_line}, column ${loc.start_column}` : String(loc.start_line)]);
      if (f.commit) facts.push(["Added in commit", h("span", { class: "mono" }, f.commit.slice(0, 12))]);
    }
    const linkButtons = [
      f.help_url ? externalLink("Open the settings page", f.help_url) : null,
      links.file ? externalLink(f.commit ? "View the file at that commit" : "View on GitHub", links.file) : null,
      links.commit ? externalLink("View the commit", links.commit) : null,
    ].filter(Boolean);
    return section(
      "Where",
      h("dl", { class: "facts" }, facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      linkButtons.length ? h("div", { class: "links" }, linkButtons) : null,
    );
  }

  function dependencyFacts(d) {
    const facts = [
      ["Package", `${d.package} (${d.ecosystem})`],
      ["Installed", d.version],
      ["Fixed in", d.fixed_versions?.length ? d.fixed_versions.join(", ") : "No fixed version yet"],
      ["Advisory", [d.advisory, ...(d.aliases ?? [])].join(", ")],
      d.cvss_score != null ? ["CVSS score", `${d.cvss_score} out of 10`] : null,
      d.informational ? ["Kind", d.informational === "unmaintained" ? "Unmaintained package (no known flaw)" : d.informational] : null,
    ].filter(Boolean);
    return [
      h("dl", { class: "facts" }, facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
      d.url ? h("div", { class: "links" }, externalLink("Read the advisory", d.url)) : null,
    ];
  }

  function snippetView(f) {
    const s = f.snippet;
    const start = f.location?.start_line ?? 0;
    const end = Math.max(start, f.location?.end_line ?? start);
    return h(
      "pre",
      { class: "snippet", tabindex: 0, "aria-label": "Code around the finding" },
      s.lines.map((text, i) => {
        const n = s.first_line + i;
        return h("div", { class: n >= start && n <= end ? "line focus" : "line" }, h("span", { class: "ln" }, n), h("span", { class: "code" }, text));
      }),
    );
  }

  function externalLink(label, url) {
    if (!ALLOWED_LINK.test(url)) {
      return h("span", { class: "muted mono" }, url);
    }
    return h(
      "button",
      { type: "button", class: "link", title: url, onclick: () => backend.openLink(url).catch((e) => onError(e.message)) },
      label,
      icon("external"),
    );
  }

  function section(title, ...body) {
    return h("section", {}, h("h3", {}, title), body);
  }

  // ---------------------------------------------------------------- public

  function applyFilter(filter = {}) {
    state.text = filter.text ?? "";
    search.value = state.text;
    state.severities = new Set(filter.severities ?? []);
    state.category = filter.category ?? "";
    state.repository = filter.repository ?? "";
    state.selected = null;
    if (state.detailOpen) closeDetail();
    update({ resetLimit: true });
    listScroll.scrollTop = 0;
  }

  /** The layout changed between phone and wider: redraw the list. */
  function relayout() {
    renderRows();
    renderDetail();
  }

  update({});
  return { element, applyFilter, relayout, focusSearch: () => search.focus() };
}
