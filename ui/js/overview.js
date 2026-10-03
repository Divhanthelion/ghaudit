// The Overview tab: is the scan complete, how bad is it, what kind of problems, where.

import { h, icon, plural, formatDate, formatDuration } from "./dom.js";
import { SEVERITIES, CATEGORIES, ANALYZER, analyzerLabel } from "./explain.js";
import { repositoryRows } from "./report.js";

/** Which analyzers find each category, to tell "none found" from "not checked". */
const CATEGORY_ANALYZERS = {
  secret: ["secrets", "history"],
  dependency: ["sca"],
  sast: ["sast"],
  workflow: ["workflows"],
  agent: ["agents"],
  settings: ["settings"],
  ai: ["ai"],
};

/**
 * prepared: from report.prepare(); go: { findings(filter), coverage() }
 */
export function renderOverview(prepared, go) {
  return h(
    "div",
    { class: "page" },
    statusBanners(prepared, go),
    severitySection(prepared, go),
    categorySection(prepared, go),
    prepared.multi ? repositorySection(prepared, go) : null,
    factsSection(prepared),
  );
}

function statusBanners(prepared, go) {
  const banners = [];
  const total = prepared.findings.length;
  const gaps = prepared.failures;
  if (gaps.length) {
    const shown = gaps.slice(0, 6);
    banners.push(
      h(
        "div",
        { class: "banner warn", role: "status" },
        icon("alert"),
        h(
          "div",
          { class: "banner-body" },
          h("h2", {}, "This scan is incomplete"),
          h(
            "p",
            {},
            "Some checks couldn't run, so problems may be missing from this report. Don't read it as all clear.",
          ),
          h(
            "ul",
            {},
            shown.map((g) =>
              h(
                "li",
                {},
                [g.repository, g.analyzer ? analyzerLabel(g.analyzer) : null].filter(Boolean).join(": ") || "Scan",
                " — ",
                g.detail,
              ),
            ),
          ),
          h(
            "p",
            { class: "links" },
            h("button", { class: "link", type: "button", onclick: () => go.coverage() }, gaps.length > shown.length ? `See all ${gaps.length}` : "See what was checked"),
          ),
        ),
      ),
    );
  }
  const baselined = prepared.raw.stats?.findings_baselined ?? 0;
  if (total === 0) {
    banners.push(
      h(
        "div",
        { class: gaps.length ? "banner" : "banner good", role: "status" },
        icon(gaps.length ? "info" : "shieldCheck"),
        h(
          "div",
          { class: "banner-body" },
          h("h2", {}, baselined ? "No new problems" : "No problems found"),
          h(
            "p",
            {},
            gaps.length
              ? "Nothing was found by the checks that ran, but see above for the ones that didn't."
              : baselined
                ? `Everything this scan found was already in the earlier report (${plural(baselined, "problem")}).`
                : "Every check that ran came back clean.",
          ),
        ),
      ),
    );
  } else {
    const worst = SEVERITIES.find((s) => prepared.bySeverity[s.id]);
    banners.push(
      h(
        "div",
        { class: `banner sev-${worst.id}`, role: "status" },
        icon("shield"),
        h(
          "div",
          { class: "banner-body" },
          h("h2", {}, baselined ? `${plural(total, "new problem")} since the earlier report` : `${plural(total, "problem")} found`),
          h(
            "p",
            {},
            worst.id === "info"
              ? "Only informational findings: nothing here needs fixing on its own."
              : `Start with the ${plural(prepared.bySeverity[worst.id], `${worst.label.toLowerCase()} one`, `${worst.label.toLowerCase()} ones`)}: ${worst.advice.toLowerCase()}.`,
          ),
          baselined ? h("p", { class: "note" }, `${plural(baselined, "problem")} from the earlier report ${baselined === 1 ? "is" : "are"} hidden.`) : null,
        ),
      ),
    );
  }
  return banners;
}

function severitySection(prepared, go) {
  const shown = SEVERITIES.filter((s) => s.id !== "unknown" || prepared.bySeverity.unknown);
  return h(
    "section",
    { class: "section", "aria-labelledby": "sev-head" },
    h("div", { class: "section-head" }, h("h2", { id: "sev-head" }, "How serious"), h("p", {}, "Select one to see those problems.")),
    h(
      "div",
      { class: "severity-grid" },
      shown.map((s) => {
        const n = prepared.bySeverity[s.id] ?? 0;
        return h(
          "button",
          {
            type: "button",
            class: `sev-card sev-${s.id}${n ? "" : " zero"}`,
            disabled: n === 0,
            onclick: () => go.findings({ severities: [s.id] }),
            "aria-label": `${plural(n, `${s.label} problem`)}. ${s.advice}. ${s.text}`,
          },
          h("div", { class: "top" }, h("span", { class: "label" }, s.label), h("span", { class: "num" }, n.toLocaleString())),
          h("span", { class: "advice" }, s.advice),
          h("span", { class: "text" }, s.text),
        );
      }),
    ),
  );
}

function categorySection(prepared, go) {
  const analyzers = new Map((prepared.raw.analyzers ?? []).map((a) => [a.analyzer, a]));
  const max = Math.max(1, ...Object.values(prepared.byCategory));
  const rows = CATEGORIES.filter((c) => c.id !== "ai" || prepared.byCategory.ai || analyzers.get("ai")?.state === "completed").map((c) => {
    const n = prepared.byCategory[c.id] ?? 0;
    const states = CATEGORY_ANALYZERS[c.id].map((id) => analyzers.get(id)?.state);
    let note = null;
    if (n === 0) {
      if (states.includes("failed")) note = "Check failed";
      else if (states.every((s) => s !== "completed")) note = "Not checked";
      else note = "None found";
    }
    const fill = h("div", { class: "bar-track", "aria-hidden": "true" });
    if (n) {
      for (const s of SEVERITIES) {
        const count = prepared.findings.filter((f) => f.category === c.id && f.severity === s.id).length;
        if (!count) continue;
        const seg = h("div", { class: `bar-fill sev-${s.id}`, title: `${count} ${s.label}` });
        seg.style.width = `${(count / max) * 100}%`;
        fill.append(seg);
      }
    }
    return h(
      "button",
      { type: "button", class: "bar-row", disabled: n === 0, onclick: () => go.findings({ category: c.id }) },
      h("span", { class: "name" }, c.label, h("span", { class: "desc" }, c.text)),
      fill,
      h("span", { class: "num" }, n ? n.toLocaleString() : h("span", { class: "muted" }, note)),
    );
  });
  return h(
    "section",
    { class: "section", "aria-labelledby": "cat-head" },
    h("div", { class: "section-head" }, h("h2", { id: "cat-head" }, "What kind of problems")),
    h("div", { class: "card bars" }, rows),
  );
}

function sevCounts(bySeverity) {
  return h(
    "div",
    { class: "sev-counts" },
    SEVERITIES.filter((s) => bySeverity[s.id]).map((s) =>
      h("span", { class: `badge sev-${s.id}`, title: s.label }, `${bySeverity[s.id].toLocaleString()} ${s.label.toLowerCase()}`),
    ),
  );
}

function repositorySection(prepared, go) {
  const rows = repositoryRows(prepared);
  const clean = rows.filter((r) => !r.error && Object.keys(r.bySeverity).length === 0).length;
  return h(
    "section",
    { class: "section", "aria-labelledby": "repo-head" },
    h(
      "div",
      { class: "section-head" },
      h("h2", { id: "repo-head" }, "Repositories"),
      h("p", {}, `${plural(rows.length, "repository", "repositories")} scanned, worst first. ${clean ? `${clean.toLocaleString()} with nothing found.` : ""}`),
    ),
    h(
      "div",
      { class: "card table-wrap" },
      h(
        "table",
        { class: "data" },
        h("thead", {}, h("tr", {}, h("th", {}, "Repository"), h("th", {}, "Problems"), h("th", { class: "num" }, "Total"))),
        h(
          "tbody",
          {},
          rows.map((r) => {
            const total = Object.values(r.bySeverity).reduce((a, b) => a + b, 0);
            const open = () => go.findings({ repository: r.name });
            return h(
              "tr",
              {
                class: r.error || total ? "clickable" : null,
                tabindex: r.error || total ? 0 : null,
                onclick: total ? open : r.error ? () => go.coverage() : null,
                onkeydown: (e) => {
                  if (e.key === "Enter" && (total || r.error)) (total ? open : go.coverage)();
                },
              },
              h("td", {}, h("span", { class: "f-repo" }, r.name)),
              h(
                "td",
                {},
                r.error
                  ? h("span", { class: "state failed" }, icon("xCircle"), "Couldn't be scanned")
                  : total
                    ? sevCounts(r.bySeverity)
                    : h("span", { class: "state ok" }, icon("checkCircle"), "Nothing found"),
              ),
              h("td", { class: "num" }, r.error ? "—" : total.toLocaleString()),
            );
          }),
        ),
      ),
    ),
  );
}

function factsSection(prepared) {
  const r = prepared.raw;
  const s = r.stats ?? {};
  const facts = [
    ["Scanned", formatDate(r.started_at)],
    ["Took", formatDuration(s.duration_ms ?? 0)],
    prepared.multi ? ["Repositories", prepared.repositories.length.toLocaleString()] : null,
    ["Files checked", (s.files_scanned ?? 0).toLocaleString()],
    ["Lines of code", (s.lines_scanned ?? 0).toLocaleString()],
    ["Dependencies checked", (s.dependencies_scanned ?? 0).toLocaleString()],
    s.files_skipped ? ["Files not fully checked", `${s.files_skipped.toLocaleString()} (see Coverage)`] : null,
    s.findings_suppressed ? ["Silenced in the code", `${s.findings_suppressed.toLocaleString()} (ghaudit:ignore comments)`] : null,
    r.commit ? ["Commit", r.commit.slice(0, 12)] : null,
    ["Scanner", `${r.tool} ${r.version}`],
  ].filter(Boolean);
  const notRun = (r.analyzers ?? []).filter((a) => a.state === "skipped").map((a) => ANALYZER[a.analyzer]?.label ?? a.analyzer);
  return h(
    "section",
    { class: "section", "aria-labelledby": "facts-head" },
    h("div", { class: "section-head" }, h("h2", { id: "facts-head" }, "About this scan")),
    h(
      "div",
      { class: "card" },
      h(
        "dl",
        { class: "facts facts-card" },
        facts.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
        notRun.length ? [h("dt", {}, "Not run"), h("dd", {}, notRun.join(", "))] : null,
      ),
    ),
  );
}

