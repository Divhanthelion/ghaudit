// The Coverage tab: what was checked, what wasn't, and why. A security report is only
// as good as its coverage, so gaps are listed here rather than hidden.

import { h, icon, plural } from "./dom.js";
import { ANALYZERS, ANALYZER_STATE, analyzerLabel } from "./explain.js";

const MAX_ROWS = 1000;

export function renderCoverage(prepared) {
  const r = prepared.raw;
  return h(
    "div",
    { class: "page" },
    checksSection(r),
    prepared.multi ? repositoryProblems(prepared) : null,
    skippedSection(r, prepared.multi),
    leftOutSection(r, prepared.multi),
  );
}

function stateCell(a) {
  const s = ANALYZER_STATE[a?.state] ?? ANALYZER_STATE.skipped;
  return h("span", { class: `state ${s.cls}` }, icon(s.icon), a ? s.label : "Not in report");
}

function checksSection(r) {
  const byId = new Map((r.analyzers ?? []).map((a) => [a.analyzer, a]));
  const ids = [...ANALYZERS.map((a) => a.id), ...[...byId.keys()].filter((id) => !ANALYZERS.some((a) => a.id === id))];
  return h(
    "section",
    { class: "section", "aria-labelledby": "checks-head" },
    h(
      "div",
      { class: "section-head" },
      h("h2", { id: "checks-head" }, "Checks"),
      h("p", {}, "“Not run” checks found nothing because they didn't look, and “failed” ones may have missed problems."),
    ),
    h(
      "div",
      { class: "card table-wrap" },
      h(
        "table",
        { class: "data" },
        h("thead", {}, h("tr", {}, h("th", {}, "Check"), h("th", {}, "Status"), h("th", {}, "Details"))),
        h(
          "tbody",
          {},
          ids.map((id) => {
            const a = byId.get(id);
            const info = ANALYZERS.find((x) => x.id === id);
            return h(
              "tr",
              {},
              h("td", {}, h("b", {}, analyzerLabel(id)), info ? h("div", { class: "muted" }, info.text) : null),
              h("td", {}, stateCell(a)),
              h("td", {}, a?.detail === "disabled" ? "Turned off for this scan" : (a?.detail ?? "")),
            );
          }),
        ),
      ),
    ),
  );
}

function repositoryProblems(prepared) {
  const rows = [];
  for (const repo of prepared.repositories) {
    if (repo.error) rows.push([repo.name, "Whole repository", "failed", repo.error]);
    for (const a of repo.analyzers ?? []) {
      if (a.state === "failed") rows.push([repo.name, analyzerLabel(a.analyzer), "failed", a.detail ?? ""]);
      else if (a.state === "completed" && /incomplete|warning/i.test(a.detail ?? "")) {
        rows.push([repo.name, analyzerLabel(a.analyzer), "note", a.detail]);
      }
    }
  }
  return h(
    "section",
    { class: "section", "aria-labelledby": "repo-problems-head" },
    h(
      "div",
      { class: "section-head" },
      h("h2", { id: "repo-problems-head" }, "Repositories"),
      h(
        "p",
        {},
        rows.length
          ? "Repositories that couldn't be scanned in full, and warnings worth reading."
          : `All ${plural(prepared.repositories.length, "repository", "repositories")} were scanned in full.`,
      ),
    ),
    rows.length
      ? h(
          "div",
          { class: "card table-wrap" },
          h(
            "table",
            { class: "data" },
            h("thead", {}, h("tr", {}, h("th", {}, "Repository"), h("th", {}, "Check"), h("th", {}, "What happened"))),
            h(
              "tbody",
              {},
              rows.map(([repo, check, kind, detail]) =>
                h(
                  "tr",
                  {},
                  h("td", {}, h("span", { class: "f-repo" }, repo)),
                  h("td", {}, check),
                  h(
                    "td",
                    {},
                    kind === "failed" ? h("span", { class: "state failed" }, icon("xCircle"), "Failed") : h("span", { class: "state skipped" }, icon("info"), "Note"),
                    h("div", {}, detail),
                  ),
                ),
              ),
            ),
          ),
        )
      : null,
  );
}

function skippedSection(r, multi) {
  const skipped = r.skipped ?? [];
  return h(
    "section",
    { class: "section", "aria-labelledby": "skipped-head" },
    h(
      "div",
      { class: "section-head" },
      h("h2", { id: "skipped-head" }, "Files not fully checked"),
      h(
        "p",
        {},
        skipped.length
          ? "Too large, generated, or too slow to analyze. Problems in these files may be missing."
          : "Every file was checked.",
      ),
    ),
    skipped.length
      ? h(
          "div",
          { class: "card table-wrap" },
          h(
            "table",
            { class: "data" },
            h("thead", {}, h("tr", {}, multi ? h("th", {}, "Repository") : null, h("th", {}, "File"), h("th", {}, "Why"))),
            h(
              "tbody",
              {},
              skipped.slice(0, MAX_ROWS).map((s) =>
                h(
                  "tr",
                  {},
                  multi ? h("td", {}, h("span", { class: "f-repo" }, s.repository ?? "")) : null,
                  h("td", {}, h("span", { class: "f-loc" }, s.path)),
                  h("td", {}, skipReason(s.reason)),
                ),
              ),
            ),
          ),
          skipped.length > MAX_ROWS ? h("p", { class: "note more" }, `and ${(skipped.length - MAX_ROWS).toLocaleString()} more (export the report to see them all)`) : null,
        )
      : null,
  );
}

function megabytes(bytes) {
  return `${(Number(bytes) / (1024 * 1024)).toLocaleString(undefined, { maximumFractionDigits: 1 })} MB`;
}

/** "2056643 bytes, over max_file_size (1048576)" → "2 MB, over the 1 MB limit" */
function skipReason(reason) {
  const size = /^(\d+) bytes, over max_file_size \((\d+)\)$/.exec(reason ?? "");
  return size ? `${megabytes(size[1])}, over the ${megabytes(size[2])} size limit` : reason;
}

function leftOutSection(r, multi) {
  const stats = r.stats ?? {};
  const omitted = r.omitted ?? [];
  const items = [];
  if (stats.findings_omitted) {
    items.push(
      h(
        "li",
        {},
        `${plural(stats.findings_omitted, "repeat")} of the same problem in the same file ${stats.findings_omitted === 1 ? "was" : "were"} counted but not listed (a rule reports at most 25 per file).`,
      ),
    );
  }
  if (stats.findings_suppressed) {
    items.push(h("li", {}, `${plural(stats.findings_suppressed, "finding")} silenced by ghaudit:ignore comments in the code.`));
  }
  if (stats.findings_baselined) {
    items.push(h("li", {}, `${plural(stats.findings_baselined, "finding")} hidden because ${stats.findings_baselined === 1 ? "it was" : "they were"} already in the earlier report.`));
  }
  return h(
    "section",
    { class: "section", "aria-labelledby": "left-out-head" },
    h("div", { class: "section-head" }, h("h2", { id: "left-out-head" }, "Findings left out"), items.length ? null : h("p", {}, "None: every finding is listed.")),
    items.length ? h("div", { class: "card" }, h("ul", { class: "plain-list" }, items)) : null,
    omitted.length
      ? h(
          "div",
          { class: "card table-wrap" },
          h(
            "table",
            { class: "data" },
            h("thead", {}, h("tr", {}, multi ? h("th", {}, "Repository") : null, h("th", {}, "File"), h("th", {}, "Rule"), h("th", { class: "num" }, "Not listed"))),
            h(
              "tbody",
              {},
              omitted.slice(0, MAX_ROWS).map((o) =>
                h(
                  "tr",
                  {},
                  multi ? h("td", {}, h("span", { class: "f-repo" }, o.repository ?? "")) : null,
                  h("td", {}, h("span", { class: "f-loc" }, o.path)),
                  h("td", {}, h("span", { class: "mono" }, o.rule_id)),
                  h("td", { class: "num" }, o.count.toLocaleString()),
                ),
              ),
            ),
          ),
        )
      : null,
  );
}
