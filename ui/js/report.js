// Derived views of a ghaudit report (the JSON written by `ghaudit -f json`).
// Pure functions: no DOM, so they can be tested on their own.

import { SEVERITY_RANK } from "./explain.js";

/**
 * Wrap a report for display: findings get a stable `id` (their index), and the
 * repository list, counts and coverage gaps are worked out once.
 */
export function prepare(report) {
  const findings = (report.findings ?? []).map((f, id) => ({ ...f, id }));
  const repositories = report.repositories ?? [];
  const multi = repositories.length > 0;
  const commits = new Map(repositories.map((r) => [r.name, r.commit]));
  return {
    raw: report,
    findings,
    repositories,
    multi,
    commits,
    settings: report.settings ?? [],
    bySeverity: countBy(findings, (f) => f.severity),
    byCategory: countBy(findings, (f) => f.category),
    failures: failures(report),
    /** `owner/name` when the whole report is about one GitHub repository. */
    singleRepo: singleRepository(report),
  };
}

function countBy(items, key) {
  const counts = {};
  for (const item of items) counts[key(item)] = (counts[key(item)] ?? 0) + 1;
  return counts;
}

/**
 * What didn't get checked: failed analyzers and repositories that couldn't be scanned
 * (as `ScanReport::failures` in the library). A report with any of these is incomplete
 * and must never be presented as clean.
 */
export function failures(report) {
  const out = [];
  for (const a of report.analyzers ?? []) {
    if (a.state === "failed") out.push({ repository: null, analyzer: a.analyzer, detail: a.detail ?? "failed" });
  }
  for (const repo of report.repositories ?? []) {
    if (repo.error) out.push({ repository: repo.name, analyzer: null, detail: repo.error });
    for (const a of repo.analyzers ?? []) {
      if (a.state === "failed") out.push({ repository: repo.name, analyzer: a.analyzer, detail: a.detail ?? "failed" });
    }
  }
  return out;
}

const OWNER_REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;

function singleRepository(report) {
  if ((report.repositories ?? []).length > 0) return null;
  return OWNER_REPO.test(report.target ?? "") ? report.target : null;
}

/** The GitHub repository a finding belongs to, if known. */
export function repositoryOf(prepared, finding) {
  return finding.repository ?? prepared.singleRepo;
}

function encodePath(path) {
  return path.split("/").map(encodeURIComponent).join("/");
}

/**
 * Links for a finding: the file on GitHub at the scanned (or, for history findings,
 * the adding) commit, and the commit itself. Only for github.com repositories with a
 * known commit; local directories have no link.
 */
export function githubLinks(prepared, finding) {
  const repo = repositoryOf(prepared, finding);
  if (!repo || !OWNER_REPO.test(repo) || finding.category === "settings") return {};
  const commit = finding.commit ?? (finding.repository ? prepared.commits.get(finding.repository) : prepared.raw.commit);
  if (!commit || !/^[0-9a-f]{7,64}$/i.test(commit)) return {};
  const base = `https://github.com/${repo}`;
  const line = finding.location?.start_line;
  return {
    file: `${base}/blob/${commit}/${encodePath(finding.location.path)}${line ? `#L${line}` : ""}`,
    commit: finding.commit ? `${base}/commit/${commit}` : null,
  };
}

// ------------------------------------------------------------------ filtering and sorting

/** Lower-cased text a search matches against. */
function haystack(f) {
  return [
    f.title,
    f.message,
    f.rule_id,
    f.location?.path,
    f.repository,
    f.dependency?.package,
    f.dependency?.advisory,
    ...(f.dependency?.aliases ?? []),
    ...(f.cwe ?? []),
  ]
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
}

/**
 * filters: { text, severities: Set (empty = all), category, repository, onlyIds: Set|null }
 */
export function filterFindings(findings, filters) {
  const words = (filters.text ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  return findings.filter((f) => {
    if (filters.severities?.size && !filters.severities.has(f.severity)) return false;
    if (filters.category && f.category !== filters.category) return false;
    if (filters.repository && f.repository !== filters.repository) return false;
    if (words.length) {
      f._haystack ??= haystack(f);
      if (!words.every((w) => f._haystack.includes(w))) return false;
    }
    return true;
  });
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

function location(f) {
  return `${f.location?.path ?? ""}:${String(f.location?.start_line ?? 0).padStart(8, "0")}`;
}

const SORT_KEYS = {
  severity: (a, b) => (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0),
  category: (a, b) => collator.compare(a.category, b.category),
  rule: (a, b) => collator.compare(a.title, b.title) || collator.compare(a.rule_id, b.rule_id),
  repository: (a, b) => collator.compare(a.repository ?? "", b.repository ?? ""),
  location: (a, b) => collator.compare(location(a), location(b)),
};

/**
 * Sort by `key` (asc or desc), then most severe, repository and location, so equal
 * keys keep a sensible order. `group` (a Map of repository name to position) keeps each
 * repository's findings together, in that order.
 */
export function sortFindings(findings, { key = "severity", dir = "desc", group = null } = {}) {
  const primary = SORT_KEYS[key] ?? SORT_KEYS.severity;
  const sign = dir === "asc" ? 1 : -1;
  const groupOf = (f) => group?.get(f.repository) ?? Number.MAX_SAFE_INTEGER;
  return [...findings].sort(
    (a, b) =>
      (group ? groupOf(a) - groupOf(b) || SORT_KEYS.repository(a, b) : 0) ||
      sign * primary(a, b) ||
      -SORT_KEYS.severity(a, b) ||
      SORT_KEYS.repository(a, b) ||
      SORT_KEYS.location(a, b) ||
      a.id - b.id,
  );
}

/** Repositories with their findings by severity, worst first. */
export function repositoryRows(prepared) {
  const rows = prepared.repositories.map((r) => ({ ...r, bySeverity: {}, worst: 0 }));
  const byName = new Map(rows.map((r) => [r.name, r]));
  for (const f of prepared.findings) {
    const row = byName.get(f.repository);
    if (!row) continue;
    row.bySeverity[f.severity] = (row.bySeverity[f.severity] ?? 0) + 1;
    row.worst = Math.max(row.worst, SEVERITY_RANK[f.severity] ?? 0);
  }
  const score = (r) => Object.entries(r.bySeverity).map(([s, n]) => [SEVERITY_RANK[s] ?? 0, n]).sort((a, b) => b[0] - a[0]);
  return rows.sort((a, b) => {
    if (!!a.error !== !!b.error) return a.error ? -1 : 1;
    const sa = score(a);
    const sb = score(b);
    for (let i = 0; i < Math.max(sa.length, sb.length); i++) {
      const [ra, na] = sa[i] ?? [0, 0];
      const [rb, nb] = sb[i] ?? [0, 0];
      if (ra !== rb) return rb - ra;
      if (na !== nb) return nb - na;
    }
    return collator.compare(a.name, b.name);
  });
}
