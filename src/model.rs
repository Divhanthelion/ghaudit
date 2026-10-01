//! Core data types shared by every analyzer and reporter.
//!
//! The flow is: analyzers produce [`Finding`]s, the scanner collects them into a
//! [`ScanReport`] together with per-analyzer status, and reporters render the report.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// How bad a finding is.
///
/// Variants are declared from least to most severe, so the derived ordering can be
/// used for sorting. `Unknown` is used for advisories that carry no severity rating;
/// for filtering and failure thresholds it is treated as `Medium` (see [`Severity::effective`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Unknown,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Severity used when comparing against `--min-severity` / `--fail-on`.
    /// An unrated advisory is still a known vulnerability, so it must never be filtered
    /// out as if it were informational.
    pub fn effective(self) -> Severity {
        match self {
            Severity::Unknown => Severity::Medium,
            other => other,
        }
    }

    /// True when this severity meets the given threshold.
    pub fn at_least(self, threshold: Severity) -> bool {
        self.effective() >= threshold.effective()
    }

    /// Map a CVSS base score (v2, v3 or v4) to a qualitative rating, per the
    /// FIRST CVSS v3.x specification bands.
    pub fn from_cvss_score(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Unknown => "unknown",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// All variants, most severe first.
    pub const DESCENDING: [Severity; 6] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Unknown,
        Severity::Low,
        Severity::Info,
    ];
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str().to_uppercase())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" | "none" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "unknown" => Ok(Severity::Unknown),
            "medium" | "moderate" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity '{other}' (expected info, low, medium, high or critical)"
            )),
        }
    }
}

/// How likely a finding is to be a true positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

/// Which analyzer produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Risky code pattern found by the tree-sitter rule engine.
    Sast,
    /// Hardcoded credential.
    Secret,
    /// Known vulnerability in a third-party dependency (via osv-scanner).
    Dependency,
    /// Insecure GitHub Actions workflow configuration.
    Workflow,
    /// Issue suggested by a language model. Always needs human review.
    Ai,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Sast => "code",
            Category::Secret => "secret",
            Category::Dependency => "dependency",
            Category::Workflow => "workflow",
            Category::Ai => "ai",
        }
    }
}

/// Position of a finding. Paths are relative to the scanned root and always use `/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    /// 1-based line number.
    pub start_line: usize,
    /// 1-based column number.
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl Location {
    pub fn new(path: impl Into<String>, line: usize, column: usize) -> Self {
        let line = line.max(1);
        let column = column.max(1);
        Self {
            path: normalize_path(&path.into()),
            start_line: line,
            start_column: column,
            end_line: line,
            end_column: column,
        }
    }

    pub fn with_end(mut self, line: usize, column: usize) -> Self {
        self.end_line = line.max(self.start_line);
        self.end_column = column.max(1);
        self
    }
}

/// Convert a platform path to the `a/b/c` form used in reports.
pub fn normalize_path(path: &str) -> String {
    let p = path.replace('\\', "/");
    p.strip_prefix("./").unwrap_or(&p).to_string()
}

/// A few lines of source around a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    /// Line number of the first entry in `lines`.
    pub first_line: usize,
    pub lines: Vec<String>,
}

impl Snippet {
    /// Take `context` lines on each side of the 1-based `line`.
    pub fn around(content: &str, line: usize, context: usize) -> Option<Self> {
        let all: Vec<&str> = content.lines().collect();
        if line == 0 || line > all.len() {
            return None;
        }
        let first = line.saturating_sub(context).max(1);
        let last = (line + context).min(all.len());
        Some(Self {
            first_line: first,
            lines: all[first - 1..last].iter().map(|l| l.to_string()).collect(),
        })
    }

    /// Replace every occurrence of `needle` with `replacement` (used to redact secrets).
    pub fn redact(mut self, needle: &str, replacement: &str) -> Self {
        if !needle.is_empty() {
            for line in &mut self.lines {
                *line = line.replace(needle, replacement);
            }
        }
        self
    }
}

/// Extra data attached to dependency findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    /// Primary advisory ID (e.g. `GHSA-...`, `RUSTSEC-...`).
    pub advisory: String,
    /// Other IDs for the same issue (CVE, PYSEC, ...).
    pub aliases: Vec<String>,
    /// Versions that fix the issue, lowest first.
    pub fixed_versions: Vec<String>,
    /// Highest CVSS base score across the advisory's ratings, if any.
    pub cvss_score: Option<f64>,
    pub url: String,
}

/// One reported issue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier: the same issue on the same line content gets the same
    /// fingerprint across runs, even if surrounding lines move.
    pub fingerprint: String,
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub message: String,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<Snippet>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency: Option<DependencyInfo>,
    /// Set when the finding comes from a multi-repository scan (`owner/name`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

impl Finding {
    /// Create a finding. `fingerprint_basis` should identify the issue independently of
    /// line numbers, typically the trimmed text of the offending line.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: impl Into<String>,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: impl Into<String>,
        message: impl Into<String>,
        location: Location,
        fingerprint_basis: &str,
    ) -> Self {
        let rule_id = rule_id.into();
        let fingerprint = fingerprint(&[&rule_id, &location.path, fingerprint_basis.trim()]);
        Self {
            fingerprint,
            rule_id,
            category,
            severity,
            confidence,
            title: title.into(),
            message: message.into(),
            location,
            snippet: None,
            cwe: Vec::new(),
            remediation: None,
            dependency: None,
            repository: None,
        }
    }

    pub fn with_snippet(mut self, snippet: Option<Snippet>) -> Self {
        self.snippet = snippet;
        self
    }

    pub fn with_cwe<I, S>(mut self, cwe: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.cwe = cwe.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
}

/// Hex-encoded SHA-256 (truncated to 128 bits) of the NUL-joined parts.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hasher.update([0u8]);
        }
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Outcome of one analyzer for one scan target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalyzerState {
    Completed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerStatus {
    pub analyzer: String,
    pub state: AnalyzerState,
    /// Why it was skipped/failed, or warnings from a completed run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AnalyzerStatus {
    pub fn completed(analyzer: &str) -> Self {
        Self {
            analyzer: analyzer.into(),
            state: AnalyzerState::Completed,
            detail: None,
        }
    }

    pub fn skipped(analyzer: &str, why: impl Into<String>) -> Self {
        Self {
            analyzer: analyzer.into(),
            state: AnalyzerState::Skipped,
            detail: Some(why.into()),
        }
    }

    pub fn failed(analyzer: &str, why: impl Into<String>) -> Self {
        Self {
            analyzer: analyzer.into(),
            state: AnalyzerState::Failed,
            detail: Some(why.into()),
        }
    }

    pub fn with_detail(mut self, detail: Option<String>) -> Self {
        self.detail = detail;
        self
    }
}

/// Per-repository summary for org/user/search scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositorySummary {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub findings: usize,
    /// Set when the repository could not be cloned or scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub analyzers: Vec<AnalyzerStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub lines_scanned: usize,
    /// Packages osv-scanner checked against the vulnerability database.
    pub dependencies_scanned: usize,
    /// Findings per severity after filtering.
    pub by_severity: HashMap<Severity, usize>,
    /// Findings per category after filtering.
    pub by_category: HashMap<Category, usize>,
    pub duration_ms: u64,
}

/// Everything a reporter needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    /// What was scanned (a path, `owner/name`, `org:...`, ...).
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
    pub stats: ScanStats,
    pub analyzers: Vec<AnalyzerStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub repositories: Vec<RepositorySummary>,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(target: impl Into<String>) -> Self {
        let now = chrono::Utc::now();
        Self {
            tool: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target: target.into(),
            commit: None,
            started_at: now,
            finished_at: now,
            stats: ScanStats::default(),
            analyzers: Vec::new(),
            repositories: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Analyzers or repositories that did not finish. A report with failures must
    /// never be read as "clean".
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .analyzers
            .iter()
            .filter(|a| a.state == AnalyzerState::Failed)
            .map(|a| {
                format!(
                    "{}: {}",
                    a.analyzer,
                    a.detail.as_deref().unwrap_or("failed")
                )
            })
            .collect();
        for repo in &self.repositories {
            if let Some(err) = &repo.error {
                out.push(format!("{}: {}", repo.name, err));
            }
            for a in repo
                .analyzers
                .iter()
                .filter(|a| a.state == AnalyzerState::Failed)
            {
                out.push(format!(
                    "{} ({}): {}",
                    repo.name,
                    a.analyzer,
                    a.detail.as_deref().unwrap_or("failed")
                ));
            }
        }
        out
    }

    pub fn is_complete(&self) -> bool {
        self.failures().is_empty()
    }

    /// Drop findings below `min`, make fingerprints unique, sort, and recompute stats.
    pub fn finalize(&mut self, min: Severity) {
        self.findings.retain(|f| f.severity.at_least(min));

        // Two identical lines in one file would otherwise share a fingerprint.
        let mut seen: HashMap<String, usize> = HashMap::new();
        for f in &mut self.findings {
            let n = seen.entry(f.fingerprint.clone()).or_insert(0);
            if *n > 0 {
                f.fingerprint = fingerprint(&[&f.fingerprint, &n.to_string()]);
            }
            *n += 1;
        }

        // Group by repository (multi-repo scans), then most severe first.
        self.findings.sort_by(|a, b| {
            a.repository
                .cmp(&b.repository)
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| a.location.path.cmp(&b.location.path))
                .then_with(|| a.location.start_line.cmp(&b.location.start_line))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        self.stats.by_severity.clear();
        self.stats.by_category.clear();
        for f in &self.findings {
            *self.stats.by_severity.entry(f.severity).or_insert(0) += 1;
            *self.stats.by_category.entry(f.category).or_insert(0) += 1;
        }
    }

    /// Number of findings at or above `threshold`.
    pub fn count_at_least(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity.at_least(threshold))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, path: &str, line: usize, basis: &str) -> Finding {
        Finding::new(
            "test/rule",
            Category::Sast,
            sev,
            Confidence::High,
            "t",
            "m",
            Location::new(path, line, 1),
            basis,
        )
    }

    #[test]
    fn unknown_severity_is_never_filtered_as_noise() {
        assert!(Severity::Unknown.at_least(Severity::Low));
        assert!(Severity::Unknown.at_least(Severity::Medium));
        assert!(!Severity::Unknown.at_least(Severity::High));
        assert!(!Severity::Info.at_least(Severity::Low));
    }

    #[test]
    fn cvss_bands() {
        assert_eq!(Severity::from_cvss_score(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss_score(7.0), Severity::High);
        assert_eq!(Severity::from_cvss_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_cvss_score(3.1), Severity::Low);
        assert_eq!(Severity::from_cvss_score(0.0), Severity::Info);
    }

    #[test]
    fn severity_parses_ghsa_wording() {
        assert_eq!("MODERATE".parse::<Severity>().unwrap(), Severity::Medium);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn paths_are_normalized() {
        assert_eq!(Location::new("src\\a\\b.rs", 0, 0).path, "src/a/b.rs");
        assert_eq!(Location::new("./x.py", 3, 2).start_line, 3);
        assert_eq!(Location::new("x.py", 0, 0).start_line, 1);
    }

    #[test]
    fn fingerprint_ignores_line_numbers_but_not_content() {
        let a = finding(Severity::High, "a.py", 10, "eval(x)");
        let b = finding(Severity::High, "a.py", 99, "  eval(x)  ");
        let c = finding(Severity::High, "a.py", 10, "eval(y)");
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_ne!(a.fingerprint, c.fingerprint);
    }

    #[test]
    fn finalize_dedupes_fingerprints_filters_and_counts() {
        let mut r = ScanReport::new("t");
        r.findings
            .push(finding(Severity::High, "a.py", 1, "eval(x)"));
        r.findings
            .push(finding(Severity::High, "a.py", 5, "eval(x)"));
        r.findings
            .push(finding(Severity::Info, "a.py", 7, "unsafe"));
        r.findings
            .push(finding(Severity::Critical, "b.py", 2, "pickle"));
        r.finalize(Severity::Low);

        assert_eq!(r.findings.len(), 3);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_ne!(r.findings[1].fingerprint, r.findings[2].fingerprint);
        assert_eq!(r.stats.by_severity[&Severity::High], 2);
        assert_eq!(r.stats.by_category[&Category::Sast], 3);
        assert_eq!(r.count_at_least(Severity::High), 3);
    }

    #[test]
    fn multi_repo_findings_are_grouped_by_repository() {
        let mut r = ScanReport::new("org:x");
        for (repo, sev) in [
            ("b/b", Severity::Critical),
            ("a/a", Severity::Low),
            ("b/b", Severity::Low),
            ("a/a", Severity::High),
        ] {
            let mut f = finding(sev, "x.py", 1, &format!("{repo}{sev}"));
            f.repository = Some(repo.into());
            r.findings.push(f);
        }
        r.finalize(Severity::Low);
        let order: Vec<(&str, Severity)> = r
            .findings
            .iter()
            .map(|f| (f.repository.as_deref().unwrap(), f.severity))
            .collect();
        assert_eq!(
            order,
            vec![
                ("a/a", Severity::High),
                ("a/a", Severity::Low),
                ("b/b", Severity::Critical),
                ("b/b", Severity::Low)
            ]
        );
    }

    #[test]
    fn snippet_bounds() {
        let content = "a\nb\nc\nd\ne";
        let s = Snippet::around(content, 1, 2).unwrap();
        assert_eq!((s.first_line, s.lines.len()), (1, 3));
        let s = Snippet::around(content, 5, 1).unwrap();
        assert_eq!(
            (s.first_line, s.lines.clone()),
            (4, vec!["d".to_string(), "e".to_string()])
        );
        assert!(Snippet::around(content, 9, 1).is_none());
    }

    #[test]
    fn failures_include_repo_errors() {
        let mut r = ScanReport::new("org:x");
        r.analyzers.push(AnalyzerStatus::completed("sast"));
        assert!(r.is_complete());
        r.repositories.push(RepositorySummary {
            name: "x/y".into(),
            commit: None,
            findings: 0,
            error: Some("clone failed".into()),
            analyzers: vec![],
        });
        assert_eq!(r.failures(), vec!["x/y: clone failed".to_string()]);
    }
}
