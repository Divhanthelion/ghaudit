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
    /// Risky AI-agent or editor configuration committed to the repository
    /// (MCP servers, auto-approval, commands run on open).
    Agent,
    /// A repository or organization security setting, read from the GitHub API.
    Settings,
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
            Category::Agent => "agent",
            Category::Settings => "settings",
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
///
/// Backslashes are separators only on Windows. Elsewhere they are ordinary file-name
/// characters, and rewriting them would let a file named `src\\app.py` pose as
/// `src/app.py`.
pub fn normalize_path(path: &str) -> String {
    let p = if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    p.strip_prefix("./").unwrap_or(&p).to_string()
}

/// Line lookups for one file: built once, then each position or line costs
/// O(log n) or O(1) instead of a scan from the start of the file.
pub struct LineIndex<'a> {
    text: &'a str,
    /// Byte offset where each line starts.
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    pub fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        // Like `str::lines`, a trailing newline does not start another line.
        if starts.len() > 1 && starts.last() == Some(&text.len()) {
            starts.pop();
        }
        Self { text, starts }
    }

    pub fn text(&self) -> &'a str {
        self.text
    }

    /// Number of lines, counted like `str::lines`.
    pub fn len(&self) -> usize {
        if self.text.is_empty() {
            0
        } else {
            self.starts.len()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The 1-based `line`, without its line terminator.
    pub fn line(&self, line: usize) -> Option<&'a str> {
        let i = line.checked_sub(1)?;
        if i >= self.len() {
            return None;
        }
        let start = self.starts[i];
        let end = self.starts.get(i + 1).copied().unwrap_or(self.text.len());
        let s = &self.text[start..end];
        let s = s.strip_suffix('\n').unwrap_or(s);
        Some(s.strip_suffix('\r').unwrap_or(s))
    }

    /// 1-based (line, column) of a byte offset. The column counts characters.
    pub fn position(&self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.text.len());
        let i = self
            .starts
            .partition_point(|&s| s <= offset)
            .saturating_sub(1);
        let col = self.text[self.starts[i]..offset].chars().count() + 1;
        (i + 1, col)
    }

    /// Byte offset of a 1-based line and a 0-based character column.
    pub fn offset(&self, line: usize, char_col: usize) -> Option<usize> {
        let text = self.line(line)?;
        let start = self.starts[line - 1];
        let within = text
            .char_indices()
            .nth(char_col)
            .map_or(text.len(), |(b, _)| b);
        Some(start + within)
    }
}

/// Characters of one snippet line kept while analyzers run. Generous, so that secret
/// redaction (which runs afterwards) sees whole values; [`Snippet::clip`] then
/// shortens lines for display.
const WORKING_LINE_CHARS: usize = 4096;
/// Characters of one snippet line in a report.
pub const DISPLAY_LINE_CHARS: usize = 200;

/// A few lines of source around a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    /// Line number of the first entry in `lines`.
    pub first_line: usize,
    pub lines: Vec<String>,
    /// Characters cut from the start of the finding's line by [`Snippet::from_index`],
    /// so [`Snippet::clip`] can still find the column.
    #[serde(skip)]
    shift: usize,
}

impl Snippet {
    /// Take `context` lines on each side of the 1-based `line`.
    /// Builds a [`LineIndex`]; analyzers that create many snippets should build one
    /// index per file and call [`Snippet::from_index`].
    pub fn around(content: &str, line: usize, context: usize) -> Option<Self> {
        Self::from_index(&LineIndex::new(content), line, 1, context)
    }

    /// Take `context` lines on each side of the 1-based `line`. Very long lines (minified
    /// code) are cut to a window around `column` on the finding's line, and to their
    /// start on context lines.
    pub fn from_index(
        index: &LineIndex,
        line: usize,
        column: usize,
        context: usize,
    ) -> Option<Self> {
        if line == 0 || line > index.len() {
            return None;
        }
        let first = line.saturating_sub(context).max(1);
        let last = (line + context).min(index.len());
        let mut shift = 0;
        let lines = (first..=last)
            .map(|n| {
                let text = index.line(n).unwrap_or_default();
                if n != line {
                    return window(text, 1, WORKING_LINE_CHARS).0;
                }
                let (cut, start) = window(text, column, WORKING_LINE_CHARS);
                shift = start;
                cut
            })
            .collect();
        Some(Self {
            first_line: first,
            lines,
            shift,
        })
    }

    /// Shorten lines for display (after secrets have been redacted). The line holding
    /// the finding keeps the part around `column`.
    pub fn clip(&mut self, line: usize, column: usize) {
        for (i, text) in self.lines.iter_mut().enumerate() {
            let focus = if self.first_line + i != line {
                1
            } else if self.shift > 0 {
                // Past the leading `…` of the working window.
                column.saturating_sub(self.shift) + 1
            } else {
                column
            };
            if text.chars().count() > DISPLAY_LINE_CHARS {
                *text = window(text, focus, DISPLAY_LINE_CHARS).0;
            }
        }
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

/// At most `max` characters of `text`, around the 1-based character `column`, with `…`
/// marking each cut. Also returns how many characters were cut from the start.
fn window(text: &str, column: usize, max: usize) -> (String, usize) {
    let total = text.chars().count();
    if total <= max {
        return (text.to_string(), 0);
    }
    let start = column
        .saturating_sub(1)
        .saturating_sub(max / 4)
        .min(total - max);
    let mut out = String::new();
    if start > 0 {
        out.push('…');
    }
    out.extend(text.chars().skip(start).take(max));
    if start + max < total {
        out.push('…');
    }
    (out, start)
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
    /// Where to fix it, when that is a web page rather than a file (settings findings).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub help_url: Option<String>,
    /// The commit that added it, when found in git history rather than the current files.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub commit: Option<String>,
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
            help_url: None,
            commit: None,
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

    /// Recompute the fingerprint from a new basis (see [`Finding::new`]).
    pub fn refingerprint(&mut self, basis: &str) {
        self.fingerprint = fingerprint(&[&self.rule_id, &self.location.path, basis.trim()]);
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
    /// Files that were not (fully) analyzed; listed in [`ScanReport::skipped`].
    #[serde(default)]
    pub files_skipped: usize,
    /// Findings silenced by `ghaudit:ignore` comments.
    #[serde(default)]
    pub findings_suppressed: usize,
    /// Repeats of one rule in one file beyond the per-file limit; see [`ScanReport::omitted`].
    #[serde(default)]
    pub findings_omitted: usize,
    /// Findings left out because they are in the `--baseline` report.
    #[serde(default)]
    pub findings_baselined: usize,
    /// Findings per severity after filtering.
    pub by_severity: HashMap<Severity, usize>,
    /// Findings per category after filtering.
    pub by_category: HashMap<Category, usize>,
    pub duration_ms: u64,
}

/// Result of one settings check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    /// The token cannot read the setting (usually: it lacks admin access). Never
    /// counted as a pass.
    NotAssessable,
}

/// One security setting of a repository or organization, checked through the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsCheck {
    /// `owner/name`, or `org:name` for organization settings.
    pub target: String,
    /// Rule ID of the check, e.g. `settings/default-branch-unprotected`.
    pub check: String,
    pub status: CheckStatus,
    /// Why it failed or could not be assessed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

/// A file that was not (fully) analyzed, and why. Listed so that a report never looks
/// cleaner than the scan was: a hostile repository could otherwise hide code in files
/// the scanner quietly passed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub path: String,
    pub reason: String,
}

/// Findings left out because one rule fired too often in one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Omitted {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub path: String,
    pub rule_id: String,
    pub count: usize,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub skipped: Vec<SkippedFile>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub omitted: Vec<Omitted>,
    /// Every settings check run, with its outcome. Failures are also findings.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub settings: Vec<SettingsCheck>,
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
            skipped: Vec::new(),
            omitted: Vec::new(),
            settings: Vec::new(),
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
        self.recount();
    }

    /// Leave out findings that are also in `baseline` (same fingerprint, same
    /// repository), so the report and the exit code cover only new findings.
    /// Fingerprints follow line content, not line numbers, so moved code still matches.
    pub fn apply_baseline(&mut self, baseline: &ScanReport) {
        let known: std::collections::HashSet<(Option<&str>, &str)> = baseline
            .findings
            .iter()
            .map(|f| (f.repository.as_deref(), f.fingerprint.as_str()))
            .collect();
        let before = self.findings.len();
        self.findings
            .retain(|f| !known.contains(&(f.repository.as_deref(), f.fingerprint.as_str())));
        self.stats.findings_baselined = before - self.findings.len();
        self.recount();
    }

    fn recount(&mut self) {
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
        let expected = if cfg!(windows) {
            "src/a/b.rs"
        } else {
            "src\\a\\b.rs" // a legal file name, not a path, outside Windows
        };
        assert_eq!(Location::new("src\\a\\b.rs", 0, 0).path, expected);
        assert_eq!(Location::new("./x.py", 3, 2).path, "x.py");
        assert_eq!(Location::new("x.py", 0, 0).start_line, 1);
    }

    #[test]
    fn line_index_matches_str_lines() {
        for text in ["", "a", "a\n", "a\n\n", "a\r\nbé\r\n\nlast", "\n\n"] {
            let index = LineIndex::new(text);
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(index.len(), lines.len(), "{text:?}");
            for (i, l) in lines.iter().enumerate() {
                assert_eq!(index.line(i + 1), Some(*l), "{text:?} line {}", i + 1);
            }
            assert_eq!(index.line(lines.len() + 1), None);
        }
        let index = LineIndex::new("ab\ncé = x\n");
        assert_eq!(index.position(0), (1, 1));
        assert_eq!(index.position(3), (2, 1));
        // `x` is the 6th character of line 2 but its 7th byte.
        assert_eq!(index.position(9), (2, 6));
        assert_eq!(index.offset(2, 5), Some(9));
    }

    #[test]
    fn long_lines_are_windowed_around_the_finding() {
        let line = format!("{}eval(x){}", "a".repeat(10_000), "b".repeat(10_000));
        let index = LineIndex::new(&line);
        let mut s = Snippet::from_index(&index, 1, 10_001, 2).unwrap();
        assert!(s.lines[0].contains("eval(x)"));
        assert!(s.lines[0].chars().count() <= WORKING_LINE_CHARS + 2);
        s.clip(1, 10_001);
        assert!(s.lines[0].contains("eval(x)"), "{}", s.lines[0]);
        assert!(s.lines[0].starts_with('…') && s.lines[0].ends_with('…'));
        assert!(s.lines[0].chars().count() <= DISPLAY_LINE_CHARS + 2);
        assert_eq!(window("short", 3, 10), ("short".to_string(), 0));
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
    fn baseline_keeps_only_new_findings() {
        let mut old = ScanReport::new("t");
        old.findings
            .push(finding(Severity::High, "a.py", 3, "eval(x)"));
        old.finalize(Severity::Low);
        let mut new = ScanReport::new("t");
        // The same issue, moved to another line, and a new one.
        new.findings
            .push(finding(Severity::High, "a.py", 40, "eval(x)"));
        new.findings
            .push(finding(Severity::Critical, "a.py", 41, "pickle.loads(d)"));
        new.finalize(Severity::Low);
        new.apply_baseline(&old);
        assert_eq!(new.findings.len(), 1);
        assert_eq!(new.findings[0].location.start_line, 41);
        assert_eq!(new.stats.findings_baselined, 1);
        assert_eq!(new.stats.by_severity.get(&Severity::High), None);
        assert_eq!(new.count_at_least(Severity::High), 1);
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
