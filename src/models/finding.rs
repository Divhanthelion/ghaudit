//! Security finding data models.

use super::{Language, Severity, Vulnerability};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a security finding discovered during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID
    pub id: String,

    /// Finding category
    pub category: FindingCategory,

    /// Severity level
    pub severity: Severity,

    /// Short title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Location of the finding
    pub location: Location,

    /// Source code snippet (if available)
    pub snippet: Option<CodeSnippet>,

    /// Related vulnerability (for SCA findings)
    pub vulnerability: Option<Vulnerability>,

    /// Confidence level
    pub confidence: Confidence,

    /// Rule or query that triggered this finding
    pub rule_id: String,

    /// Suggested fix or remediation
    pub remediation: Option<String>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,

    /// Timestamp when finding was discovered
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

impl Finding {
    /// Create a new SAST finding.
    pub fn sast(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        location: Location,
        severity: Severity,
    ) -> Self {
        Self {
            id: uuid_v4(),
            category: FindingCategory::Sast(SastCategory::Other),
            severity,
            title: title.into(),
            description: description.into(),
            location,
            snippet: None,
            vulnerability: None,
            confidence: Confidence::Medium,
            rule_id: rule_id.into(),
            remediation: None,
            metadata: std::collections::HashMap::new(),
            discovered_at: chrono::Utc::now(),
        }
    }

    /// Create a new SCA finding.
    pub fn sca(vulnerability: Vulnerability, dependency: &str, version: &str) -> Self {
        Self {
            id: uuid_v4(),
            category: FindingCategory::Sca,
            severity: vulnerability.severity,
            title: format!(
                "Vulnerable dependency: {} {} ({})",
                dependency, version, vulnerability.id
            ),
            description: vulnerability.summary.clone(),
            location: Location {
                file: PathBuf::from("Cargo.lock"),
                start_line: 0,
                end_line: 0,
                start_column: 0,
                end_column: 0,
                language: None,
            },
            snippet: None,
            vulnerability: Some(vulnerability),
            confidence: Confidence::High,
            rule_id: "sca/vulnerable-dependency".to_string(),
            remediation: None,
            metadata: std::collections::HashMap::new(),
            discovered_at: chrono::Utc::now(),
        }
    }

    /// Set the SAST category.
    pub fn with_sast_category(mut self, category: SastCategory) -> Self {
        self.category = FindingCategory::Sast(category);
        self
    }

    /// Set the code snippet.
    pub fn with_snippet(mut self, snippet: CodeSnippet) -> Self {
        self.snippet = Some(snippet);
        self
    }

    /// Set the confidence level.
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Set remediation advice.
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Categories of findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum FindingCategory {
    /// Static Application Security Testing finding
    Sast(SastCategory),

    /// Software Composition Analysis finding
    Sca,

    /// Supply chain / provenance finding
    Provenance,

    /// AI-detected finding
    Ai,

    /// Configuration issue
    Config,

    /// Secret detection
    Secret,
}

/// SAST finding subcategories.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SastCategory {
    /// Unsafe code usage
    UnsafeCode,

    /// Memory safety issue
    MemorySafety,

    /// Injection vulnerability (SQL, command, etc.)
    Injection,

    /// Cross-site scripting
    Xss,

    /// Path traversal
    PathTraversal,

    /// Insecure cryptography
    Crypto,

    /// Authentication/authorization issue
    Auth,

    /// Information disclosure
    InfoDisclosure,

    /// Race condition
    RaceCondition,

    /// Denial of service
    Dos,

    /// Unbounded resource consumption
    UnboundedResource,

    /// Prototype pollution (JavaScript-specific)
    PrototypePollution,

    /// Other/uncategorized
    Other,
}

/// Location of a finding in source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path (relative to repository root)
    pub file: PathBuf,

    /// Start line (1-indexed)
    pub start_line: usize,

    /// End line (1-indexed)
    pub end_line: usize,

    /// Start column (1-indexed)
    pub start_column: usize,

    /// End column (1-indexed)
    pub end_column: usize,

    /// Language of the file
    pub language: Option<Language>,
}

impl Location {
    /// Create a new location.
    pub fn new(file: PathBuf, start_line: usize, start_column: usize) -> Self {
        Self {
            file,
            start_line,
            end_line: start_line,
            start_column,
            end_column: start_column,
            language: None,
        }
    }

    /// Set the end position.
    pub fn with_end(mut self, end_line: usize, end_column: usize) -> Self {
        self.end_line = end_line;
        self.end_column = end_column;
        self
    }

    /// Set the language.
    pub fn with_language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }
}

/// Code snippet for context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSnippet {
    /// Lines of code with line numbers
    pub lines: Vec<(usize, String)>,

    /// Highlighted line (the problematic line)
    pub highlight_line: usize,
}

impl CodeSnippet {
    /// Create a snippet from source content.
    pub fn from_content(content: &str, line: usize, context_lines: usize) -> Self {
        let lines: Vec<&str> = content.lines().collect();
        let start = line.saturating_sub(context_lines + 1);
        let end = (line + context_lines).min(lines.len());

        let snippet_lines = lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| (start + i + 1, l.to_string()))
            .collect();

        Self {
            lines: snippet_lines,
            highlight_line: line,
        }
    }
}

/// Confidence level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
}

/// Scan result for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Repository that was scanned
    pub repository: String,

    /// Commit SHA that was scanned
    pub commit_sha: Option<String>,

    /// All findings
    pub findings: Vec<Finding>,

    /// Scan statistics
    pub stats: ScanStats,

    /// Scan start time
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Scan end time
    pub completed_at: chrono::DateTime<chrono::Utc>,

    /// Whether the scan completed successfully
    pub success: bool,

    /// Error message if scan failed
    pub error: Option<String>,
}

impl ScanResult {
    /// Create a new scan result.
    pub fn new(repository: impl Into<String>) -> Self {
        let now = chrono::Utc::now();
        Self {
            repository: repository.into(),
            commit_sha: None,
            findings: Vec::new(),
            stats: ScanStats::default(),
            started_at: now,
            completed_at: now,
            success: true,
            error: None,
        }
    }

    /// Add a finding.
    pub fn add_finding(&mut self, finding: Finding) {
        match finding.category {
            FindingCategory::Sast(_) => self.stats.sast_findings += 1,
            FindingCategory::Sca => self.stats.sca_findings += 1,
            FindingCategory::Secret => self.stats.secrets_found += 1,
            _ => {}
        }
        self.findings.push(finding);
    }

    /// Get findings by severity.
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == severity).collect()
    }

    /// Get the highest severity finding.
    pub fn max_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::None)
    }
}

/// Statistics about a scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Number of files scanned
    pub files_scanned: usize,

    /// Total lines of code analyzed
    pub lines_analyzed: usize,

    /// Number of SAST findings
    pub sast_findings: usize,

    /// Number of SCA findings
    pub sca_findings: usize,

    /// Number of dependencies checked
    pub dependencies_checked: usize,

    /// Number of secrets found
    pub secrets_found: usize,

    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

/// Generate a proper UUID v4 using cryptographic randomness.
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}
