//! Juliet Test Suite benchmark harness for SAST evaluation.
//!
//! The Juliet Test Suite from NIST SAMATE is the de facto standard for
//! evaluating static analysis tools. This module provides:
//! - Test case parsing and categorization (CWE-based)
//! - Ground truth extraction from file naming conventions
//! - Metrics computation (precision, recall, F1, false positive rate)
//! - Benchmark report generation
//!
//! Juliet test case naming convention:
//! - `CWE<num>_<name>__<variant>_<nn>.(c|cpp|java|py)` - bad (vulnerable) case
//! - Files containing `good` in the name - fixed (non-vulnerable) case
//! - Files containing `bad` in the name - vulnerable case

use crate::config::AnalysisConfig;
use crate::error::{AuditorError, Result};
use crate::models::{Confidence, Finding, Language, SourceFile};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// CWE identifier extracted from Juliet test case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CweId(pub u32);

impl CweId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> String {
        format!("CWE-{}", self.0)
    }
}

impl std::fmt::Display for CweId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CWE-{}", self.0)
    }
}

/// Ground truth label for a test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundTruth {
    /// Test case contains a vulnerability (should be detected).
    Vulnerable,
    /// Test case is fixed/secure (should NOT be detected).
    Secure,
    /// Unknown ground truth (not from Juliet).
    Unknown,
}

/// A single Juliet test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JulietTestCase {
    /// Path to the test file.
    pub path: PathBuf,
    /// CWE identifier.
    pub cwe: CweId,
    /// Ground truth label.
    pub ground_truth: GroundTruth,
    /// Variant name (e.g., "char_connect_socket").
    pub variant: String,
    /// Test case number within variant.
    pub case_number: u32,
    /// Language of the test case.
    pub language: Language,
}

impl JulietTestCase {
    /// Parse a Juliet test case from a file path.
    ///
    /// Expected format: `CWE<num>_<name>__<variant>_<nn>.(c|cpp|java|py)`
    pub fn from_path(path: &Path) -> Option<Self> {
        let file_name = path.file_name()?.to_str()?;
        let stem = path.file_stem()?.to_str()?;

        // Detect language from extension
        let ext = path.extension()?.to_str()?;
        let language = match ext {
            "py" => Language::Python,
            "js" => Language::JavaScript,
            "ts" => Language::TypeScript,
            "go" => Language::Go,
            "rs" => Language::Rust,
            "c" | "cpp" | "cc" | "cxx" => Language::C,
            "java" => Language::Java,
            _ => return None,
        };

        // Parse CWE number from filename
        // Format: CWE<num>_<name>__<variant>_<nn>
        if !stem.starts_with("CWE") {
            return None;
        }

        // Extract CWE number
        let cwe_part = stem.strip_prefix("CWE")?;
        let underscore_pos = cwe_part.find('_')?;
        let cwe_num: u32 = cwe_part[..underscore_pos].parse().ok()?;

        // Determine ground truth from filename
        let ground_truth = if file_name.to_lowercase().contains("good")
            || file_name.to_lowercase().contains("_good")
            || file_name.to_lowercase().contains("fixed")
        {
            GroundTruth::Secure
        } else if file_name.to_lowercase().contains("bad")
            || file_name.to_lowercase().contains("_bad")
        {
            GroundTruth::Vulnerable
        } else {
            // Default: files without explicit markers are typically vulnerable
            GroundTruth::Vulnerable
        };

        // Extract variant and case number
        let remaining = &cwe_part[underscore_pos + 1..];
        let variant_parts: Vec<&str> = remaining.split("__").collect();
        let variant = if variant_parts.len() >= 2 {
            variant_parts[1].to_string()
        } else {
            remaining.to_string()
        };

        // Try to extract case number from end
        let case_number = stem
            .rsplit('_')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Some(Self {
            path: path.to_path_buf(),
            cwe: CweId::new(cwe_num),
            ground_truth,
            variant,
            case_number,
            language,
        })
    }
}

/// Result of analyzing a single test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseResult {
    /// The test case.
    pub test_case: JulietTestCase,
    /// Whether the analyzer detected a vulnerability.
    pub detected: bool,
    /// Findings produced by the analyzer.
    pub findings: Vec<FindingSummary>,
    /// Analysis time.
    pub analysis_time: Duration,
}

impl TestCaseResult {
    /// Check if this result is a true positive.
    pub fn is_true_positive(&self) -> bool {
        self.detected && self.test_case.ground_truth == GroundTruth::Vulnerable
    }

    /// Check if this result is a false positive.
    pub fn is_false_positive(&self) -> bool {
        self.detected && self.test_case.ground_truth == GroundTruth::Secure
    }

    /// Check if this result is a true negative.
    pub fn is_true_negative(&self) -> bool {
        !self.detected && self.test_case.ground_truth == GroundTruth::Secure
    }

    /// Check if this result is a false negative.
    pub fn is_false_negative(&self) -> bool {
        !self.detected && self.test_case.ground_truth == GroundTruth::Vulnerable
    }
}

/// Summary of a finding for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
    pub line: usize,
    pub message: String,
}

impl From<&Finding> for FindingSummary {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.clone(),
            severity: format!("{:?}", f.severity),
            confidence: format!("{:?}", f.confidence),
            line: f.location.start_line,
            message: f.title.clone(),
        }
    }
}

/// Benchmark metrics for a set of test cases.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    /// Total number of test cases.
    pub total_cases: usize,
    /// Number of vulnerable test cases.
    pub vulnerable_cases: usize,
    /// Number of secure test cases.
    pub secure_cases: usize,
    /// True positives (correctly identified vulnerabilities).
    pub true_positives: usize,
    /// False positives (incorrectly flagged secure code).
    pub false_positives: usize,
    /// True negatives (correctly identified secure code).
    pub true_negatives: usize,
    /// False negatives (missed vulnerabilities).
    pub false_negatives: usize,
    /// Precision = TP / (TP + FP).
    pub precision: f64,
    /// Recall = TP / (TP + FN).
    pub recall: f64,
    /// F1 score = 2 * (precision * recall) / (precision + recall).
    pub f1_score: f64,
    /// False positive rate = FP / (FP + TN).
    pub false_positive_rate: f64,
    /// Total analysis time.
    pub total_time: Duration,
    /// Average time per test case.
    pub avg_time_per_case: Duration,
}

impl BenchmarkMetrics {
    /// Compute metrics from test case results.
    pub fn compute(results: &[TestCaseResult]) -> Self {
        let total_cases = results.len();
        let mut vulnerable_cases = 0;
        let mut secure_cases = 0;
        let mut true_positives = 0;
        let mut false_positives = 0;
        let mut true_negatives = 0;
        let mut false_negatives = 0;
        let mut total_time = Duration::ZERO;

        for result in results {
            total_time += result.analysis_time;

            match result.test_case.ground_truth {
                GroundTruth::Vulnerable => {
                    vulnerable_cases += 1;
                    if result.detected {
                        true_positives += 1;
                    } else {
                        false_negatives += 1;
                    }
                }
                GroundTruth::Secure => {
                    secure_cases += 1;
                    if result.detected {
                        false_positives += 1;
                    } else {
                        true_negatives += 1;
                    }
                }
                GroundTruth::Unknown => {}
            }
        }

        // Compute derived metrics
        let precision = if true_positives + false_positives > 0 {
            true_positives as f64 / (true_positives + false_positives) as f64
        } else {
            0.0
        };

        let recall = if true_positives + false_negatives > 0 {
            true_positives as f64 / (true_positives + false_negatives) as f64
        } else {
            0.0
        };

        let f1_score = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        let false_positive_rate = if false_positives + true_negatives > 0 {
            false_positives as f64 / (false_positives + true_negatives) as f64
        } else {
            0.0
        };

        let avg_time_per_case = if total_cases > 0 {
            total_time / total_cases as u32
        } else {
            Duration::ZERO
        };

        Self {
            total_cases,
            vulnerable_cases,
            secure_cases,
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            precision,
            recall,
            f1_score,
            false_positive_rate,
            total_time,
            avg_time_per_case,
        }
    }
}

/// Per-CWE breakdown of metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweMetrics {
    /// CWE identifier.
    pub cwe: CweId,
    /// CWE name (if available).
    pub cwe_name: Option<String>,
    /// Metrics for this CWE.
    pub metrics: BenchmarkMetrics,
}

/// Complete benchmark report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Overall metrics.
    pub overall: BenchmarkMetrics,
    /// Per-CWE metrics.
    pub by_cwe: Vec<CweMetrics>,
    /// Per-language metrics.
    pub by_language: HashMap<String, BenchmarkMetrics>,
    /// Individual test case results.
    pub results: Vec<TestCaseResult>,
    /// Benchmark metadata.
    pub metadata: BenchmarkMetadata,
}

/// Benchmark metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    /// Juliet test suite version.
    pub juliet_version: Option<String>,
    /// Test suite path.
    pub test_suite_path: PathBuf,
    /// Analyzer version.
    pub analyzer_version: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Configuration used.
    pub config: String,
}

/// Juliet benchmark harness.
pub struct JulietBenchmark {
    /// Test suite root path.
    test_suite_path: PathBuf,
    /// Discovered test cases.
    test_cases: Vec<JulietTestCase>,
    /// CWE name mappings.
    cwe_names: HashMap<u32, String>,
    /// Languages to include in benchmark.
    languages: HashSet<Language>,
    /// CWEs to include (empty = all).
    include_cwes: HashSet<u32>,
    /// Analysis configuration.
    config: AnalysisConfig,
}

impl JulietBenchmark {
    /// Create a new benchmark harness.
    pub fn new(test_suite_path: PathBuf, config: AnalysisConfig) -> Self {
        let mut harness = Self {
            test_suite_path,
            test_cases: Vec::new(),
            cwe_names: Self::default_cwe_names(),
            languages: HashSet::new(),
            include_cwes: HashSet::new(),
            config,
        };

        // Default to supporting all languages
        harness.languages.insert(Language::Python);
        harness.languages.insert(Language::JavaScript);
        harness.languages.insert(Language::Go);
        harness.languages.insert(Language::Rust);

        harness
    }

    /// Set languages to include in benchmark.
    pub fn with_languages(mut self, languages: Vec<Language>) -> Self {
        self.languages = languages.into_iter().collect();
        self
    }

    /// Set CWEs to include in benchmark (empty = all).
    pub fn with_cwes(mut self, cwes: Vec<u32>) -> Self {
        self.include_cwes = cwes.into_iter().collect();
        self
    }

    /// Discover test cases from the test suite directory.
    pub fn discover_test_cases(&mut self) -> Result<usize> {
        info!(
            "Discovering Juliet test cases in {}",
            self.test_suite_path.display()
        );

        self.test_cases.clear();

        // Walk the directory tree
        self.discover_recursive(&self.test_suite_path.clone())?;

        // Filter by language and CWE
        self.test_cases.retain(|tc| {
            let language_ok = self.languages.contains(&tc.language);
            let cwe_ok = self.include_cwes.is_empty() || self.include_cwes.contains(&tc.cwe.0);
            language_ok && cwe_ok
        });

        info!("Discovered {} test cases", self.test_cases.len());
        Ok(self.test_cases.len())
    }

    /// Recursively discover test cases.
    fn discover_recursive(&mut self, dir: &Path) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)
            .map_err(|e| AuditorError::Analysis(format!("Failed to read directory: {}", e)))?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                self.discover_recursive(&path)?;
            } else if path.is_file() {
                if let Some(test_case) = JulietTestCase::from_path(&path) {
                    self.test_cases.push(test_case);
                }
            }
        }

        Ok(())
    }

    /// Run the benchmark using the provided analyzer function.
    ///
    /// The analyzer function takes a SourceFile and returns findings.
    pub fn run_benchmark<F>(&self, mut analyzer: F) -> Result<BenchmarkReport>
    where
        F: FnMut(&mut SourceFile) -> Result<Vec<Finding>>,
    {
        info!("Running benchmark on {} test cases", self.test_cases.len());

        let mut results = Vec::with_capacity(self.test_cases.len());
        let benchmark_start = Instant::now();

        for test_case in &self.test_cases {
            let result = self.run_single_test(test_case, &mut analyzer)?;
            results.push(result);
        }

        let total_time = benchmark_start.elapsed();

        // Compute overall metrics
        let overall = BenchmarkMetrics::compute(&results);

        // Compute per-CWE metrics
        let by_cwe = self.compute_cwe_metrics(&results);

        // Compute per-language metrics
        let by_language = self.compute_language_metrics(&results);

        // Build metadata
        let metadata = BenchmarkMetadata {
            juliet_version: None,
            test_suite_path: self.test_suite_path.clone(),
            analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now(),
            config: format!("{:?}", self.config),
        };

        info!(
            "Benchmark complete: {:.1}% precision, {:.1}% recall, {:.1}% F1",
            overall.precision * 100.0,
            overall.recall * 100.0,
            overall.f1_score * 100.0
        );

        Ok(BenchmarkReport {
            overall,
            by_cwe,
            by_language,
            results,
            metadata,
        })
    }

    /// Run a single test case.
    fn run_single_test<F>(
        &self,
        test_case: &JulietTestCase,
        analyzer: &mut F,
    ) -> Result<TestCaseResult>
    where
        F: FnMut(&mut SourceFile) -> Result<Vec<Finding>>,
    {
        debug!("Testing {} ({})", test_case.path.display(), test_case.cwe);

        // Read file content
        let content = std::fs::read_to_string(&test_case.path).map_err(|e| {
            AuditorError::Analysis(format!("Failed to read {}: {}", test_case.path.display(), e))
        })?;

        let mut source_file = SourceFile {
            path: test_case.path.clone(),
            absolute_path: test_case.path.clone(),
            language: test_case.language,
            size: content.len() as u64,
            content: Some(content),
        };

        // Run analysis
        let start = Instant::now();
        let findings = analyzer(&mut source_file).unwrap_or_default();
        let analysis_time = start.elapsed();

        // Check if any findings match the expected CWE
        let detected = self.check_detection(&findings, test_case);

        // Convert findings to summaries
        let finding_summaries: Vec<FindingSummary> = findings.iter().map(|f| f.into()).collect();

        Ok(TestCaseResult {
            test_case: test_case.clone(),
            detected,
            findings: finding_summaries,
            analysis_time,
        })
    }

    /// Check if findings indicate detection of the expected vulnerability.
    fn check_detection(&self, findings: &[Finding], test_case: &JulietTestCase) -> bool {
        if findings.is_empty() {
            return false;
        }

        // Check for CWE match in findings
        for finding in findings {
            // Check metadata for CWE
            if let Some(cwe_value) = finding.metadata.get("cwe") {
                if let Some(cwe_str) = cwe_value.as_str() {
                    // Handle formats like "CWE-89" or "89"
                    let cwe_num = cwe_str
                        .strip_prefix("CWE-")
                        .unwrap_or(cwe_str)
                        .parse::<u32>()
                        .unwrap_or(0);

                    if cwe_num == test_case.cwe.0 {
                        return true;
                    }
                }
            }

            // Check rule ID for CWE reference
            let cwe_in_id = test_case.cwe.as_str().to_lowercase();
            if finding.rule_id.to_lowercase().contains(&cwe_in_id) {
                return true;
            }

            // For medium/high confidence findings, count as detection
            // even without exact CWE match
            if matches!(finding.confidence, Confidence::High | Confidence::Medium) {
                return true;
            }
        }

        // Any finding on a vulnerable case counts as detection
        // (conservative approach - may overcount)
        !findings.is_empty()
    }

    /// Compute per-CWE metrics.
    fn compute_cwe_metrics(&self, results: &[TestCaseResult]) -> Vec<CweMetrics> {
        let mut by_cwe: HashMap<CweId, Vec<&TestCaseResult>> = HashMap::new();

        for result in results {
            by_cwe
                .entry(result.test_case.cwe.clone())
                .or_default()
                .push(result);
        }

        let mut cwe_metrics: Vec<CweMetrics> = by_cwe
            .into_iter()
            .map(|(cwe, cwe_results)| {
                let cwe_name = self.cwe_names.get(&cwe.0).cloned();
                let results_owned: Vec<TestCaseResult> =
                    cwe_results.into_iter().cloned().collect();
                let metrics = BenchmarkMetrics::compute(&results_owned);

                CweMetrics {
                    cwe,
                    cwe_name,
                    metrics,
                }
            })
            .collect();

        // Sort by CWE number
        cwe_metrics.sort_by_key(|m| m.cwe.0);

        cwe_metrics
    }

    /// Compute per-language metrics.
    fn compute_language_metrics(&self, results: &[TestCaseResult]) -> HashMap<String, BenchmarkMetrics> {
        let mut by_language: HashMap<Language, Vec<&TestCaseResult>> = HashMap::new();

        for result in results {
            by_language
                .entry(result.test_case.language)
                .or_default()
                .push(result);
        }

        by_language
            .into_iter()
            .map(|(lang, lang_results)| {
                let results_owned: Vec<TestCaseResult> =
                    lang_results.into_iter().cloned().collect();
                let metrics = BenchmarkMetrics::compute(&results_owned);
                (format!("{:?}", lang), metrics)
            })
            .collect()
    }

    /// Get default CWE name mappings for common vulnerability types.
    fn default_cwe_names() -> HashMap<u32, String> {
        let mut names = HashMap::new();

        // Injection vulnerabilities
        names.insert(78, "OS Command Injection".to_string());
        names.insert(89, "SQL Injection".to_string());
        names.insert(90, "LDAP Injection".to_string());
        names.insert(91, "XML Injection".to_string());
        names.insert(94, "Code Injection".to_string());
        names.insert(95, "Eval Injection".to_string());

        // XSS
        names.insert(79, "Cross-site Scripting (XSS)".to_string());
        names.insert(80, "Basic XSS".to_string());

        // Path traversal
        names.insert(22, "Path Traversal".to_string());
        names.insert(23, "Relative Path Traversal".to_string());
        names.insert(36, "Absolute Path Traversal".to_string());

        // Authentication
        names.insert(259, "Hard-coded Password".to_string());
        names.insert(321, "Hard-coded Cryptographic Key".to_string());
        names.insert(798, "Hard-coded Credentials".to_string());

        // Cryptography
        names.insert(326, "Inadequate Encryption Strength".to_string());
        names.insert(327, "Broken Crypto Algorithm".to_string());
        names.insert(328, "Weak Hash".to_string());
        names.insert(330, "Insufficient Randomness".to_string());

        // Memory safety
        names.insert(119, "Buffer Overflow".to_string());
        names.insert(120, "Buffer Copy without Size Check".to_string());
        names.insert(121, "Stack-based Buffer Overflow".to_string());
        names.insert(122, "Heap-based Buffer Overflow".to_string());
        names.insert(125, "Out-of-bounds Read".to_string());
        names.insert(126, "Buffer Over-read".to_string());
        names.insert(127, "Buffer Under-read".to_string());
        names.insert(415, "Double Free".to_string());
        names.insert(416, "Use After Free".to_string());

        // Race conditions
        names.insert(362, "Race Condition".to_string());
        names.insert(366, "Race in Signal Handler".to_string());
        names.insert(367, "TOCTOU Race Condition".to_string());

        // Integer issues
        names.insert(190, "Integer Overflow".to_string());
        names.insert(191, "Integer Underflow".to_string());
        names.insert(681, "Numeric Truncation".to_string());

        // Null pointer
        names.insert(476, "NULL Pointer Dereference".to_string());

        // Deserialization
        names.insert(502, "Unsafe Deserialization".to_string());

        // XXE
        names.insert(611, "XML External Entity (XXE)".to_string());

        // SSRF
        names.insert(918, "Server-Side Request Forgery".to_string());

        names
    }

    /// Get the number of discovered test cases.
    pub fn test_case_count(&self) -> usize {
        self.test_cases.len()
    }

    /// Get discovered test cases.
    pub fn test_cases(&self) -> &[JulietTestCase] {
        &self.test_cases
    }
}

/// Format a benchmark report as a text summary.
pub fn format_benchmark_summary(report: &BenchmarkReport) -> String {
    let mut output = String::new();

    output.push_str("╔══════════════════════════════════════════════════════════════════╗\n");
    output.push_str("║               JULIET BENCHMARK RESULTS                           ║\n");
    output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");

    // Overall metrics
    output.push_str(&format!(
        "║ Total Test Cases:    {:>6}                                     ║\n",
        report.overall.total_cases
    ));
    output.push_str(&format!(
        "║ Vulnerable Cases:    {:>6}                                     ║\n",
        report.overall.vulnerable_cases
    ));
    output.push_str(&format!(
        "║ Secure Cases:        {:>6}                                     ║\n",
        report.overall.secure_cases
    ));
    output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");
    output.push_str(&format!(
        "║ True Positives:      {:>6}                                     ║\n",
        report.overall.true_positives
    ));
    output.push_str(&format!(
        "║ False Positives:     {:>6}                                     ║\n",
        report.overall.false_positives
    ));
    output.push_str(&format!(
        "║ True Negatives:      {:>6}                                     ║\n",
        report.overall.true_negatives
    ));
    output.push_str(&format!(
        "║ False Negatives:     {:>6}                                     ║\n",
        report.overall.false_negatives
    ));
    output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");
    output.push_str(&format!(
        "║ Precision:           {:>6.1}%                                    ║\n",
        report.overall.precision * 100.0
    ));
    output.push_str(&format!(
        "║ Recall:              {:>6.1}%                                    ║\n",
        report.overall.recall * 100.0
    ));
    output.push_str(&format!(
        "║ F1 Score:            {:>6.1}%                                    ║\n",
        report.overall.f1_score * 100.0
    ));
    output.push_str(&format!(
        "║ False Positive Rate: {:>6.1}%                                    ║\n",
        report.overall.false_positive_rate * 100.0
    ));
    output.push_str("╠══════════════════════════════════════════════════════════════════╣\n");
    output.push_str(&format!(
        "║ Total Analysis Time: {:>6.2}s                                    ║\n",
        report.overall.total_time.as_secs_f64()
    ));
    output.push_str(&format!(
        "║ Avg Time Per Case:   {:>6.2}ms                                   ║\n",
        report.overall.avg_time_per_case.as_secs_f64() * 1000.0
    ));
    output.push_str("╚══════════════════════════════════════════════════════════════════╝\n");

    // Top CWEs by recall
    output.push_str("\nTop 10 CWEs by Recall:\n");
    output.push_str("─────────────────────────────────────────────────────────────────────\n");

    let mut sorted_cwes = report.by_cwe.clone();
    sorted_cwes.sort_by(|a, b| {
        b.metrics
            .recall
            .partial_cmp(&a.metrics.recall)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for cwe_metric in sorted_cwes.iter().take(10) {
        let name = cwe_metric
            .cwe_name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        output.push_str(&format!(
            "  {:8} ({:25}) - Recall: {:5.1}%, Precision: {:5.1}%\n",
            cwe_metric.cwe,
            if name.len() > 25 { &name[..25] } else { &name },
            cwe_metric.metrics.recall * 100.0,
            cwe_metric.metrics.precision * 100.0
        ));
    }

    // Per-language breakdown
    output.push_str("\nPer-Language Metrics:\n");
    output.push_str("─────────────────────────────────────────────────────────────────────\n");

    for (lang, metrics) in &report.by_language {
        output.push_str(&format!(
            "  {:12} - Cases: {:5}, Precision: {:5.1}%, Recall: {:5.1}%, F1: {:5.1}%\n",
            lang,
            metrics.total_cases,
            metrics.precision * 100.0,
            metrics.recall * 100.0,
            metrics.f1_score * 100.0
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_juliet_path_parsing() {
        let test_cases = vec![
            (
                "CWE89_SQL_Injection__basic_01_bad.py",
                Some((89, GroundTruth::Vulnerable)),
            ),
            (
                "CWE89_SQL_Injection__basic_01_good.py",
                Some((89, GroundTruth::Secure)),
            ),
            (
                "CWE78_OS_Command_Injection__basic_01.py",
                Some((78, GroundTruth::Vulnerable)),
            ),
            ("not_a_cwe_file.py", None),
            ("README.md", None),
        ];

        for (filename, expected) in test_cases {
            let path = PathBuf::from(filename);
            let result = JulietTestCase::from_path(&path);

            match expected {
                Some((cwe, ground_truth)) => {
                    assert!(result.is_some(), "Expected to parse: {}", filename);
                    let tc = result.unwrap();
                    assert_eq!(tc.cwe.0, cwe, "CWE mismatch for {}", filename);
                    assert_eq!(tc.ground_truth, ground_truth, "Ground truth mismatch for {}", filename);
                }
                None => {
                    assert!(result.is_none(), "Should not parse: {}", filename);
                }
            }
        }
    }

    #[test]
    fn test_metrics_computation() {
        let test_cases = vec![
            (GroundTruth::Vulnerable, true),  // TP
            (GroundTruth::Vulnerable, true),  // TP
            (GroundTruth::Vulnerable, false), // FN
            (GroundTruth::Secure, false),     // TN
            (GroundTruth::Secure, true),      // FP
        ];

        let results: Vec<TestCaseResult> = test_cases
            .into_iter()
            .enumerate()
            .map(|(i, (gt, detected))| TestCaseResult {
                test_case: JulietTestCase {
                    path: PathBuf::from(format!("test_{}.py", i)),
                    cwe: CweId::new(89),
                    ground_truth: gt,
                    variant: "test".to_string(),
                    case_number: i as u32,
                    language: Language::Python,
                },
                detected,
                findings: vec![],
                analysis_time: Duration::from_millis(10),
            })
            .collect();

        let metrics = BenchmarkMetrics::compute(&results);

        assert_eq!(metrics.total_cases, 5);
        assert_eq!(metrics.vulnerable_cases, 3);
        assert_eq!(metrics.secure_cases, 2);
        assert_eq!(metrics.true_positives, 2);
        assert_eq!(metrics.false_positives, 1);
        assert_eq!(metrics.true_negatives, 1);
        assert_eq!(metrics.false_negatives, 1);

        // Precision = 2 / (2 + 1) = 0.667
        assert!((metrics.precision - 0.667).abs() < 0.01);

        // Recall = 2 / (2 + 1) = 0.667
        assert!((metrics.recall - 0.667).abs() < 0.01);
    }

    #[test]
    fn test_cwe_id_display() {
        let cwe = CweId::new(89);
        assert_eq!(cwe.to_string(), "CWE-89");
        assert_eq!(cwe.as_str(), "CWE-89");
    }
}
