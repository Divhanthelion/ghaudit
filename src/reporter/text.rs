//! Human-readable text reporter.

use super::Reporter;
use crate::models::{FindingCategory, ScanResult, Severity};

/// Text format reporter for terminal output.
pub struct TextReporter {
    /// Use colors in output
    use_colors: bool,

    /// Show code snippets
    show_snippets: bool,

    /// Maximum findings to show (0 = unlimited)
    max_findings: usize,
}

impl TextReporter {
    /// Create a new text reporter.
    pub fn new() -> Self {
        Self {
            use_colors: true,
            show_snippets: true,
            max_findings: 0,
        }
    }

    /// Disable colors.
    pub fn without_colors(mut self) -> Self {
        self.use_colors = false;
        self
    }

    /// Disable snippets.
    pub fn without_snippets(mut self) -> Self {
        self.show_snippets = false;
        self
    }

    /// Limit number of findings shown.
    pub fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = max;
        self
    }

    /// Get severity color code.
    fn severity_color(&self, severity: Severity) -> &'static str {
        if !self.use_colors {
            return "";
        }
        match severity {
            Severity::Critical => "\x1b[91m", // Bright red
            Severity::High => "\x1b[31m",     // Red
            Severity::Medium => "\x1b[33m",   // Yellow
            Severity::Low => "\x1b[36m",      // Cyan
            Severity::None => "\x1b[32m",     // Green
            Severity::Unknown => "\x1b[37m",  // White
        }
    }

    /// Reset color.
    fn reset(&self) -> &'static str {
        if self.use_colors {
            "\x1b[0m"
        } else {
            ""
        }
    }

    /// Bold text.
    fn bold(&self) -> &'static str {
        if self.use_colors {
            "\x1b[1m"
        } else {
            ""
        }
    }

    /// Dim text.
    fn dim(&self) -> &'static str {
        if self.use_colors {
            "\x1b[2m"
        } else {
            ""
        }
    }

    /// Category icon.
    fn category_icon(&self, category: &FindingCategory) -> &'static str {
        match category {
            FindingCategory::Sast(_) => "[SAST]",
            FindingCategory::Sca => "[SCA]",
            FindingCategory::Provenance => "[PROV]",
            FindingCategory::Ai => "[AI]",
            FindingCategory::Config => "[CFG]",
            FindingCategory::Secret => "[SEC]",
        }
    }
}

impl Default for TextReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for TextReporter {
    fn generate(&self, result: &ScanResult) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n{}=== Security Scan Report ==={}\n\n",
            self.bold(),
            self.reset()
        ));

        // Repository info
        output.push_str(&format!(
            "{}Repository:{} {}\n",
            self.bold(),
            self.reset(),
            result.repository
        ));
        if let Some(ref sha) = result.commit_sha {
            output.push_str(&format!(
                "{}Commit:{} {}\n",
                self.bold(),
                self.reset(),
                sha
            ));
        }
        output.push_str(&format!(
            "{}Scan Time:{} {} - {}\n",
            self.bold(),
            self.reset(),
            result.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
            result.completed_at.format("%H:%M:%S UTC")
        ));
        output.push_str(&format!(
            "{}Duration:{} {}ms\n\n",
            self.bold(),
            self.reset(),
            result.stats.duration_ms
        ));

        // Summary
        output.push_str(&format!("{}--- Summary ---{}\n", self.bold(), self.reset()));
        output.push_str(&format!(
            "Files Scanned: {}\n",
            result.stats.files_scanned
        ));
        output.push_str(&format!(
            "Lines Analyzed: {}\n",
            result.stats.lines_analyzed
        ));
        output.push_str(&format!(
            "Dependencies Checked: {}\n\n",
            result.stats.dependencies_checked
        ));

        // Finding counts by severity
        let critical = result.findings_by_severity(Severity::Critical).len();
        let high = result.findings_by_severity(Severity::High).len();
        let medium = result.findings_by_severity(Severity::Medium).len();
        let low = result.findings_by_severity(Severity::Low).len();

        output.push_str(&format!(
            "{}Findings:{}\n",
            self.bold(),
            self.reset()
        ));
        output.push_str(&format!(
            "  {}CRITICAL:{} {}\n",
            self.severity_color(Severity::Critical),
            self.reset(),
            critical
        ));
        output.push_str(&format!(
            "  {}HIGH:{} {}\n",
            self.severity_color(Severity::High),
            self.reset(),
            high
        ));
        output.push_str(&format!(
            "  {}MEDIUM:{} {}\n",
            self.severity_color(Severity::Medium),
            self.reset(),
            medium
        ));
        output.push_str(&format!(
            "  {}LOW:{} {}\n\n",
            self.severity_color(Severity::Low),
            self.reset(),
            low
        ));

        // Findings detail
        if result.findings.is_empty() {
            output.push_str(&format!(
                "{}No security findings detected.{}\n",
                self.dim(),
                self.reset()
            ));
        } else {
            output.push_str(&format!("{}--- Findings ---{}\n\n", self.bold(), self.reset()));

            // Sort by severity
            let mut findings = result.findings.clone();
            findings.sort_by(|a, b| b.severity.cmp(&a.severity));

            let findings_to_show = if self.max_findings > 0 {
                &findings[..self.max_findings.min(findings.len())]
            } else {
                &findings[..]
            };

            for (i, finding) in findings_to_show.iter().enumerate() {
                // Finding header
                output.push_str(&format!(
                    "{}[{}]{} {}{} {}{}\n",
                    self.severity_color(finding.severity),
                    finding.severity,
                    self.reset(),
                    self.category_icon(&finding.category),
                    self.bold(),
                    finding.title,
                    self.reset()
                ));

                // Location
                output.push_str(&format!(
                    "  {}Location:{} {}:{}:{}\n",
                    self.dim(),
                    self.reset(),
                    finding.location.file.display(),
                    finding.location.start_line,
                    finding.location.start_column
                ));

                // Rule ID
                output.push_str(&format!(
                    "  {}Rule:{} {}\n",
                    self.dim(),
                    self.reset(),
                    finding.rule_id
                ));

                // Description
                output.push_str(&format!(
                    "  {}Description:{} {}\n",
                    self.dim(),
                    self.reset(),
                    finding.description
                ));

                // Code snippet
                if self.show_snippets {
                    if let Some(ref snippet) = finding.snippet {
                        output.push_str(&format!("  {}Code:{}\n", self.dim(), self.reset()));
                        for (line_num, line) in &snippet.lines {
                            let marker = if *line_num == snippet.highlight_line {
                                format!("{}>{}", self.severity_color(finding.severity), self.reset())
                            } else {
                                " ".to_string()
                            };
                            output.push_str(&format!(
                                "    {}{:>4} |{} {}\n",
                                marker,
                                line_num,
                                self.reset(),
                                line
                            ));
                        }
                    }
                }

                // Remediation
                if let Some(ref remediation) = finding.remediation {
                    output.push_str(&format!(
                        "  {}Remediation:{} {}\n",
                        self.dim(),
                        self.reset(),
                        remediation
                    ));
                }

                // Vulnerability info for SCA
                if let Some(ref vuln) = finding.vulnerability {
                    output.push_str(&format!(
                        "  {}Vulnerability:{} {} (CVSS: {})\n",
                        self.dim(),
                        self.reset(),
                        vuln.id,
                        vuln.cvss_score.unwrap_or(0.0)
                    ));
                    if let Some(ref fixed) = vuln.fixed_version {
                        output.push_str(&format!(
                            "  {}Fixed in:{} {}\n",
                            self.dim(),
                            self.reset(),
                            fixed
                        ));
                    }
                }

                output.push('\n');

                // Add separator between findings
                if i < findings_to_show.len() - 1 {
                    output.push_str(&format!("{}---{}\n\n", self.dim(), self.reset()));
                }
            }

            // Show if there are more findings
            if self.max_findings > 0 && findings.len() > self.max_findings {
                output.push_str(&format!(
                    "\n{}... and {} more findings{}\n",
                    self.dim(),
                    findings.len() - self.max_findings,
                    self.reset()
                ));
            }
        }

        // Status
        output.push_str(&format!("\n{}--- Status ---{}\n", self.bold(), self.reset()));
        if result.success {
            output.push_str(&format!(
                "{}Scan completed successfully.{}\n",
                if self.use_colors { "\x1b[32m" } else { "" },
                self.reset()
            ));
        } else {
            output.push_str(&format!(
                "{}Scan failed: {}{}\n",
                if self.use_colors { "\x1b[31m" } else { "" },
                result.error.as_deref().unwrap_or("Unknown error"),
                self.reset()
            ));
        }

        // Exit recommendation
        if critical > 0 || high > 0 {
            output.push_str(&format!(
                "\n{}WARNING: Critical or high severity issues found. Review required.{}\n",
                if self.use_colors { "\x1b[31m" } else { "" },
                self.reset()
            ));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Finding, Location, Severity};

    #[test]
    fn test_text_report_generation() {
        let reporter = TextReporter::new().without_colors();

        let mut result = ScanResult::new("test/repo");
        result.add_finding(Finding::sast(
            "test/rule",
            "Test Finding",
            "This is a test finding",
            Location::new("src/main.rs".into(), 10, 5),
            Severity::High,
        ));

        let report = reporter.generate(&result);

        assert!(report.contains("Security Scan Report"));
        assert!(report.contains("test/repo"));
        assert!(report.contains("Test Finding"));
        assert!(report.contains("HIGH"));
    }

    #[test]
    fn test_empty_report() {
        let reporter = TextReporter::new().without_colors();
        let result = ScanResult::new("test/repo");

        let report = reporter.generate(&result);

        assert!(report.contains("No security findings detected"));
    }
}
