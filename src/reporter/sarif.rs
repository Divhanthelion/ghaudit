//! SARIF (Static Analysis Results Interchange Format) reporter.

use super::Reporter;
use crate::models::{Finding, FindingCategory, ScanResult, Severity};
use serde::Serialize;
use serde_json::{json, Value};

/// SARIF format reporter.
pub struct SarifReporter {
    /// Tool name
    tool_name: String,

    /// Tool version
    tool_version: String,

    /// Include snippets in results
    include_snippets: bool,
}

impl SarifReporter {
    /// Create a new SARIF reporter.
    pub fn new() -> Self {
        Self {
            tool_name: "sec_auditor".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            include_snippets: true,
        }
    }

    /// Set whether to include code snippets.
    pub fn with_snippets(mut self, include: bool) -> Self {
        self.include_snippets = include;
        self
    }

    /// Build a SARIF rule from a finding.
    fn build_rule(&self, finding: &Finding) -> Value {
        let mut rule = json!({
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.description
            },
            "defaultConfiguration": {
                "level": self.severity_to_level(finding.severity)
            },
            "properties": {
                "security-severity": self.severity_to_score(finding.severity),
                "precision": self.confidence_to_precision(&finding.confidence)
            }
        });

        // Add help text if remediation is available
        if let Some(ref remediation) = finding.remediation {
            rule["help"] = json!({
                "text": remediation,
                "markdown": format!("**Remediation:** {}", remediation)
            });
        }

        // Add CWE tags
        let cwes: Vec<String> = finding
            .metadata
            .get("cwe")
            .and_then(|v| v.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();

        if !cwes.is_empty() {
            rule["properties"]["tags"] = json!(cwes);
        }

        rule
    }

    /// Build a SARIF result from a finding.
    fn build_result(&self, finding: &Finding) -> Value {
        let mut result = json!({
            "ruleId": finding.rule_id,
            "level": self.severity_to_level(finding.severity),
            "message": {
                "text": finding.description
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.location.file.display().to_string(),
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": finding.location.start_line,
                        "startColumn": finding.location.start_column,
                        "endLine": finding.location.end_line,
                        "endColumn": finding.location.end_column
                    }
                }
            }]
        });

        // Add code snippet if available
        if self.include_snippets {
            if let Some(ref snippet) = finding.snippet {
                let snippet_text: String = snippet
                    .lines
                    .iter()
                    .map(|(_, line)| line.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");

                result["locations"][0]["physicalLocation"]["contextRegion"] = json!({
                    "startLine": snippet.lines.first().map(|(n, _)| *n).unwrap_or(1),
                    "endLine": snippet.lines.last().map(|(n, _)| *n).unwrap_or(1),
                    "snippet": {
                        "text": snippet_text
                    }
                });
            }
        }

        // Add fingerprint for deduplication
        result["fingerprints"] = json!({
            "primary": finding.id.clone()
        });

        // Add properties
        let mut properties = json!({
            "category": self.category_string(&finding.category),
            "confidence": format!("{:?}", finding.confidence)
        });

        // Add vulnerability info for SCA findings
        if let Some(ref vuln) = finding.vulnerability {
            properties["vulnerability"] = json!({
                "id": vuln.id,
                "cvss": vuln.cvss_score,
                "package": vuln.package,
                "fixedVersion": vuln.fixed_version
            });
        }

        result["properties"] = properties;

        result
    }

    /// Convert severity to SARIF level.
    fn severity_to_level(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::None | Severity::Unknown => "none",
        }
    }

    /// Convert severity to numeric score.
    fn severity_to_score(&self, severity: Severity) -> f32 {
        match severity {
            Severity::Critical => 10.0,
            Severity::High => 8.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::None | Severity::Unknown => 0.0,
        }
    }

    /// Convert confidence to SARIF precision.
    fn confidence_to_precision(&self, confidence: &crate::models::Confidence) -> &'static str {
        match confidence {
            crate::models::Confidence::High => "high",
            crate::models::Confidence::Medium => "medium",
            crate::models::Confidence::Low => "low",
        }
    }

    /// Convert finding category to string.
    fn category_string(&self, category: &FindingCategory) -> String {
        match category {
            FindingCategory::Sast(cat) => format!("SAST/{:?}", cat),
            FindingCategory::Sca => "SCA".to_string(),
            FindingCategory::Provenance => "Provenance".to_string(),
            FindingCategory::Ai => "AI".to_string(),
            FindingCategory::Config => "Config".to_string(),
            FindingCategory::Secret => "Secret".to_string(),
        }
    }
}

impl Default for SarifReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for SarifReporter {
    fn generate(&self, result: &ScanResult) -> String {
        // Collect unique rules
        let mut rules: Vec<Value> = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();

        for finding in &result.findings {
            if !seen_rules.contains(&finding.rule_id) {
                seen_rules.insert(finding.rule_id.clone());
                rules.push(self.build_rule(finding));
            }
        }

        // Build results
        let results: Vec<Value> = result.findings.iter().map(|f| self.build_result(f)).collect();

        // Build the SARIF document
        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "informationUri": "https://github.com/anthropics/sec_auditor",
                        "rules": rules,
                        "properties": {
                            "comments": "Security analysis tool for GitHub repositories"
                        }
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": result.success,
                    "startTimeUtc": result.started_at.to_rfc3339(),
                    "endTimeUtc": result.completed_at.to_rfc3339()
                }],
                "properties": {
                    "repository": result.repository,
                    "commitSha": result.commit_sha,
                    "stats": {
                        "filesScanned": result.stats.files_scanned,
                        "linesAnalyzed": result.stats.lines_analyzed,
                        "sastFindings": result.stats.sast_findings,
                        "scaFindings": result.stats.sca_findings,
                        "secretsFound": result.stats.secrets_found,
                        "durationMs": result.stats.duration_ms
                    }
                }
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Finding, Location, Severity};

    #[test]
    fn test_sarif_generation() {
        let reporter = SarifReporter::new();

        let mut result = ScanResult::new("test/repo");
        result.add_finding(Finding::sast(
            "test/rule",
            "Test Finding",
            "This is a test finding",
            Location::new("src/main.rs".into(), 10, 5),
            Severity::High,
        ));

        let sarif = reporter.generate(&result);

        // Parse to verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    }
}
