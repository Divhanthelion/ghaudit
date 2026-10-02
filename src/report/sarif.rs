//! SARIF 2.1.0 output, shaped for GitHub code scanning.
//!
//! Notes on the choices here:
//! - `startLine` is always >= 1 (GitHub rejects 0).
//! - URIs are relative with `/` separators, so reports from Windows and Linux match;
//!   other characters that are not valid in a URI are percent-encoded.
//! - Columns count Unicode code points (`columnKind: unicodeCodePoints`), as ghaudit's
//!   locations do; the SARIF default would be UTF-16 code units.
//! - Fingerprints are content-based and stable across runs, so alerts are tracked
//!   instead of being closed and re-opened on every upload.
//! - `security-severity` is what GitHub uses to label alerts critical/high/medium/low.

use crate::model::{AnalyzerState, Category, Finding, ScanReport, Severity};
use serde_json::{Value, json};
use std::collections::HashMap;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFO_URI: &str = "https://github.com/Divhanthelion/ghaudit";
/// GitHub code scanning shows at most this many results per run.
pub const MAX_RESULTS: usize = 5000;
/// GitHub truncates rule descriptions beyond this length.
const MAX_DESCRIPTION: usize = 1000;

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Unknown => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Numeric score in GitHub's bands (>= 9 critical, >= 7 high, >= 4 medium, else low).
fn security_severity(f: &Finding) -> String {
    let score = f
        .dependency
        .as_ref()
        .and_then(|d| d.cvss_score)
        .unwrap_or(match f.severity {
            Severity::Critical => 9.5,
            Severity::High => 8.0,
            Severity::Medium | Severity::Unknown => 5.5,
            Severity::Low => 3.0,
            Severity::Info => 0.0,
        });
    format!("{score:.1}")
}

fn uri(f: &Finding) -> String {
    // A setting has no file. GitHub code scanning needs a location anyway; this is the
    // placeholder OpenSSF Scorecard uses for the same situation.
    if f.category == Category::Settings {
        return "no file associated with this alert".to_string();
    }
    let path = match &f.repository {
        Some(repo) => format!("{repo}/{}", f.location.path),
        None => f.location.path.clone(),
    };
    encode_uri_path(&path)
}

/// Percent-encode everything but unreserved characters, `/` and sub-delimiters.
fn encode_uri_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_alphanumeric() || "-._~/!$&'()*+,;=:@".contains(c) {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn rule(f: &Finding) -> Value {
    let mut tags = vec!["security".to_string(), f.category.label().to_string()];
    tags.extend(
        f.cwe
            .iter()
            .map(|c| format!("external/cwe/{}", c.to_lowercase())),
    );
    let (short, full) = match &f.dependency {
        // The finding title names the package; the rule describes the advisory.
        Some(dep) => {
            let summary = f
                .title
                .split_once(": ")
                .map_or(f.title.as_str(), |(_, s)| s)
                .to_string();
            (format!("{}: {summary}", dep.advisory), f.message.clone())
        }
        None => (f.title.clone(), f.message.clone()),
    };
    let mut rule = json!({
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": { "text": clip(&short, MAX_DESCRIPTION) },
        "fullDescription": { "text": clip(&full, MAX_DESCRIPTION) },
        "defaultConfiguration": { "level": level(f.severity) },
        "properties": {
            "tags": tags,
            "precision": match f.confidence {
                crate::model::Confidence::High => "high",
                crate::model::Confidence::Medium => "medium",
                crate::model::Confidence::Low => "low",
            },
            "security-severity": security_severity(f),
        }
    });
    if let Some(fix) = &f.remediation {
        rule["help"] = json!({ "text": fix, "markdown": fix });
    }
    if let Some(dep) = &f.dependency {
        rule["helpUri"] = json!(dep.url);
    } else if let Some(url) = &f.help_url {
        rule["helpUri"] = json!(url);
    }
    rule
}

fn result(f: &Finding, rule_index: usize) -> Value {
    let loc = &f.location;
    let mut region = json!({
        "startLine": loc.start_line.max(1),
        "startColumn": loc.start_column.max(1),
        "endLine": loc.end_line.max(loc.start_line).max(1),
        "endColumn": loc.end_column.max(1),
    });
    if let Some(snippet) = &f.snippet
        && let Some(text) = snippet
            .lines
            .get(loc.start_line.saturating_sub(snippet.first_line))
    {
        region["snippet"] = json!({ "text": text });
    }
    let mut message = f.message.clone();
    if let (Category::Settings, Some(repo)) = (f.category, &f.repository) {
        message = format!("{repo}: {message}");
    }
    if let Some(fix) = &f.remediation {
        message = format!("{message}\nFix: {fix}");
    }
    if let (Category::Settings, Some(url)) = (f.category, &f.help_url) {
        message = format!("{message}\nSettings: {url}");
    }
    let mut properties = json!({
        "category": f.category.label(),
        "severity": f.severity.as_str(),
        "confidence": f.confidence.to_string(),
    });
    if let Some(commit) = &f.commit {
        properties["commit"] = json!(commit);
    }
    json!({
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": level(f.severity),
        "message": { "text": message },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri(f), "uriBaseId": "%SRCROOT%" },
                "region": region,
            }
        }],
        "fingerprints": { "ghaudit/v1": f.fingerprint },
        // Our own key: GitHub's upload action computes primaryLocationLineHash itself and
        // warns when a supplied value differs from its own.
        "partialFingerprints": { "ghaudit/v1": f.fingerprint },
        "properties": properties,
    })
}

pub fn to_sarif(report: &ScanReport) -> Value {
    // Keep the most severe findings if there are more than GitHub will display.
    let mut findings: Vec<&Finding> = report.findings.iter().collect();
    let dropped = findings.len().saturating_sub(MAX_RESULTS);
    if dropped > 0 {
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        findings.truncate(MAX_RESULTS);
    }

    let mut rules = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        if !index.contains_key(f.rule_id.as_str()) {
            index.insert(&f.rule_id, rules.len());
            rules.push(rule(f));
        }
    }
    let results: Vec<Value> = findings
        .iter()
        .map(|f| result(f, index[f.rule_id.as_str()]))
        .collect();

    let notifications: Vec<Value> = report
        .analyzers
        .iter()
        .filter(|a| a.state == AnalyzerState::Failed)
        .map(|a| json!({ "level": "error", "message": { "text": format!("{} analyzer failed: {}", a.analyzer, a.detail.as_deref().unwrap_or("unknown error")) } }))
        .chain(report.repositories.iter().filter_map(|r| {
            r.error.as_ref().map(|e| json!({ "level": "error", "message": { "text": format!("{}: {e}", r.name) } }))
        }))
        .chain((dropped > 0).then(|| json!({ "level": "warning", "message": { "text": format!(
            "{dropped} lower-severity findings omitted: SARIF consumers such as GitHub show at most {MAX_RESULTS} results per run. Use JSON output for the full list."
        ) } })))
        .chain((!report.skipped.is_empty()).then(|| json!({ "level": "warning", "message": { "text": format!(
            "{} files were not fully analyzed (too large, minified, unreadable or over the time limit). Use JSON output for the list.",
            report.skipped.len()
        ) } })))
        .chain((report.stats.findings_omitted > 0).then(|| json!({ "level": "note", "message": { "text": format!(
            "{} repeated findings omitted (over {} of one rule in one file). Use JSON output for the counts.",
            report.stats.findings_omitted,
            crate::scanner::MAX_PER_RULE_AND_FILE
        ) } })))
        .collect();

    let run = json!({
        "tool": {
            "driver": {
                "name": report.tool,
                "version": report.version,
                "semanticVersion": report.version,
                "informationUri": INFO_URI,
                "rules": rules,
            }
        },
        "columnKind": "unicodeCodePoints",
        "invocations": [{
            "executionSuccessful": report.is_complete(),
            "startTimeUtc": report.started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "endTimeUtc": report.finished_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "toolExecutionNotifications": notifications,
        }],
        "results": results,
    });
    json!({ "$schema": SCHEMA, "version": "2.1.0", "runs": [run] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnalyzerStatus, Category, Confidence, DependencyInfo, Location, Snippet};

    fn sample() -> ScanReport {
        let mut r = ScanReport::new("demo");
        r.analyzers = vec![
            AnalyzerStatus::completed("sast"),
            AnalyzerStatus::failed("sca", "osv-scanner not found"),
        ];
        r.findings.push(
            Finding::new(
                "python/eval",
                Category::Sast,
                Severity::High,
                Confidence::Medium,
                "eval",
                "msg",
                Location::new("src\\app.py", 3, 2),
                "eval(x)",
            )
            .with_snippet(Snippet::around("a\nb\neval(x)\n", 3, 1))
            .with_cwe(["CWE-95"])
            .with_remediation("fix it"),
        );
        let mut dep = Finding::new(
            "osv/GHSA-xxxx",
            Category::Dependency,
            Severity::Critical,
            Confidence::High,
            "smallvec 0.6.9: buffer overflow",
            "crates.io smallvec@0.6.9 is affected by GHSA-xxxx",
            Location::new("Cargo.lock", 0, 0),
            "k",
        );
        dep.dependency = Some(DependencyInfo {
            ecosystem: "crates.io".into(),
            package: "smallvec".into(),
            version: "0.6.9".into(),
            advisory: "GHSA-xxxx".into(),
            aliases: vec![],
            fixed_versions: vec!["0.6.10".into()],
            cvss_score: Some(9.8),
            url: "https://osv.dev/vulnerability/GHSA-xxxx".into(),
        });
        r.findings.push(dep);
        r.finalize(Severity::Low);
        r
    }

    #[test]
    fn locations_are_valid_for_github() {
        let sarif = to_sarif(&sample());
        assert_eq!(sarif["runs"][0]["columnKind"], "unicodeCodePoints");
        for res in sarif["runs"][0]["results"].as_array().unwrap() {
            let loc = &res["locations"][0]["physicalLocation"];
            assert!(loc["region"]["startLine"].as_u64().unwrap() >= 1);
            assert!(
                !loc["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
                    .contains('\\')
            );
        }
    }

    #[test]
    fn settings_results_have_a_placeholder_location_and_a_link() {
        let mut r = ScanReport::new("o/r");
        let mut f = Finding::new(
            "settings/webhook-no-secret",
            Category::Settings,
            Severity::Medium,
            Confidence::High,
            "Webhook without a secret",
            "m",
            Location::new("settings/hooks", 1, 1),
            "x",
        );
        f.help_url = Some("https://github.com/o/r/settings/hooks".into());
        r.findings.push(f);
        r.finalize(Severity::Low);
        let sarif = to_sarif(&r);
        let res = &sarif["runs"][0]["results"][0];
        assert_eq!(
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "no file associated with this alert"
        );
        assert!(
            res["message"]["text"]
                .as_str()
                .unwrap()
                .contains("settings/hooks")
        );
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"],
            "https://github.com/o/r/settings/hooks"
        );
    }

    #[test]
    fn uris_are_percent_encoded() {
        assert_eq!(encode_uri_path("src/my file.py"), "src/my%20file.py");
        assert_eq!(encode_uri_path("a\\b/é.rs"), "a%5Cb/%C3%A9.rs");
        assert_eq!(encode_uri_path("o/r/src/a-b_c.~x"), "o/r/src/a-b_c.~x");
    }

    #[test]
    fn rules_are_indexed_and_carry_severity() {
        let sarif = to_sarif(&sample());
        let run = &sarif["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        for res in run["results"].as_array().unwrap() {
            let idx = res["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], res["ruleId"]);
        }
        let dep_rule = rules.iter().find(|r| r["id"] == "osv/GHSA-xxxx").unwrap();
        assert_eq!(dep_rule["properties"]["security-severity"], "9.8");
        assert_eq!(
            dep_rule["shortDescription"]["text"],
            "GHSA-xxxx: buffer overflow"
        );
        let code_rule = rules.iter().find(|r| r["id"] == "python/eval").unwrap();
        assert!(
            code_rule["properties"]["tags"]
                .as_array()
                .unwrap()
                .contains(&json!("external/cwe/cwe-95"))
        );
    }

    #[test]
    fn fingerprints_are_stable_across_runs() {
        let a = to_sarif(&sample());
        let b = to_sarif(&sample());
        let fp = |s: &Value| -> Vec<Value> {
            s["runs"][0]["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["fingerprints"].clone())
                .collect()
        };
        assert_eq!(fp(&a), fp(&b));
    }

    #[test]
    fn large_reports_keep_the_most_severe_results() {
        let mut r = ScanReport::new("big");
        for i in 0..MAX_RESULTS + 10 {
            let sev = if i < 3 {
                Severity::Critical
            } else {
                Severity::Low
            };
            r.findings.push(Finding::new(
                "t/r",
                Category::Sast,
                sev,
                Confidence::High,
                "t",
                "x".repeat(2000),
                Location::new("a.py", i + 1, 1),
                &i.to_string(),
            ));
        }
        r.finalize(Severity::Low);
        let sarif = to_sarif(&r);
        let run = &sarif["runs"][0];
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), MAX_RESULTS);
        assert_eq!(results.iter().filter(|x| x["level"] == "error").count(), 3);
        let desc = run["tool"]["driver"]["rules"][0]["fullDescription"]["text"]
            .as_str()
            .unwrap();
        assert_eq!(desc.chars().count(), MAX_DESCRIPTION);
        assert!(
            run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("10 lower-severity")
        );
    }

    #[test]
    fn failures_are_reported_as_unsuccessful_execution() {
        let sarif = to_sarif(&sample());
        let inv = &sarif["runs"][0]["invocations"][0];
        assert_eq!(inv["executionSuccessful"], false);
        assert!(
            inv["toolExecutionNotifications"][0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("sca")
        );
    }
}
