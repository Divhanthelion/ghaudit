//! Dependency vulnerabilities, delegated to Google's osv-scanner.
//!
//! osv-scanner understands every common lockfile and manifest (Cargo.lock,
//! package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, requirements.txt,
//! go.mod, Gemfile.lock, composer.lock, pom.xml, ...) and matches versions against the
//! OSV database with each ecosystem's own version rules. ghaudit runs it as a
//! subprocess, reads its JSON output, and converts each advisory group into a finding.
//!
//! A failure to run osv-scanner is reported as a failed analyzer, never as an empty
//! (clean-looking) result.

use crate::model::{Category, Confidence, DependencyInfo, Finding, Location, Severity};
use regex::Regex;
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::debug;

pub const INSTALL_HINT: &str =
    "install it from https://google.github.io/osv-scanner/installation/ or run with --no-sca";

/// Result of a successful osv-scanner run.
#[derive(Debug, Default)]
pub struct ScaOutcome {
    pub findings: Vec<Finding>,
    /// Packages osv-scanner extracted and checked.
    pub packages: usize,
    /// Non-fatal problems osv-scanner reported (e.g. a manifest it could not resolve).
    pub warnings: Vec<String>,
}

pub struct OsvScanner {
    program: String,
    extra_args: Vec<String>,
    timeout: Duration,
}

impl OsvScanner {
    /// `excludes` are ghaudit's gitignore-style `--exclude` patterns; directory patterns
    /// are forwarded to osv-scanner so excluded lockfiles are not scanned either.
    pub fn new(
        program: impl Into<String>,
        mut extra_args: Vec<String>,
        excludes: &[String],
        timeout: Duration,
    ) -> Self {
        extra_args.extend(exclude_args(excludes));
        Self {
            program: program.into(),
            extra_args,
            timeout,
        }
    }

    /// Scan every lockfile/manifest under `root`.
    pub async fn scan(&self, root: &Path) -> Result<ScaOutcome, String> {
        let root = std::path::absolute(root).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&self.program);
        cmd.args([
            "scan",
            "source",
            "--recursive",
            "--all-packages",
            "--allow-no-lockfiles",
            // Report everything in the JSON and exit code, including findings osv-scanner
            // would otherwise de-emphasize (e.g. Debian "unimportant").
            "--all-vulns",
            "--format",
            "json",
        ])
        .args(&self.extra_args)
        .arg(&root)
        .stdin(Stdio::null())
        .kill_on_drop(true);

        debug!("running {} on {}", self.program, root.display());
        let output = match tokio::time::timeout(self.timeout, cmd.output()).await {
            Err(_) => {
                return Err(format!(
                    "osv-scanner timed out after {}s",
                    self.timeout.as_secs()
                ));
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!("osv-scanner not found ({INSTALL_HINT})"));
            }
            Ok(Err(e)) => return Err(format!("could not run osv-scanner: {e}")),
            Ok(Ok(o)) => o,
        };

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let failure = |code: Option<i32>| {
            let tail: Vec<&str> = stderr.lines().rev().take(3).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            format!(
                "osv-scanner exited with {}: {}",
                code.map_or("a signal".to_string(), |c| format!("status {c}")),
                tail.join(" | ")
            )
        };
        // 0: clean, 1: vulnerabilities found, 128: no packages found.
        // 127: an error was logged but no vulnerabilities were found; the JSON on stdout
        //      is still complete, so use it and surface the error as a warning.
        // Anything else (129: API failure, 130: bad config, ...) is a failure.
        let parsed = match output.status.code() {
            Some(0 | 1 | 128) => parse_output(&stdout)
                .map_err(|e| format!("could not parse osv-scanner output: {e}"))?,
            Some(127) => parse_output(&stdout).map_err(|_| failure(Some(127)))?,
            code => return Err(failure(code)),
        };
        let mut outcome = convert(&parsed, &root);
        outcome.warnings = warnings_from(&stderr);
        Ok(outcome)
    }
}

/// Translate gitignore-style directory patterns (`docs/`, `tests/fixtures/**`,
/// `**/testdata`) into osv-scanner `--experimental-exclude=r:<regex>` arguments.
/// osv-scanner only excludes directories, so file patterns such as `*.md` are skipped.
pub fn exclude_args(patterns: &[String]) -> Vec<String> {
    const SEP: &str = r"[/\\]";
    let mut args = Vec::new();
    for pattern in patterns {
        let mut p = pattern
            .trim()
            .trim_start_matches("./")
            .trim_start_matches('/');
        while let Some(stripped) = p.strip_suffix("/**").or_else(|| p.strip_suffix('/')) {
            p = stripped;
        }
        let p = p.strip_prefix("**/").unwrap_or(p);
        if p.is_empty() || p.starts_with('!') || p.contains("**") {
            continue;
        }
        let last = p.rsplit('/').next().unwrap_or(p);
        if last.contains('.') && !last.contains('*') {
            continue; // looks like a file (README.md, app.min.js)
        }
        let body: Vec<String> = p
            .split('/')
            .map(|seg| {
                let mut re = String::new();
                for c in seg.chars() {
                    match c {
                        '*' => re.push_str(r"[^/\\]*"),
                        '?' => re.push_str(r"[^/\\]"),
                        c => re.push_str(&regex::escape(&c.to_string())),
                    }
                }
                re
            })
            .collect();
        if body
            .last()
            .is_some_and(|seg| seg.starts_with(r"[^/\\]*") && seg.len() > r"[^/\\]*".len())
        {
            continue; // `*.md`-style file pattern
        }
        args.push(format!(
            "--experimental-exclude=r:(^|{SEP}){}$",
            body.join(SEP)
        ));
    }
    args
}

/// Parse osv-scanner's JSON, tolerating log lines printed before it.
pub fn parse_output(stdout: &str) -> Result<Output, serde_json::Error> {
    let start = stdout.find("\n{").map_or(0, |i| i + 1);
    let json = if stdout.trim_start().starts_with('{') {
        stdout
    } else {
        &stdout[start..]
    };
    serde_json::from_str(json)
}

/// Lines from stderr that describe problems, shortened and de-duplicated.
fn warnings_from(stderr: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in stderr.lines() {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("error") || lower.contains("failed")) {
            continue;
        }
        let mut short: String = line.trim().chars().take(200).collect();
        if line.trim().chars().count() > 200 {
            short.push('…');
        }
        if !out.contains(&short) {
            out.push(short);
        }
        if out.len() == 5 {
            break;
        }
    }
    out
}

/// Turn osv-scanner results into findings. `root` is the absolute scan root, used to
/// make lockfile paths relative.
pub fn convert(output: &Output, root: &Path) -> ScaOutcome {
    let mut outcome = ScaOutcome::default();
    let mut file_cache: HashMap<PathBuf, Option<String>> = HashMap::new();

    for result in &output.results {
        let abs = PathBuf::from(&result.source.path);
        let rel = relative_to(&abs, root);
        outcome.packages += result.packages.len();

        for pkg in &result.packages {
            let vulns: HashMap<&str, &Vuln> = pkg
                .vulnerabilities
                .iter()
                .map(|v| (v.id.as_str(), v))
                .collect();
            for group in &pkg.groups {
                let content = file_cache
                    .entry(abs.clone())
                    .or_insert_with(|| std::fs::read_to_string(&abs).ok());
                let line = content
                    .as_deref()
                    .map_or(1, |c| find_package_line(c, &pkg.package));
                outcome
                    .findings
                    .push(group_finding(&rel, line, &pkg.package, group, &vulns));
            }
        }
    }
    outcome
}

fn group_finding(
    path: &str,
    line: usize,
    pkg: &Package,
    group: &Group,
    vulns: &HashMap<&str, &Vuln>,
) -> Finding {
    let in_group: Vec<&Vuln> = group
        .ids
        .iter()
        .filter_map(|id| vulns.get(id.as_str()).copied())
        .collect();
    // Prefer an advisory with a human-written summary (GHSA/RUSTSEC usually have one).
    let primary = in_group
        .iter()
        .find(|v| v.summary.as_deref().is_some_and(|s| !s.trim().is_empty()))
        .or_else(|| in_group.first())
        .copied();
    let advisory = primary
        .map(|v| v.id.clone())
        .or_else(|| group.ids.first().cloned())
        .unwrap_or_default();

    let cvss_score = group.max_severity.trim().parse::<f64>().ok();
    // OpenSSF malicious-package reports (MAL-...) carry no CVSS score, but the package
    // itself is malware: installing it may already have compromised the machine.
    let malicious = group.ids.iter().any(|id| id.starts_with("MAL-"));
    let severity = match cvss_score {
        _ if malicious => Severity::Critical,
        Some(score) => Severity::from_cvss_score(score),
        None => in_group
            .iter()
            .filter_map(|v| v.database_specific_str("severity"))
            .filter_map(|s| s.parse::<Severity>().ok())
            .max()
            .unwrap_or(Severity::Unknown),
    };

    let version = if pkg.version.is_empty() {
        pkg.commit
            .as_deref()
            .map(|c| c.chars().take(12).collect())
            .unwrap_or_default()
    } else {
        pkg.version.clone()
    };
    let fixed_versions = fixed_versions(&in_group, pkg, &version);
    let mut aliases: Vec<String> = group
        .aliases
        .iter()
        .chain(group.ids.iter())
        .filter(|a| **a != advisory)
        .cloned()
        .collect();
    aliases.sort();
    aliases.dedup();

    let summary = primary
        .and_then(|v| {
            v.summary
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            primary
                .and_then(|v| v.details.as_deref())
                .map(first_sentence)
        })
        .unwrap_or_else(|| "Known vulnerability".to_string());

    let mut cwe: Vec<String> = in_group
        .iter()
        .flat_map(|v| v.database_specific_list("cwe_ids"))
        .collect();
    cwe.sort();
    cwe.dedup();

    let also = if aliases.is_empty() {
        String::new()
    } else {
        format!(" (also {})", aliases.join(", "))
    };
    let message = format!(
        "{} {}@{} is affected by {advisory}{also}: {summary}",
        pkg.ecosystem, pkg.name, version
    );
    let remediation = match fixed_versions.first() {
        _ if malicious => format!(
            "Remove {} immediately. Treat every machine and CI runner that installed it as compromised: rotate the credentials they could reach.",
            pkg.name
        ),
        Some(v) => format!("Upgrade {} to {v} or later.", pkg.name),
        None => "No fixed version is published. Check the advisory for workarounds, or replace the package.".to_string(),
    };
    let url = format!("https://osv.dev/vulnerability/{advisory}");

    let mut finding = Finding::new(
        format!("osv/{advisory}"),
        Category::Dependency,
        severity,
        Confidence::High,
        format!("{} {}: {}", pkg.name, version, truncate(&summary, 100)),
        message,
        Location::new(path, line, 1),
        &format!("{}|{}|{}|{}", pkg.ecosystem, pkg.name, version, advisory),
    )
    .with_cwe(cwe)
    .with_remediation(remediation);
    finding.dependency = Some(DependencyInfo {
        ecosystem: pkg.ecosystem.clone(),
        package: pkg.name.clone(),
        version,
        advisory,
        aliases,
        fixed_versions,
        cvss_score,
        url,
    });
    finding
}

/// Fix versions newer than `current`, lowest first.
fn fixed_versions(vulns: &[&Vuln], pkg: &Package, current: &str) -> Vec<String> {
    let mut fixed: Vec<String> = Vec::new();
    for v in vulns {
        for affected in &v.affected {
            let same_package = affected.package.as_ref().is_none_or(|p| {
                p.name.eq_ignore_ascii_case(&pkg.name)
                    && (p.ecosystem.is_empty() || p.ecosystem == pkg.ecosystem)
            });
            if !same_package {
                continue;
            }
            for range in affected.ranges.iter().filter(|r| r.kind != "GIT") {
                for event in &range.events {
                    if let Some(f) = &event.fixed
                        && !fixed.contains(f)
                    {
                        fixed.push(f.clone());
                    }
                }
            }
        }
    }
    let newer: Vec<String> = fixed
        .iter()
        .filter(|f| compare_versions(f, current) == Some(Ordering::Greater))
        .cloned()
        .collect();
    let mut out =
        if newer.is_empty() && fixed.iter().all(|f| compare_versions(f, current).is_none()) {
            fixed
        } else {
            newer
        };
    out.sort_by(|a, b| compare_versions(a, b).unwrap_or_else(|| a.cmp(b)));
    out
}

/// Compare the leading numeric components of two versions (`v1.2.3-rc1` -> [1, 2, 3]).
/// Good enough to pick which fixed release applies; `None` if either has no numbers.
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    fn numbers(v: &str) -> Vec<u64> {
        let v = v.trim().trim_start_matches(['v', 'V']);
        let mut out = Vec::new();
        for part in v.split('.') {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            match digits.parse() {
                Ok(n) => out.push(n),
                Err(_) => break,
            }
            if digits.len() != part.len() {
                break; // "0-rc1": stop after the numeric prefix
            }
        }
        out
    }
    let (x, y) = (numbers(a), numbers(b));
    if x.is_empty() || y.is_empty() {
        return None;
    }
    let len = x.len().max(y.len());
    for i in 0..len {
        let (p, q) = (
            x.get(i).copied().unwrap_or(0),
            y.get(i).copied().unwrap_or(0),
        );
        match p.cmp(&q) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}

/// Best-effort line of a package in its lockfile, for a clickable location.
fn find_package_line(content: &str, pkg: &Package) -> usize {
    let name = regex::escape(&pkg.name);
    let Ok(re) = Regex::new(&format!(
        r"(?i)(^|[^A-Za-z0-9_.\-/@]){name}($|[^A-Za-z0-9_.\-/])"
    )) else {
        return 1;
    };
    // `name = "pkg"` / `name: pkg` declarations (Cargo.lock, poetry.lock, ...).
    let declaration = Regex::new(&format!(r#"(?i)^\s*name\s*[=:]\s*["']?{name}["']?\s*$"#)).ok();
    let lines: Vec<&str> = content.lines().collect();
    let with_version = (!pkg.version.is_empty())
        .then(|| {
            lines
                .iter()
                .position(|l| re.is_match(l) && l.contains(pkg.version.as_str()))
        })
        .flatten();
    with_version
        .or_else(|| declaration.and_then(|d| lines.iter().position(|l| d.is_match(l))))
        .or_else(|| lines.iter().position(|l| re.is_match(l)))
        .map_or(1, |i| i + 1)
}

fn relative_to(abs: &Path, root: &Path) -> String {
    let rel = abs
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .ok()
        .or_else(|| {
            // osv-scanner may report symlink-resolved paths (e.g. /private/tmp on macOS).
            let canon_root = root.canonicalize().ok()?;
            let canon_abs = abs.canonicalize().unwrap_or_else(|_| abs.to_path_buf());
            canon_abs
                .strip_prefix(&canon_root)
                .ok()
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(|| abs.to_path_buf());
    crate::model::normalize_path(&rel.to_string_lossy())
}

fn first_sentence(text: &str) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default()
        .trim();
    truncate(line, 160)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

// ---- osv-scanner JSON schema (only the fields ghaudit uses) ----

#[derive(Debug, Deserialize)]
pub struct Output {
    #[serde(default)]
    pub results: Vec<SourceResult>,
}

#[derive(Debug, Deserialize)]
pub struct SourceResult {
    pub source: Source,
    #[serde(default)]
    pub packages: Vec<PackageResult>,
}

#[derive(Debug, Deserialize)]
pub struct Source {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct PackageResult {
    pub package: Package,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub vulnerabilities: Vec<Vuln>,
}

#[derive(Debug, Deserialize)]
pub struct Package {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub commit: Option<String>,
}

/// Advisories osv-scanner considers the same issue (linked by aliases).
#[derive(Debug, Deserialize)]
pub struct Group {
    pub ids: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Highest CVSS base score in the group, as a string; empty when unrated.
    #[serde(default)]
    pub max_severity: String,
}

#[derive(Debug, Deserialize)]
pub struct Vuln {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

impl Vuln {
    fn database_specific_str(&self, key: &str) -> Option<&str> {
        self.database_specific.as_ref()?.get(key)?.as_str()
    }

    fn database_specific_list(&self, key: &str) -> Vec<String> {
        self.database_specific
            .as_ref()
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: Option<AffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
pub struct AffectedPackage {
    pub name: String,
    #[serde(default)]
    pub ecosystem: String,
}

#[derive(Debug, Deserialize)]
pub struct Range {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub fixed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/osv-scanner")
    }

    /// Real osv-scanner 2.x output (trimmed) for a project with a Cargo.lock,
    /// requirements.txt and svc/go.mod; `__ROOT__` stands for the project directory.
    fn fixture_output() -> String {
        let raw = std::fs::read_to_string(fixture_dir().join("multi-ecosystem.json")).unwrap();
        let root = fixture_dir().to_string_lossy().replace('\\', "/");
        raw.replace("__ROOT__", &root)
    }

    fn converted() -> ScaOutcome {
        let parsed = parse_output(&fixture_output()).unwrap();
        convert(&parsed, &fixture_dir())
    }

    fn find<'a>(o: &'a ScaOutcome, advisory: &str) -> &'a Finding {
        o.findings
            .iter()
            .find(|f| {
                f.dependency.as_ref().unwrap().advisory == advisory
                    || f.dependency
                        .as_ref()
                        .unwrap()
                        .aliases
                        .iter()
                        .any(|a| a == advisory)
            })
            .unwrap_or_else(|| panic!("{advisory} not found"))
    }

    #[test]
    fn every_advisory_group_becomes_a_finding() {
        let o = converted();
        assert_eq!(
            o.packages, 6,
            "demo, smallvec, time, django, requests, golang.org/x/text"
        );
        assert_eq!(o.findings.len(), 15);
        assert!(
            o.findings
                .iter()
                .all(|f| f.category == Category::Dependency)
        );
    }

    #[test]
    fn severity_comes_from_the_cvss_score_not_unknown() {
        let o = converted();
        let unknown = o
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Unknown)
            .count();
        assert_eq!(
            unknown, 1,
            "only the one unrated Go advisory should be unknown"
        );
        let critical = find(&o, "RUSTSEC-2019-0009");
        assert_eq!(critical.severity, Severity::Critical);
        assert_eq!(critical.dependency.as_ref().unwrap().cvss_score, Some(9.8));
        let django = find(&o, "PYSEC-2018-2");
        assert_eq!(django.severity, Severity::Medium);
    }

    #[test]
    fn locations_are_relative_with_a_real_line() {
        let o = converted();
        let smallvec = find(&o, "RUSTSEC-2019-0009");
        assert_eq!(smallvec.location.path, "Cargo.lock");
        assert_eq!(
            smallvec.location.start_line, 13,
            "line of name = \"smallvec\""
        );
        let text = o
            .findings
            .iter()
            .find(|f| f.dependency.as_ref().unwrap().package == "golang.org/x/text")
            .unwrap();
        assert_eq!(text.location.path, "svc/go.mod");
        assert_eq!(text.location.start_line, 5);
        let django = find(&o, "PYSEC-2018-2");
        assert_eq!(
            (django.location.path.as_str(), django.location.start_line),
            ("requirements.txt", 1)
        );
    }

    #[test]
    fn fixed_versions_only_list_upgrades() {
        let o = converted();
        let django = find(&o, "PYSEC-2018-2");
        let dep = django.dependency.as_ref().unwrap();
        assert_eq!(dep.fixed_versions, vec!["2.0.8".to_string()]);
        assert!(django.remediation.as_deref().unwrap().contains("2.0.8"));
        assert!(dep.aliases.contains(&"CVE-2018-14574".to_string()));
        assert!(!dep.aliases.contains(&dep.advisory));
    }

    #[test]
    fn findings_are_stable_and_distinct() {
        let a = converted();
        let b = converted();
        let fa: Vec<_> = a.findings.iter().map(|f| f.fingerprint.clone()).collect();
        let fb: Vec<_> = b.findings.iter().map(|f| f.fingerprint.clone()).collect();
        assert_eq!(fa, fb);
        let mut unique = fa.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), fa.len());
    }

    #[test]
    fn excludes_become_directory_regexes() {
        let args = exclude_args(&[
            "tests/fixtures/".into(),
            "**/testdata".into(),
            "docs/**".into(),
            "*.md".into(),
            "README.md".into(),
            "!keep".into(),
        ]);
        assert_eq!(
            args,
            vec![
                r"--experimental-exclude=r:(^|[/\\])tests[/\\]fixtures$".to_string(),
                r"--experimental-exclude=r:(^|[/\\])testdata$".to_string(),
                r"--experimental-exclude=r:(^|[/\\])docs$".to_string(),
            ]
        );
    }

    #[test]
    fn malicious_package_reports_are_critical() {
        let json = r#"{"results":[{"source":{"path":"/r/package-lock.json"},"packages":[{"package":{"name":"evil-lib","version":"1.0.0","ecosystem":"npm"},
            "groups":[{"ids":["MAL-2025-1234"],"aliases":[],"max_severity":""}],
            "vulnerabilities":[{"id":"MAL-2025-1234","summary":"Malicious code in evil-lib (npm)","affected":[]}]}]}]}"#;
        let o = convert(&parse_output(json).unwrap(), Path::new("/r"));
        assert_eq!(o.findings[0].severity, Severity::Critical);
        assert!(
            o.findings[0]
                .remediation
                .as_deref()
                .unwrap()
                .contains("compromised")
        );
    }

    #[test]
    fn version_comparison() {
        assert_eq!(compare_versions("2.0.8", "2.0.0"), Some(Ordering::Greater));
        assert_eq!(compare_versions("1.11.15", "2.0.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("v0.3.3", "0.3.0"), Some(Ordering::Greater));
        assert_eq!(compare_versions("1.0", "1.0.0"), Some(Ordering::Equal));
        assert_eq!(
            compare_versions("1.0.0-rc1", "1.0.0"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare_versions("abc123", "1.0"), None);
    }

    #[test]
    fn output_with_log_lines_before_json() {
        let out =
            parse_output("Scanning dir .\nNo package sources found\n{\"results\": []}\n").unwrap();
        assert!(out.results.is_empty());
    }

    #[test]
    fn stderr_problems_become_warnings() {
        let stderr = "Scanned x\nfailed resolution for requirements.txt: blocked\nfailed resolution for requirements.txt: blocked\nLoaded db\nError during extraction: boom";
        assert_eq!(
            warnings_from(stderr),
            vec![
                "failed resolution for requirements.txt: blocked".to_string(),
                "Error during extraction: boom".to_string()
            ]
        );
    }

    #[cfg(unix)]
    mod subprocess {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn fake_scanner(dir: &Path, body: &str) -> String {
            let path = dir.join("osv-scanner");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.to_string_lossy().into_owned()
        }

        #[tokio::test]
        async fn vulnerabilities_found_exit_code_is_success() {
            let tmp = tempfile::tempdir().unwrap();
            let json = tmp.path().join("out.json");
            std::fs::write(&json, fixture_output()).unwrap();
            let program = fake_scanner(
                tmp.path(),
                &format!(
                    "cat '{}'\necho 'failed resolution for x' >&2\nexit 1",
                    json.display()
                ),
            );
            let outcome = OsvScanner::new(program, vec![], &[], Duration::from_secs(30))
                .scan(&fixture_dir())
                .await
                .unwrap();
            assert_eq!(outcome.findings.len(), 15);
            assert_eq!(
                outcome.warnings,
                vec!["failed resolution for x".to_string()]
            );
        }

        #[tokio::test]
        async fn errors_are_failures_not_empty_results() {
            let tmp = tempfile::tempdir().unwrap();
            let program = fake_scanner(
                tmp.path(),
                "echo 'could not reach api.osv.dev' >&2\nexit 127",
            );
            let err = OsvScanner::new(program, vec![], &[], Duration::from_secs(30))
                .scan(tmp.path())
                .await
                .unwrap_err();
            assert!(
                err.contains("status 127") && err.contains("api.osv.dev"),
                "{err}"
            );

            let program = fake_scanner(tmp.path(), "echo 'not json'\nexit 0");
            let err = OsvScanner::new(program, vec![], &[], Duration::from_secs(30))
                .scan(tmp.path())
                .await
                .unwrap_err();
            assert!(err.contains("parse"), "{err}");

            let program = fake_scanner(tmp.path(), "sleep 5");
            let err = OsvScanner::new(program, vec![], &[], Duration::from_millis(200))
                .scan(tmp.path())
                .await
                .unwrap_err();
            assert!(err.contains("timed out"), "{err}");
        }

        #[tokio::test]
        async fn exit_127_with_complete_json_is_a_warning_not_a_failure() {
            let tmp = tempfile::tempdir().unwrap();
            let program = fake_scanner(
                tmp.path(),
                "echo '{\"results\": []}'\necho 'failed resolution for requirements.txt' >&2\nexit 127",
            );
            let outcome = OsvScanner::new(program, vec![], &[], Duration::from_secs(30))
                .scan(tmp.path())
                .await
                .unwrap();
            assert_eq!(
                outcome.warnings,
                vec!["failed resolution for requirements.txt".to_string()]
            );

            let program = fake_scanner(tmp.path(), "echo 'API down' >&2\nexit 129");
            let err = OsvScanner::new(program, vec![], &[], Duration::from_secs(30))
                .scan(tmp.path())
                .await
                .unwrap_err();
            assert!(err.contains("status 129"), "{err}");
        }

        #[tokio::test]
        async fn missing_binary_explains_how_to_fix_it() {
            let err = OsvScanner::new(
                "definitely-not-osv-scanner",
                vec![],
                &[],
                Duration::from_secs(5),
            )
            .scan(Path::new("."))
            .await
            .unwrap_err();
            assert!(
                err.contains("not found") && err.contains("--no-sca"),
                "{err}"
            );
        }
    }
}
