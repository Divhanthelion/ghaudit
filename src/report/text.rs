//! Human-readable terminal report.

use crate::model::{AnalyzerState, Category, Finding, ScanReport, Severity};
use std::fmt::Write;

pub struct TextOptions {
    pub color: bool,
}

struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn severity(&self, sev: Severity) -> String {
        let label = format!("{:<8}", sev.to_string());
        let code = match sev {
            Severity::Critical => "1;91",
            Severity::High => "31",
            Severity::Medium | Severity::Unknown => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, &label)
    }
}

pub fn render(report: &ScanReport, opts: &TextOptions) -> String {
    let s = Style { on: opts.color };
    let mut out = String::new();

    let commit = report
        .commit
        .as_deref()
        .map(|c| format!(" @ {}", &c[..c.len().min(12)]))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "{} {} scan of {}{commit}",
        s.bold(&report.tool),
        report.version,
        report.target
    );
    let _ = writeln!(
        out,
        "{}",
        s.dim(&format!(
            "{} files, {} lines, {} dependencies in {:.1}s",
            report.stats.files_scanned,
            report.stats.lines_scanned,
            report.stats.dependencies_scanned,
            report.stats.duration_ms as f64 / 1000.0
        ))
    );
    out.push('\n');

    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings at or above the reporting threshold.\n");
    } else {
        let mut current_repo: Option<&str> = None;
        for f in &report.findings {
            if f.repository.as_deref() != current_repo {
                current_repo = f.repository.as_deref();
                if let Some(r) = current_repo {
                    let _ = writeln!(out, "{}\n", s.bold(&format!("== {r} ==")));
                }
            }
            write_finding(&mut out, &s, f);
        }
    }

    write_summary(&mut out, &s, report);
    out
}

fn write_finding(out: &mut String, s: &Style, f: &Finding) {
    const INDENT: &str = "         ";
    let _ = writeln!(
        out,
        "{} {} {}  {}",
        s.severity(f.severity),
        s.dim(&format!("{:<10}", f.category.label())),
        s.bold(&f.title),
        s.dim(&format!("[{}]", f.rule_id))
    );
    let loc = &f.location;
    let _ = writeln!(
        out,
        "{INDENT}  {}:{}:{}",
        loc.path, loc.start_line, loc.start_column
    );

    if let Some(snippet) = &f.snippet {
        let width = (snippet.first_line + snippet.lines.len()).to_string().len();
        for (i, line) in snippet.lines.iter().enumerate() {
            let n = snippet.first_line + i;
            let marker = if n == loc.start_line { ">" } else { " " };
            let text: String = line.chars().take(160).collect();
            let _ = writeln!(
                out,
                "{INDENT}  {}",
                s.dim(&format!("{marker} {n:>width$} | ")) + &text
            );
        }
    }

    if let Some(dep) = &f.dependency {
        let mut ids = dep.advisory.clone();
        if !dep.aliases.is_empty() {
            ids.push_str(&format!(" ({})", dep.aliases.join(", ")));
        }
        let score = dep
            .cvss_score
            .map(|c| format!("  CVSS {c:.1}"))
            .unwrap_or_default();
        let _ = writeln!(out, "{INDENT}  {ids}{score}");
        let _ = writeln!(out, "{INDENT}  {}", s.dim(&dep.url));
    } else {
        for line in wrap(&f.message, 88) {
            let _ = writeln!(out, "{INDENT}  {line}");
        }
    }
    if let Some(fix) = &f.remediation {
        let mut first = true;
        for line in wrap(fix, 83) {
            let prefix = if first { "Fix: " } else { "     " };
            first = false;
            let _ = writeln!(out, "{INDENT}  {}{line}", s.dim(prefix));
        }
    }
    out.push('\n');
}

fn write_summary(out: &mut String, s: &Style, report: &ScanReport) {
    let count = |sev| report.stats.by_severity.get(&sev).copied().unwrap_or(0);
    let mut parts: Vec<String> = Severity::DESCENDING
        .iter()
        .filter(|&&sev| sev != Severity::Unknown || count(sev) > 0)
        .filter(|&&sev| sev != Severity::Info || count(sev) > 0)
        .map(|&sev| format!("{} {}", count(sev), sev.as_str()))
        .collect();
    if report.findings.is_empty() {
        parts = vec!["0 findings".into()];
    }
    let by_cat: Vec<String> = [
        Category::Sast,
        Category::Secret,
        Category::Dependency,
        Category::Ai,
    ]
    .iter()
    .filter_map(|c| {
        report
            .stats
            .by_category
            .get(c)
            .map(|n| format!("{n} {}", c.label()))
    })
    .collect();
    let cats = if by_cat.is_empty() {
        String::new()
    } else {
        format!("  ({})", by_cat.join(", "))
    };
    let _ = writeln!(out, "{} {}{cats}", s.bold("Findings:"), parts.join(", "));

    let analyzers: Vec<String> = report
        .analyzers
        .iter()
        .map(|a| {
            let state = match a.state {
                AnalyzerState::Completed => s.paint("32", "ok"),
                AnalyzerState::Skipped => s.dim("off"),
                AnalyzerState::Failed => s.paint("1;31", "FAILED"),
            };
            format!("{} {state}", a.analyzer)
        })
        .collect();
    let _ = writeln!(out, "{} {}", s.bold("Analyzers:"), analyzers.join("  "));
    for a in &report.analyzers {
        if let (AnalyzerState::Completed, Some(detail)) = (a.state, &a.detail) {
            let _ = writeln!(out, "  {}", s.dim(&format!("{}: {detail}", a.analyzer)));
        }
    }

    if !report.repositories.is_empty() {
        let failed = report
            .repositories
            .iter()
            .filter(|r| r.error.is_some())
            .count();
        let _ = writeln!(
            out,
            "{} {} scanned, {failed} failed",
            s.bold("Repositories:"),
            report.repositories.len() - failed
        );
    }

    let failures = report.failures();
    if !failures.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            s.paint("1;31", "INCOMPLETE SCAN: parts of this scan did not run, so a short report is not a clean one.")
        );
        for f in failures {
            let _ = writeln!(out, "  - {f}");
        }
    }
}

/// Greedy word wrap.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnalyzerStatus, Confidence, Finding, Location, Snippet};

    fn report() -> ScanReport {
        let mut r = ScanReport::new("./demo");
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
                "eval/exec on dynamic input",
                "eval() runs a string as code.",
                Location::new("app/x.py", 2, 5),
                "eval(x)",
            )
            .with_snippet(Snippet::around("a = 1\nb = eval(x)\nc = 2", 2, 1))
            .with_remediation("Parse data instead."),
        );
        r.finalize(Severity::Low);
        r
    }

    #[test]
    fn plain_text_has_finding_location_snippet_and_incomplete_warning() {
        let out = render(&report(), &TextOptions { color: false });
        assert!(out.contains("HIGH"));
        assert!(out.contains("app/x.py:2:5"));
        assert!(out.contains("> 2 | b = eval(x)"));
        assert!(out.contains("Fix: Parse data instead."));
        assert!(out.contains("sca FAILED"));
        assert!(out.contains("INCOMPLETE SCAN"));
        assert!(!out.contains('\x1b'), "no escape codes without color");
    }

    #[test]
    fn color_is_optional() {
        assert!(render(&report(), &TextOptions { color: true }).contains("\x1b["));
    }

    #[test]
    fn empty_report_says_so() {
        let mut r = ScanReport::new("x");
        r.analyzers = vec![AnalyzerStatus::completed("sast")];
        r.finalize(Severity::Low);
        let out = render(&r, &TextOptions { color: false });
        assert!(out.contains("No findings"));
        assert!(!out.contains("INCOMPLETE"));
    }

    #[test]
    fn wraps_words() {
        assert_eq!(wrap("aa bb cc", 5), vec!["aa bb", "cc"]);
    }
}
