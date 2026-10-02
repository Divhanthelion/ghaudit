//! Credentials in git history.
//!
//! A token deleted in a later commit is still in the repository: anyone who can clone
//! it can recover the token from history. This walks every commit reachable from any
//! ref (`git log --all -p -U0`), runs the secret detector over the lines each commit
//! added, and reports each credential once, at the newest commit that added it.
//! Credentials the current files still hold are dropped by the caller
//! ([`HistoryOutcome::drop_current`]): the normal scan reports those.
//!
//! The diff is streamed, so memory stays bounded; byte, time and per-file limits keep a
//! huge history from stalling the scan, and say so in the report. Nothing a repository
//! configures may run: external diff drivers, textconv filters and signature checks are
//! off, and the diff format is pinned.

use super::secrets::{Masker, SecretDetector};
use crate::discovery::PathFilter;
use crate::model::{Finding, LineIndex, Snippet, fingerprint};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MARKER: &str = "ghaudit-commit ";

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Diff output read at most.
    pub bytes: u64,
    /// Time spent at most.
    pub time: Duration,
    /// Lines one commit added to one file, in bytes, searched at most.
    pub file: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 1 << 30,
            time: Duration::from_secs(600),
            file: 2 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Default)]
pub struct HistoryOutcome {
    pub findings: Vec<Finding>,
    pub commits: usize,
    /// File versions over [`Limits::file`], not searched.
    pub oversized: usize,
    /// Why history was not read completely, if it was not.
    pub incomplete: Option<String>,
    /// The credential behind each finding. Never reported.
    values: Vec<String>,
}

impl HistoryOutcome {
    /// Drop credentials the scan of the current files found: it reports them already.
    pub fn drop_current(&mut self, current: &HashSet<String>) {
        let findings = std::mem::take(&mut self.findings);
        let values = std::mem::take(&mut self.values);
        for (f, v) in findings.into_iter().zip(values) {
            if !current.contains(&v) {
                self.findings.push(f);
                self.values.push(v);
            }
        }
    }

    /// One line for the analyzer status.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "searched {} commit{}",
            self.commits,
            if self.commits == 1 { "" } else { "s" }
        );
        if self.oversized > 0 {
            s.push_str(&format!(
                "; {} file versions over the per-file limit skipped",
                self.oversized
            ));
        }
        if let Some(why) = &self.incomplete {
            s.push_str(&format!("; incomplete: {why}"));
        }
        s
    }
}

/// Lines one commit added to one file, with their line numbers in that version.
#[derive(Default)]
struct Chunk {
    commit: String,
    time: i64,
    path: Option<String>,
    lines: Vec<String>,
    numbers: Vec<usize>,
    bytes: usize,
    oversized: bool,
}

pub fn scan_history(
    root: &Path,
    detector: &SecretDetector,
    filter: &PathFilter,
    limits: Limits,
    cancel: &AtomicBool,
) -> Result<HistoryOutcome, String> {
    let mut outcome = HistoryOutcome::default();
    match is_shallow(root) {
        None => return Err("not a git repository".into()),
        Some(true) => {
            outcome.incomplete =
                Some("shallow clone: only the fetched commits were searched".into());
        }
        Some(false) => {}
    }
    let mut child = git(root)
        .args([
            "log",
            "--all",
            "-p",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-notes",
            "--no-show-signature",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--format=ghaudit-commit %H %ct",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run git log: {e}"))?;
    let stdout = child.stdout.take().expect("piped");
    let started = Instant::now();
    let mut reader = BufReader::new(stdout.take(limits.bytes));
    let mut read: u64 = 0;
    let mut buf = Vec::new();
    let mut chunk = Chunk::default();
    let mut next_line = 0usize;
    let mut hits = Hits::default();
    let mut stopped = false;

    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("reading git log: {e}"))?;
        if n == 0 {
            if read >= limits.bytes {
                outcome.incomplete = Some(format!(
                    "stopped after {} MiB of history",
                    limits.bytes >> 20
                ));
                stopped = true;
            }
            break;
        }
        read += n as u64;
        if cancel.load(Ordering::Relaxed) {
            outcome.incomplete = Some("cancelled".into());
            stopped = true;
            break;
        }
        if started.elapsed() > limits.time {
            outcome.incomplete = Some(format!(
                "stopped after the {}s history time limit",
                limits.time.as_secs()
            ));
            stopped = true;
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\n', '\r']);

        if let Some(rest) = line.strip_prefix(MARKER) {
            hits.flush(&mut chunk, detector, &mut outcome.oversized);
            let mut parts = rest.split(' ');
            chunk.commit = parts.next().unwrap_or_default().to_string();
            chunk.time = parts.next().and_then(|t| t.parse().ok()).unwrap_or(0);
            chunk.path = None;
            outcome.commits += 1;
        } else if let Some(path) = line.strip_prefix("+++ ") {
            hits.flush(&mut chunk, detector, &mut outcome.oversized);
            chunk.path = diff_path(path, filter);
        } else if line.starts_with("diff --git ") {
            hits.flush(&mut chunk, detector, &mut outcome.oversized);
            chunk.path = None;
        } else if let Some(header) = line.strip_prefix("@@ ") {
            // @@ -a,b +c,d @@: added lines are numbered from c.
            next_line = header
                .split(' ')
                .find_map(|p| p.strip_prefix('+'))
                .and_then(|p| p.split(',').next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
        } else if let Some(added) = line.strip_prefix('+')
            && chunk.path.is_some()
        {
            chunk.bytes += added.len() + 1;
            if chunk.bytes > limits.file {
                chunk.oversized = true;
            } else {
                chunk.lines.push(added.to_string());
                chunk.numbers.push(next_line);
            }
            next_line += 1;
        }
    }
    hits.flush(&mut chunk, detector, &mut outcome.oversized);
    if stopped {
        let _ = child.kill();
    }
    let status = child.wait();
    if !stopped && !status.is_ok_and(|s| s.success()) {
        return Err("git log failed".into());
    }
    outcome.findings = hits.findings;
    outcome.values = hits.values;
    Ok(outcome)
}

/// A `git` command for reading `root` that runs nothing the repository configures.
fn git(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotePath=false",
            "-c",
            "log.showSignature=false",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// Path from a `+++ b/path` line; `None` for deletions and excluded paths.
fn diff_path(raw: &str, filter: &PathFilter) -> Option<String> {
    let raw = raw.trim();
    if raw == "/dev/null" {
        return None;
    }
    // Quoted when the name has special characters: "b/odd\tname".
    let unquoted = raw.trim_matches('"');
    let path = unquoted.strip_prefix("b/").unwrap_or(unquoted);
    (filter.keeps(path) && SecretDetector::should_scan(path)).then(|| path.to_string())
}

/// Credentials found so far, one per value: git log lists the newest commit first, so
/// the first sighting is the one kept.
#[derive(Default)]
struct Hits {
    findings: Vec<Finding>,
    values: Vec<String>,
    seen: HashSet<(String, String)>,
}

impl Hits {
    fn flush(&mut self, chunk: &mut Chunk, detector: &SecretDetector, oversized: &mut usize) {
        let lines = std::mem::take(&mut chunk.lines);
        let numbers = std::mem::take(&mut chunk.numbers);
        chunk.bytes = 0;
        if std::mem::take(&mut chunk.oversized) {
            *oversized += 1;
            return;
        }
        let Some(path) = chunk.path.as_deref() else {
            return;
        };
        if lines.is_empty() {
            return;
        }
        let text = lines.join("\n");
        let scan = detector.detect(path, &text);
        if scan.findings.is_empty() {
            return;
        }
        let index = LineIndex::new(&text);
        let masker = Masker::new(&scan.values);
        let short = &chunk.commit[..chunk.commit.len().min(12)];
        let date = chrono::DateTime::from_timestamp(chunk.time, 0)
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        for mut f in scan.findings {
            let n = f.location.start_line;
            let Some(value) = value_on_line(&scan.values, index.line(n).unwrap_or_default()) else {
                continue;
            };
            if !self.seen.insert((f.rule_id.clone(), value.clone())) {
                continue;
            }
            let real = numbers.get(n - 1).copied().unwrap_or(1);
            f.location.start_line = real;
            f.location.end_line = real;
            let mut snippet = Snippet::from_index(&index, n, f.location.start_column, 0);
            if let Some(s) = &mut snippet {
                s.first_line = real;
                for l in &mut s.lines {
                    *l = masker.redact(l).into_owned();
                }
                s.clip(real, f.location.start_column);
            }
            f.snippet = snippet;
            // Distinct from a current-file finding on the same line, and per commit, so
            // a baseline that accepts one leak does not hide another on a similar line.
            f.fingerprint = fingerprint(&["history", &f.fingerprint, &chunk.commit]);
            f.commit = Some(chunk.commit.clone());
            f.title = format!("{} in git history", f.title);
            f.message = format!(
                "{} Added in commit {short} ({date}) and gone from the current files, but anyone who can clone the repository can recover it from history.",
                f.message
            );
            f.remediation = Some(
                "Revoke and rotate this credential: everyone who can read the repository's history has it. Rewriting history does not help once it has been pushed or cloned.".into(),
            );
            self.findings.push(f);
            self.values.push(value);
        }
    }
}

/// The detected value on a line (the longest, if several).
fn value_on_line(values: &[String], line: &str) -> Option<String> {
    values
        .iter()
        .filter(|v| line.contains(v.as_str()))
        .max_by_key(|v| v.len())
        .cloned()
}

/// Whether `root` is a shallow clone; `None` when it is not a git repository.
fn is_shallow(root: &Path) -> Option<bool> {
    let out = git(root)
        .args(["rev-parse", "--is-shallow-repository"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim() == "true")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(parts: &[&str]) -> String {
        parts.concat()
    }

    fn run(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn commit(dir: &Path, file: &str, body: &str, msg: &str) {
        let p = dir.join(file);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
        assert!(run(dir, &["add", "-A"]));
        assert!(run(dir, &["commit", "-q", "--no-gpg-sign", "-m", msg]));
    }

    fn scan(root: &Path, exclude: &[&str], limits: Limits, cancel: bool) -> HistoryOutcome {
        let exclude: Vec<String> = exclude.iter().map(|s| s.to_string()).collect();
        let filter = PathFilter::new(root, &exclude).unwrap();
        scan_history(
            root,
            &SecretDetector::new(),
            &filter,
            limits,
            &AtomicBool::new(cancel),
        )
        .unwrap()
    }

    #[test]
    fn deleted_credentials_are_found_once_and_masked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if !run(root, &["init", "-q"]) {
            return;
        }
        let gh = tok(&["ghp_", "R8d2kLq9ZxT4mWn7Bv1Cy6Pa3Hs5Je0Fu2Gk"]);
        let stripe = tok(&["sk_live_", "4eC39HqLyjWDarjtT1zdp7dcXyZ"]);
        commit(root, "app.py", "import os\n", "init");
        commit(
            root,
            "app.py",
            &format!("import os\nTOKEN = \"{gh}\"\n"),
            "add token",
        );
        commit(
            root,
            "app.py",
            &format!("import os\n\nAPI_TOKEN = \"{gh}\"\n"),
            "rename it",
        );
        commit(
            root,
            "app.py",
            "import os\nTOKEN = os.environ[\"TOKEN\"]\n",
            "remove token",
        );
        // Still present at HEAD: the normal scan's job, dropped below.
        commit(root, ".env", &format!("STRIPE={stripe}\n"), "stripe");
        // Dependency directories and excluded paths are skipped.
        commit(
            root,
            "node_modules/x/k.js",
            &format!("t='{gh}'\n"),
            "vendored",
        );
        commit(
            root,
            "fixtures/k.py",
            &format!("t='{stripe}x'\n"),
            "fixture",
        );

        let mut out = scan(root, &["fixtures"], Limits::default(), false);
        assert_eq!(out.commits, 7);
        assert!(out.incomplete.is_none(), "{:?}", out.incomplete);
        assert_eq!(out.findings.len(), 2);
        out.drop_current(&HashSet::from([stripe.clone()]));
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.rule_id, "secret/github-token");
        assert_eq!(f.location.path, "app.py");
        // Newest commit that added it: "rename it", line 3.
        assert_eq!(f.location.start_line, 3);
        assert!(f.commit.as_deref().is_some_and(|c| c.len() == 40));
        assert!(f.message.contains("gone from the current files"));
        let json = serde_json::to_string(f).unwrap();
        assert!(!json.contains(&gh), "{json}");
        assert_eq!(f.snippet.as_ref().unwrap().first_line, 3);
        assert_eq!(out.summary(), "searched 7 commits");
    }

    #[test]
    fn limits_mark_the_result_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if !run(root, &["init", "-q"]) {
            return;
        }
        commit(root, "a.txt", &"x\n".repeat(1000), "big");
        let small = Limits {
            bytes: 100,
            ..Limits::default()
        };
        assert!(
            scan(root, &[], small, false)
                .incomplete
                .unwrap()
                .contains("MiB")
        );
        let out = scan(root, &[], Limits::default(), true);
        assert_eq!(out.incomplete.as_deref(), Some("cancelled"));
        let tight = Limits {
            file: 100,
            ..Limits::default()
        };
        let out = scan(root, &[], tight, false);
        assert_eq!(out.oversized, 1);
        assert!(out.summary().contains("1 file versions over"));
    }

    #[test]
    fn a_directory_without_git_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let filter = PathFilter::new(dir.path(), &[]).unwrap();
        let out = scan_history(
            dir.path(),
            &SecretDetector::new(),
            &filter,
            Limits::default(),
            &AtomicBool::new(false),
        );
        assert!(out.is_err());
    }

    #[test]
    fn diff_paths() {
        let dir = tempfile::tempdir().unwrap();
        let filter = PathFilter::new(dir.path(), &["docs/**".into()]).unwrap();
        assert_eq!(
            diff_path("b/src/a.py", &filter).as_deref(),
            Some("src/a.py")
        );
        assert_eq!(diff_path("/dev/null", &filter), None);
        assert_eq!(
            diff_path("\"b/odd name.env\"", &filter).as_deref(),
            Some("odd name.env")
        );
        assert_eq!(diff_path("b/web/node_modules/x/a.js", &filter), None);
        assert_eq!(diff_path("b/Cargo.lock", &filter), None);
        assert_eq!(diff_path("b/docs/a.md", &filter), None);
    }
}
