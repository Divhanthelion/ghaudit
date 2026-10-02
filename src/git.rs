//! Cloning repositories with the system `git`.
//!
//! Using the git CLI (rather than a linked libgit2) means proxies, credential setup
//! and TLS behave exactly as they do for the user's own `git clone`, and the build
//! needs no C libraries.

use crate::error::{Error, Result};
use base64::Engine;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;
use tracing::debug;

const CLONE_TIMEOUT: Duration = Duration::from_secs(600);

/// A shallow clone in a temporary directory, deleted when this value is dropped.
#[derive(Debug)]
pub struct Checkout {
    _dir: TempDir,
    pub path: PathBuf,
    pub commit: Option<String>,
}

/// Shallow-clone `url` (default branch, depth 1), or with `full_history`, clone every
/// branch with all its commits.
///
/// The token, when given, is passed to git through `GIT_CONFIG_*` environment
/// variables as an HTTP header scoped to the clone URL's host. It never appears in
/// the command line (visible to other local users via `ps`) or in `.git/config`,
/// and it is only sent over http(s).
///
/// The repository is untrusted, so the clone runs nothing it controls: no hooks or
/// submodules (a plain clone fetches neither), no symlinks, no `ext::` transport, and
/// no Git LFS downloads (the repository's `.lfsconfig` could point them anywhere).
pub async fn clone(url: &str, token: Option<&str>, full_history: bool) -> Result<Checkout> {
    let dir = tempfile::Builder::new().prefix("ghaudit-").tempdir()?;
    let path = dir.path().join("repo");

    let mut cmd = git_command();
    cmd.args([
        // Check symlinks out as plain files so nothing in the checkout can point
        // outside it.
        "-c",
        "core.symlinks=false",
        "-c",
        "protocol.ext.allow=never",
        // Disable the LFS filter even when the user has run `git lfs install`:
        // pointer files are checked out as they are.
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.process=",
        "-c",
        "filter.lfs.required=false",
        "clone",
        "--quiet",
        "--no-tags",
    ]);
    if !full_history {
        cmd.args(["--depth", "1", "--single-branch"]);
    }
    cmd.args(["--", url])
        .arg(&path)
        .env("GIT_LFS_SKIP_SMUDGE", "1");

    if let Some(token) = token.filter(|t| !t.is_empty())
        && let Some(host) = url_origin(url)
    {
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
        // Append to any GIT_CONFIG_* entries already set in the environment.
        let n: usize = std::env::var("GIT_CONFIG_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        cmd.env("GIT_CONFIG_COUNT", (n + 1).to_string())
            .env(
                format!("GIT_CONFIG_KEY_{n}"),
                format!("http.{host}/.extraheader"),
            )
            .env(
                format!("GIT_CONFIG_VALUE_{n}"),
                format!("AUTHORIZATION: basic {basic}"),
            );
    }

    debug!("cloning {url}");
    let output = tokio::time::timeout(CLONE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| Error::Git(format!("clone of {url} timed out")))?
        .map_err(spawn_error)?;
    if !output.status.success() {
        return Err(Error::Git(format!(
            "clone of {url} failed: {}",
            summarize_stderr(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    let commit = head_commit(&path).await;
    Ok(Checkout {
        _dir: dir,
        path,
        commit,
    })
}

/// `git rev-parse HEAD` for a directory, if it is inside a git work tree.
pub async fn head_commit(path: &Path) -> Option<String> {
    let output = git_command()
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "HEAD"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (sha.len() >= 40).then_some(sha)
}

/// URL of the `origin` remote of the git work tree at `path`, if any.
pub async fn origin_url(path: &Path) -> Option<String> {
    let output = git_command()
        .arg("-C")
        .arg(path)
        .args(["remote", "get-url", "origin"])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!url.is_empty()).then_some(url)
}

fn git_command() -> Command {
    let mut cmd = Command::new("git");
    // `core.fsmonitor` names a command git may run; a scanned tree's .git/config must
    // not be able to set one.
    cmd.args(["-c", "core.fsmonitor=false"])
        .env("GIT_TERMINAL_PROMPT", "0") // fail instead of prompting for credentials
        .stdin(Stdio::null())
        .kill_on_drop(true);
    cmd
}

fn spawn_error(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        Error::Git("git is not installed or not on PATH".into())
    } else {
        Error::Git(e.to_string())
    }
}

/// The line of git's error output that says what went wrong (`fatal: ...`), shortened.
fn summarize_stderr(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let line = lines
        .iter()
        .rev()
        .find(|l| l.starts_with("fatal:") || l.starts_with("error:"))
        .or(lines.last())
        .copied()
        .unwrap_or("no error output");
    let mut short: String = line.chars().take(300).collect();
    if line.chars().count() > 300 {
        short.push('…');
    }
    short
}

/// `https://host[:port]` part of an http(s) URL. Other schemes never get the token.
fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return None;
    }
    let host = rest.split('/').next()?;
    let host = host.rsplit('@').next()?; // drop any userinfo
    (!host.is_empty()).then(|| format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_extraction() {
        assert_eq!(
            url_origin("https://github.com/a/b.git").unwrap(),
            "https://github.com"
        );
        assert_eq!(
            url_origin("https://u@ghe.corp:8443/a/b").unwrap(),
            "https://ghe.corp:8443"
        );
        assert!(url_origin("not a url").is_none());
        assert!(url_origin("file:///tmp/repo").is_none());
        assert!(url_origin("ssh://git@github.com/a/b").is_none());
    }

    #[test]
    fn errors_are_one_line() {
        let stderr = "Cloning into 'repo'...\nremote: Repository not found.\nfatal: repository 'https://github.com/a/b/' not found\n";
        assert_eq!(
            summarize_stderr(stderr),
            "fatal: repository 'https://github.com/a/b/' not found"
        );
        assert_eq!(summarize_stderr(""), "no error output");
        assert!(summarize_stderr(&"x".repeat(1000)).chars().count() <= 301);
    }

    #[tokio::test]
    async fn clones_a_local_repository_and_reports_head() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return; // git not installed
        }
        let src = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(args)
                .current_dir(src.path())
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        };
        run(&["init", "-q"]);
        std::fs::write(src.path().join("a.txt"), "hello").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);
        std::fs::write(src.path().join("a.txt"), "again").unwrap();
        run(&["commit", "-q", "-am", "second"]);
        run(&["branch", "side"]);

        // file:///tmp/x on Unix, file:///C:/x on Windows.
        let path = src.path().to_string_lossy().replace('\\', "/");
        let url = format!("file:///{}", path.trim_start_matches('/'));
        // A token is never attached to a file:// URL (and must not make it fail).
        let checkout = clone(&url, Some("ghp_unused"), false).await.unwrap();
        assert!(checkout.path.join("a.txt").exists());
        assert_eq!(checkout.commit.as_deref().map(str::len), Some(40));
        let count = |dir: &Path, rev: &str| {
            let out = std::process::Command::new("git")
                .args(["rev-list", "--count", rev])
                .current_dir(dir)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(count(&checkout.path, "--all"), "1");
        let full = clone(&url, None, true).await.unwrap();
        assert_eq!(count(&full.path, "--all"), "2");
        assert_eq!(count(&full.path, "origin/side"), "2");
        let dir = checkout.path.clone();
        drop(checkout);
        assert!(!dir.exists(), "temporary clone should be removed on drop");
    }

    #[tokio::test]
    async fn clone_failure_is_reported() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let err = clone("file:///definitely/not/a/repo", None, false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
        assert!(!err.to_string().contains('\n'), "{err}");
    }
}
