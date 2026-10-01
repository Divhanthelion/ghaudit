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

/// Shallow-clone `url` (default branch, depth 1).
///
/// The token, when given, is passed to git through `GIT_CONFIG_*` environment
/// variables as an HTTP header scoped to the clone URL's host. It never appears in
/// the command line (visible to other local users via `ps`) or in `.git/config`.
pub async fn clone(url: &str, token: Option<&str>) -> Result<Checkout> {
    let dir = tempfile::Builder::new().prefix("ghaudit-").tempdir()?;
    let path = dir.path().join("repo");

    let mut cmd = git_command();
    cmd.args([
        // Check symlinks out as plain files so nothing in the checkout can point
        // outside it. Hooks and submodules are never fetched by a plain clone.
        "-c",
        "core.symlinks=false",
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--",
        url,
    ])
    .arg(&path);

    if let Some(token) = token.filter(|t| !t.is_empty()) {
        let host = url_origin(url)
            .ok_or_else(|| Error::Git(format!("cannot determine host of clone URL {url}")))?;
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Git(format!(
            "clone of {url} failed: {}",
            stderr.trim()
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

fn git_command() -> Command {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0") // fail instead of prompting for credentials
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

/// `https://host[:port]` part of a URL.
fn url_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
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

        // file:///tmp/x on Unix, file:///C:/x on Windows.
        let path = src.path().to_string_lossy().replace('\\', "/");
        let url = format!("file:///{}", path.trim_start_matches('/'));
        let checkout = clone(&url, None).await.unwrap();
        assert!(checkout.path.join("a.txt").exists());
        assert_eq!(checkout.commit.as_deref().map(str::len), Some(40));
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
        let err = clone("file:///definitely/not/a/repo", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
    }
}
