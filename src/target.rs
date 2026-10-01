//! What the user asked to scan.

use crate::error::{Error, Result};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A directory on disk.
    Local(PathBuf),
    /// A single GitHub repository.
    Repo { owner: String, name: String },
    /// Every repository of an organization.
    Org(String),
    /// Every repository owned by a user.
    User(String),
    /// Repositories matching a GitHub search query.
    Search(String),
}

impl Target {
    /// Human-readable label used as the report's `target`.
    pub fn label(&self) -> String {
        match self {
            Target::Local(p) => p.display().to_string(),
            Target::Repo { owner, name } => format!("{owner}/{name}"),
            Target::Org(o) => format!("org:{o}"),
            Target::User(u) => format!("user:{u}"),
            Target::Search(q) => format!("search:{q}"),
        }
    }
}

static OWNER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$").unwrap());
static REPO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,100}$").unwrap());
static HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?$").unwrap());

/// Validate a GitHub owner (user or organization) name.
pub fn valid_owner(s: &str) -> bool {
    OWNER.is_match(s)
}

fn valid_repo(s: &str) -> bool {
    REPO.is_match(s) && s != "." && s != ".."
}

/// Parse the argument of `ghaudit scan`.
///
/// Accepts, in order of precedence:
/// - an existing directory (`.`, `../project`, `C:\code\app`)
/// - a GitHub URL, including deep links such as `https://github.com/o/r/tree/main/src`
///   and SSH remotes (`git@github.com:o/r.git`)
/// - `owner/repo`
pub fn parse_scan_target(input: &str) -> Result<Target> {
    let input = input.trim();
    let path = PathBuf::from(input);
    if path.is_dir() {
        return Ok(Target::Local(path));
    }
    if path.exists() {
        return Err(Error::Config(format!(
            "{input} is a file; pass the directory that contains it"
        )));
    }

    let rest = if let Some(r) = input.strip_prefix("git@") {
        // git@host:owner/repo.git
        r.split_once(':').map(|(_, path)| path)
    } else {
        let no_scheme = input
            .strip_prefix("https://")
            .or_else(|| input.strip_prefix("http://"))
            .or_else(|| input.strip_prefix("ssh://git@"))
            .unwrap_or(input);
        if no_scheme
            .split('/')
            .next()
            .is_some_and(|h| HOST.is_match(h))
        {
            // host/owner/repo/...
            no_scheme.split_once('/').map(|(_, path)| path)
        } else if no_scheme != input {
            None
        } else {
            Some(no_scheme)
        }
    };

    let Some(rest) = rest else {
        return Err(Error::InvalidTarget(input.to_string()));
    };
    let mut parts = rest.trim_matches('/').split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    let name = name.strip_suffix(".git").unwrap_or(name);
    // A bare "owner/repo" must be exactly two segments; URLs may carry more (tree/..., blob/...).
    let is_url = rest != input;
    if !is_url && parts.next().is_some() {
        return Err(Error::InvalidTarget(input.to_string()));
    }
    if valid_owner(owner) && valid_repo(name) {
        Ok(Target::Repo {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    } else {
        Err(Error::InvalidTarget(input.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(o: &str, n: &str) -> Target {
        Target::Repo {
            owner: o.into(),
            name: n.into(),
        }
    }

    #[test]
    fn parses_repo_forms() {
        assert_eq!(
            parse_scan_target("rust-lang/regex").unwrap(),
            repo("rust-lang", "regex")
        );
        assert_eq!(
            parse_scan_target("https://github.com/rust-lang/regex").unwrap(),
            repo("rust-lang", "regex")
        );
        assert_eq!(
            parse_scan_target("https://github.com/rust-lang/regex.git").unwrap(),
            repo("rust-lang", "regex")
        );
        assert_eq!(
            parse_scan_target("github.com/rust-lang/regex/").unwrap(),
            repo("rust-lang", "regex")
        );
        assert_eq!(
            parse_scan_target("git@github.com:rust-lang/regex.git").unwrap(),
            repo("rust-lang", "regex")
        );
        assert_eq!(
            parse_scan_target("https://github.com/owner/repo/tree/main/src").unwrap(),
            repo("owner", "repo")
        );
        assert_eq!(
            parse_scan_target("a/repo.js").unwrap(),
            repo("a", "repo.js")
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "justaword",
            "a/b/c",
            "https://github.com/onlyowner",
            "-bad/repo",
            "o/..",
            "https://github.com",
            "./does/not/exist/anywhere",
        ] {
            assert!(parse_scan_target(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn existing_directory_wins() {
        let dir = tempfile::tempdir().unwrap();
        let t = parse_scan_target(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(t, Target::Local(dir.path().to_path_buf()));
    }

    #[test]
    fn a_file_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("Cargo.lock");
        std::fs::write(&f, "").unwrap();
        let err = parse_scan_target(f.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("directory"), "{err}");
    }
}
