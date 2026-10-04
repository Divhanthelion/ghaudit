//! Finds the files to analyze under a scan root.
//!
//! Skips dependency and build directories by name at any depth, never follows
//! symlinks (a hostile repository could otherwise point us at files outside the
//! checkout), and reports files over the size limit instead of dropping them silently.
//!
//! `.gitignore`/`.ignore` files are honored only for trusted (local) scans: in a
//! repository you do not control they are the author's way of hiding files from the
//! scanner. Even then, files git tracks are scanned although they match an ignore
//! pattern, because they are in the repository all the same.

use crate::error::{Error, Result};
use crate::model::normalize_path;
use ignore::WalkBuilder;
use ignore::overrides::{Override, OverrideBuilder};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::debug;

/// Directory names skipped wherever they appear. These hold third-party or generated
/// code: scanning them buries real findings in noise and costs time.
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    ".terraform",
];

/// Language of a source file, at the granularity of tree-sitter grammars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    /// TypeScript with JSX; parsed with a separate grammar.
    Tsx,
    Go,
}

impl Language {
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Language::Rust,
            "py" | "pyw" => Language::Python,
            "js" | "jsx" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "mts" | "cts" => Language::TypeScript,
            "tsx" => Language::Tsx,
            "go" => Language::Go,
            _ => return None,
        })
    }

    /// The name used in configuration (`languages = [...]`).
    pub fn config_name(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript | Language::Tsx => "typescript",
            Language::Go => "go",
        }
    }
}

/// A file selected for analysis.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Path relative to the scan root, with `/` separators.
    pub rel_path: String,
    pub abs_path: PathBuf,
    /// Set when the SAST engine has a grammar for this file.
    pub language: Option<Language>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub max_file_size: u64,
    /// Extra gitignore-style patterns to skip.
    pub exclude: Vec<String>,
    /// Honor the scanned tree's own `.gitignore`/`.ignore` files. Only for trees you
    /// control: see the module documentation.
    pub honor_ignore_files: bool,
}

/// Files selected for analysis, and files left out because of their size.
#[derive(Debug, Default)]
pub struct Discovered {
    /// Sorted by path.
    pub files: Vec<SourceFile>,
    /// `(path, size)` of files over `max_file_size`.
    pub too_large: Vec<(String, u64)>,
}

/// Walk `root` and return the files to analyze.
pub fn discover(root: &Path, opts: &DiscoveryOptions) -> Result<Discovered> {
    if !root.is_dir() {
        return Err(Error::Config(format!(
            "{} is not a directory",
            root.display()
        )));
    }

    let overrides = exclude_overrides(root, &opts.exclude)?;

    let honor = opts.honor_ignore_files;
    let walker = WalkBuilder::new(root)
        .hidden(false) // .env and friends matter for secret detection
        .git_ignore(honor)
        .git_exclude(honor)
        .git_global(false)
        .ignore(honor)
        .parents(honor)
        .require_git(false)
        .follow_links(false)
        .overrides(overrides.clone())
        .filter_entry(|entry| {
            let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
            !(is_dir && entry.depth() > 0 && is_excluded_dir(entry.file_name().to_str()))
        })
        .build();

    let mut found = Discovered::default();
    // Keyed by the normalized relative path: on Windows, a path from git joined to the
    // root mixes separators and would not compare equal to the walker's.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!("skipping unreadable entry: {e}");
                continue;
            }
        };
        // `is_file` on the entry's own type: symlinks are reported as symlinks, not files.
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        add(&mut found, &mut seen, root, entry.path(), size, opts);
    }

    if honor {
        for rel in tracked_but_ignored(root) {
            if !keep_tracked(&rel, &overrides) {
                continue;
            }
            let abs = root.join(&rel);
            // `symlink_metadata`: a tracked symlink is not followed.
            let Ok(meta) = std::fs::symlink_metadata(&abs) else {
                continue;
            };
            if meta.is_file() {
                add(&mut found, &mut seen, root, &abs, meta.len(), opts);
            }
        }
    }

    found.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    found.too_large.sort();
    debug!(
        "discovered {} files under {} ({} over the size limit)",
        found.files.len(),
        root.display(),
        found.too_large.len()
    );
    Ok(found)
}

fn add(
    found: &mut Discovered,
    seen: &mut BTreeSet<String>,
    root: &Path,
    abs: &Path,
    size: u64,
    opts: &DiscoveryOptions,
) {
    let rel = abs.strip_prefix(root).unwrap_or(abs);
    let rel_path = normalize_path(&rel.to_string_lossy());
    if !seen.insert(rel_path.clone()) {
        return;
    }
    if size > opts.max_file_size {
        found.too_large.push((rel_path, size));
        return;
    }
    found.files.push(SourceFile {
        rel_path,
        language: Language::from_path(abs),
        abs_path: abs.to_path_buf(),
        size,
    });
}

fn exclude_overrides(root: &Path, exclude: &[String]) -> Result<Override> {
    let mut overrides = OverrideBuilder::new(root);
    for pattern in exclude {
        // In an override set, a leading `!` means "exclude".
        overrides
            .add(&format!("!{}", pattern.trim_start_matches('!')))
            .map_err(|e| Error::Config(format!("invalid exclude pattern '{pattern}': {e}")))?;
    }
    overrides
        .build()
        .map_err(|e| Error::Config(format!("invalid exclude patterns: {e}")))
}

/// The default excluded directories and `--exclude` patterns, for paths that are not
/// walked (files in git history).
pub struct PathFilter(Override);

impl PathFilter {
    pub fn new(root: &Path, exclude: &[String]) -> Result<Self> {
        exclude_overrides(root, exclude).map(Self)
    }

    /// Whether `rel` (relative, `/`-separated) would be scanned.
    pub fn keeps(&self, rel: &str) -> bool {
        keep_tracked(rel, &self.0)
    }
}

fn is_excluded_dir(name: Option<&str>) -> bool {
    name.is_some_and(|n| DEFAULT_EXCLUDED_DIRS.contains(&n))
}

/// Whether a tracked file passes the same directory and `--exclude` filters as the walk.
fn keep_tracked(rel: &str, overrides: &Override) -> bool {
    let mut parts: Vec<&str> = rel.split('/').collect();
    parts.pop();
    if parts.iter().any(|d| is_excluded_dir(Some(d))) {
        return false;
    }
    let mut prefix = String::new();
    for dir in &parts {
        prefix.push_str(dir);
        if overrides.matched(&prefix, true).is_ignore() {
            return false;
        }
        prefix.push('/');
    }
    !overrides.matched(rel, false).is_ignore()
}

/// Files git tracks although an ignore rule matches them (`git ls-files -ci`).
/// Empty outside a git work tree or without git.
fn tracked_but_ignored(root: &Path) -> Vec<String> {
    let mut git = Command::new("git");
    crate::process::hide_window_std(&mut git);
    let output = git
        .arg("-C")
        .arg(root)
        // A copied-in .git/config must not run a command for us.
        .args(["-c", "core.fsmonitor=false"])
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--ignored",
            "--exclude-standard",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// File content as analyzers see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileText {
    /// UTF-8 (invalid sequences replaced) or UTF-16 with a byte-order mark or the
    /// typical zero-byte pattern, decoded.
    Text(String),
    /// Binary data, decoded lossily with NUL bytes turned into line breaks. Only
    /// credential patterns are searched in it: a secret does not become harmless
    /// because a NUL byte was put in front of it.
    Binary(String),
}

/// Read a file for analysis. `None` when it cannot be read.
pub fn read_file(path: &Path) -> Option<FileText> {
    let bytes = std::fs::read(path).ok()?;
    Some(decode(bytes))
}

/// Read a file as text; `None` for binary or unreadable files.
pub fn read_text(path: &Path) -> Option<String> {
    match read_file(path)? {
        FileText::Text(s) => Some(s),
        FileText::Binary(_) => None,
    }
}

fn decode(bytes: Vec<u8>) -> FileText {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return FileText::Text(utf16(rest, u16::from_le_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return FileText::Text(utf16(rest, u16::from_be_bytes));
    }
    let bytes = match bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        Some(rest) => rest.to_vec(),
        None => bytes,
    };
    let head = &bytes[..bytes.len().min(8192)];
    if !head.contains(&0) {
        return FileText::Text(match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        });
    }
    // UTF-16 without a byte-order mark (e.g. git's `working-tree-encoding=UTF-16LE`):
    // mostly-ASCII text has a zero in every other byte.
    let pairs = head.len() / 2;
    if pairs >= 2 {
        let zeros_at = |parity: usize| {
            head.as_chunks::<2>()
                .0
                .iter()
                .filter(|pair| pair[parity] == 0)
                .count()
        };
        let (even, odd) = (zeros_at(0), zeros_at(1));
        if odd * 10 >= pairs * 4 && even * 20 < pairs {
            return FileText::Text(utf16(&bytes, u16::from_le_bytes));
        }
        if even * 10 >= pairs * 4 && odd * 20 < pairs {
            return FileText::Text(utf16(&bytes, u16::from_be_bytes));
        }
    }
    let text = String::from_utf8_lossy(&bytes).replace('\0', "\n");
    FileText::Binary(text)
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| unit(pair))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn opts() -> DiscoveryOptions {
        DiscoveryOptions {
            max_file_size: 1024 * 1024,
            exclude: vec![],
            honor_ignore_files: true,
        }
    }

    fn paths(found: &Discovered) -> Vec<&str> {
        found.files.iter().map(|f| f.rel_path.as_str()).collect()
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn skips_dependency_dirs_at_any_depth_and_gitignored_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "src/app.js", "x");
        write(root, "node_modules/lib/index.js", "x");
        write(root, "packages/web/node_modules/lib/index.js", "x");
        write(root, "target/debug/build.rs", "x");
        write(root, "generated/out.py", "x");
        write(root, ".gitignore", "generated/\n");
        write(root, ".env", "SECRET=1");

        let files = discover(root, &opts()).unwrap();
        assert_eq!(paths(&files), vec![".env", ".gitignore", "src/app.js"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_scanned_repositorys_git_config_cannot_run_commands() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if !git(root, &["init", "-q"]) {
            return;
        }
        write(root, "a.txt", "x");
        assert!(git(root, &["add", "a.txt"]));
        assert!(git(root, &["commit", "-q", "-m", "init"]));
        // `git ls-files` runs core.fsmonitor; a downloaded repository could set it.
        let marker = root.join("PWNED");
        let hook = format!("touch '{}'", marker.display());
        assert!(git(root, &["config", "core.fsmonitor", &hook]));
        discover(root, &opts()).unwrap();
        assert!(!marker.exists(), "core.fsmonitor ran during discovery");
    }

    #[test]
    fn untrusted_trees_cannot_hide_files_with_ignore_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, ".gitignore", "secrets.env\n");
        write(root, ".ignore", "*.py\n");
        write(root, "secrets.env", "x");
        write(root, "app.py", "x");
        let o = DiscoveryOptions {
            honor_ignore_files: false,
            ..opts()
        };
        assert_eq!(
            paths(&discover(root, &o).unwrap()),
            vec![".gitignore", ".ignore", "app.py", "secrets.env"]
        );
    }

    #[test]
    fn tracked_files_are_scanned_even_if_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        if !git(root, &["init", "-q"]) {
            return; // git not installed
        }
        write(root, "deploy.env", "x");
        write(root, "node_modules/a.js", "x");
        assert!(git(root, &["add", "-f", "deploy.env", "node_modules/a.js"]));
        assert!(git(root, &["commit", "-q", "-m", "init"]));
        write(root, ".gitignore", "*.env\nnode_modules/\nlocal.env\n");
        write(root, "local.env", "untracked and ignored");
        assert_eq!(
            paths(&discover(root, &opts()).unwrap()),
            vec![".gitignore", "deploy.env"],
            "tracked deploy.env is scanned; untracked local.env and dependency dirs are not"
        );
    }

    #[test]
    fn user_excludes_and_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "docs/a.md", "x");
        write(root, "src/a.rs", "x");
        write(root, "src/big.rs", &"x".repeat(2000));
        let o = DiscoveryOptions {
            max_file_size: 1000,
            exclude: vec!["docs/**".into()],
            honor_ignore_files: true,
        };
        let found = discover(root, &o).unwrap();
        assert_eq!(paths(&found), vec!["src/a.rs"]);
        assert_eq!(found.too_large, vec![("src/big.rs".to_string(), 2000)]);
    }

    #[test]
    fn excluded_name_only_matches_directories() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "src/build", "a file named build is kept");
        assert_eq!(
            paths(&discover(dir.path(), &opts()).unwrap()),
            vec!["src/build"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "id_rsa", "secret");
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("id_rsa"), dir.path().join("key")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linkdir")).unwrap();
        assert!(discover(dir.path(), &opts()).unwrap().files.is_empty());
    }

    #[test]
    fn language_detection() {
        assert_eq!(
            Language::from_path(Path::new("a/b.tsx")),
            Some(Language::Tsx)
        );
        assert_eq!(
            Language::from_path(Path::new("a.MJS")),
            Some(Language::JavaScript)
        );
        assert_eq!(Language::from_path(Path::new("Makefile")), None);
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn utf16_is_decoded_with_or_without_a_bom() {
        // As written by PowerShell redirection.
        let mut bom = vec![0xFF, 0xFE];
        bom.extend(utf16le("token = abc\n"));
        assert_eq!(decode(bom), FileText::Text("token = abc\n".into()));
        // As checked out with `working-tree-encoding=UTF-16LE`.
        assert_eq!(
            decode(utf16le("password = x\n")),
            FileText::Text("password = x\n".into())
        );
        let be: Vec<u8> = "key: v"
            .encode_utf16()
            .flat_map(|c| c.to_be_bytes())
            .collect();
        assert_eq!(decode(be), FileText::Text("key: v".into()));
    }

    #[test]
    fn binary_files_keep_their_text_for_credential_search() {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(b"TOKEN=abc");
        assert_eq!(
            decode(bytes),
            FileText::Binary(format!("{}TOKEN=abc", "\n".repeat(16)))
        );
        assert_eq!(
            decode(b"caf\xe9 = 1".to_vec()),
            FileText::Text("caf\u{FFFD} = 1".into())
        );
        assert_eq!(
            decode(b"\xEF\xBB\xBFx = 1".to_vec()),
            FileText::Text("x = 1".into())
        );
    }
}
