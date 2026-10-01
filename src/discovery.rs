//! Finds the files to analyze under a scan root.
//!
//! Honors `.gitignore`/`.ignore` files (even outside a git checkout), skips
//! dependency and build directories by name at any depth, never follows symlinks
//! (a hostile repository could otherwise point us at files outside the checkout),
//! and drops files over the configured size limit.

use crate::error::{Error, Result};
use crate::model::normalize_path;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use std::path::{Path, PathBuf};
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
}

/// Walk `root` and return the files to analyze, sorted by path.
pub fn discover(root: &Path, opts: &DiscoveryOptions) -> Result<Vec<SourceFile>> {
    if !root.is_dir() {
        return Err(Error::Config(format!(
            "{} is not a directory",
            root.display()
        )));
    }

    let mut overrides = OverrideBuilder::new(root);
    for pattern in &opts.exclude {
        // In an override set, a leading `!` means "exclude".
        overrides
            .add(&format!("!{}", pattern.trim_start_matches('!')))
            .map_err(|e| Error::Config(format!("invalid exclude pattern '{pattern}': {e}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| Error::Config(format!("invalid exclude patterns: {e}")))?;

    let walker = WalkBuilder::new(root)
        .hidden(false) // .env and friends matter for secret detection
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .ignore(true)
        .require_git(false)
        .follow_links(false)
        .max_filesize(Some(opts.max_file_size))
        .overrides(overrides)
        .filter_entry(|entry| {
            let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
            !(is_dir && entry.depth() > 0 && is_excluded_dir(entry.file_name().to_str()))
        })
        .build();

    let mut files = Vec::new();
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
        let abs_path = entry.path().to_path_buf();
        let rel = abs_path.strip_prefix(root).unwrap_or(&abs_path);
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        files.push(SourceFile {
            rel_path: normalize_path(&rel.to_string_lossy()),
            language: Language::from_path(&abs_path),
            abs_path,
            size,
        });
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    debug!("discovered {} files under {}", files.len(), root.display());
    Ok(files)
}

fn is_excluded_dir(name: Option<&str>) -> bool {
    name.is_some_and(|n| DEFAULT_EXCLUDED_DIRS.contains(&n))
}

/// Read a file as text. Returns `None` for binary files (NUL bytes near the start,
/// which also catches UTF-16). Invalid UTF-8 sequences are replaced, not rejected.
pub fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        return None;
    }
    Some(match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
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
        }
    }

    fn paths(files: &[SourceFile]) -> Vec<&str> {
        files.iter().map(|f| f.rel_path.as_str()).collect()
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
        };
        assert_eq!(paths(&discover(root, &o).unwrap()), vec!["src/a.rs"]);
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
        assert!(discover(dir.path(), &opts()).unwrap().is_empty());
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

    #[test]
    fn binary_and_utf16_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("req.txt");
        // "Django==2.0" as UTF-16LE with BOM, as written by PowerShell redirection
        let mut bytes = vec![0xFF, 0xFE];
        for c in "Django==2.0".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        fs::write(&p, bytes).unwrap();
        assert!(read_text(&p).is_none());
        fs::write(&p, b"caf\xe9 = 1").unwrap();
        assert_eq!(read_text(&p).unwrap(), "caf\u{FFFD} = 1");
    }
}
