//! Git operations using git2.

use crate::error::{AuditorError, Result};
use crate::models::Repository;
use git2::{build::RepoBuilder, Cred, FetchOptions, RemoteCallbacks};
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Git operations handler.
pub struct GitOperations {
    /// Base directory for cloning repositories
    base_dir: PathBuf,

    /// GitHub token for authentication
    token: Option<String>,

    /// Shallow clone depth (0 = full clone)
    depth: u32,
}

impl GitOperations {
    /// Create a new Git operations handler.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            token: std::env::var("GITHUB_TOKEN").ok(),
            depth: 1, // Shallow clone by default
        }
    }

    /// Set the authentication token.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the clone depth (0 = full clone).
    pub fn with_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }

    /// Clone a repository.
    ///
    /// Uses a lock file to prevent TOCTOU race conditions when multiple
    /// processes attempt to clone the same repository.
    pub fn clone_repository(&self, repo: &mut Repository) -> Result<PathBuf> {
        let target_dir = self.base_dir.join(&repo.owner).join(&repo.name);

        // Create parent directories first
        if let Some(parent) = target_dir.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Use a lock file to prevent race conditions
        let lock_path = target_dir.with_extension("lock");
        let _lock = self.acquire_lock(&lock_path)?;

        // Now check if repository exists (protected by lock)
        if target_dir.exists() {
            if let Ok(git_repo) = git2::Repository::open(&target_dir) {
                if !git_repo.is_bare() {
                    info!("Repository already cloned: {}", target_dir.display());
                    repo.local_path = Some(target_dir.clone());
                    return Ok(target_dir);
                }
            }
            // Invalid repo, remove it (safe - we hold the lock)
            std::fs::remove_dir_all(&target_dir)?;
        }

        info!("Cloning repository: {} -> {}", repo.clone_url, target_dir.display());

        let mut callbacks = RemoteCallbacks::new();

        // Set up authentication
        if let Some(ref token) = self.token {
            let token = token.clone();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                // Use token as password with any username for HTTPS
                Cred::userpass_plaintext(username_from_url.unwrap_or("git"), &token)
            });
        }

        // Progress callback
        callbacks.transfer_progress(|progress| {
            debug!(
                "Clone progress: {}/{} objects",
                progress.received_objects(),
                progress.total_objects()
            );
            true
        });

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);

        if self.depth > 0 {
            fetch_options.depth(self.depth as i32);
        }

        let mut builder = RepoBuilder::new();
        builder.fetch_options(fetch_options);

        // Clone the repository
        let git_repo = builder
            .clone(&repo.clone_url, &target_dir)
            .map_err(|e| AuditorError::Clone(format!("Failed to clone {}: {}", repo.full_name, e)))?;

        // Get the HEAD commit SHA
        if let Ok(head) = git_repo.head() {
            if let Some(oid) = head.target() {
                repo.commit_sha = Some(oid.to_string());
            }
        }

        repo.local_path = Some(target_dir.clone());
        info!("Successfully cloned: {}", repo.full_name);

        Ok(target_dir)
    }

    /// Acquire a file lock for the given path.
    ///
    /// Returns a guard that releases the lock when dropped.
    fn acquire_lock(&self, lock_path: &Path) -> Result<LockGuard> {
        use std::io::Write;

        // Try to create the lock file exclusively
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 10;
        const RETRY_DELAY_MS: u64 = 100;

        loop {
            match File::options()
                .write(true)
                .create_new(true)
                .open(lock_path)
            {
                Ok(mut file) => {
                    // Write our PID to the lock file for debugging
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(LockGuard {
                        path: lock_path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(AuditorError::Clone(format!(
                            "Could not acquire lock after {} attempts: {}",
                            MAX_ATTEMPTS,
                            lock_path.display()
                        )));
                    }
                    // Wait and retry
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                }
                Err(e) => {
                    return Err(AuditorError::Io(e));
                }
            }
        }
    }

    /// Open an existing local repository.
    pub fn open_repository(&self, path: &Path) -> Result<git2::Repository> {
        git2::Repository::open(path).map_err(|e| e.into())
    }

    /// Get the current commit SHA.
    pub fn get_head_sha(path: &Path) -> Result<String> {
        let repo = git2::Repository::open(path)?;
        let head = repo.head()?;
        let oid = head.target().ok_or_else(|| {
            AuditorError::Git(git2::Error::from_str("HEAD has no target"))
        })?;
        Ok(oid.to_string())
    }

    /// Check if a path is a Git repository.
    pub fn is_repository(path: &Path) -> bool {
        git2::Repository::open(path).is_ok()
    }

    /// Get list of files changed in recent commits.
    pub fn get_changed_files(path: &Path, since_commit: Option<&str>) -> Result<Vec<PathBuf>> {
        let repo = git2::Repository::open(path)?;
        let head = repo.head()?.peel_to_commit()?;
        let head_tree = head.tree()?;

        let base_tree = if let Some(sha) = since_commit {
            let oid = git2::Oid::from_str(sha)?;
            let commit = repo.find_commit(oid)?;
            Some(commit.tree()?)
        } else if let Some(parent) = head.parent(0).ok() {
            Some(parent.tree()?)
        } else {
            None
        };

        let diff = repo.diff_tree_to_tree(base_tree.as_ref(), Some(&head_tree), None)?;

        let mut files = Vec::new();
        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    files.push(path.to_path_buf());
                }
                true
            },
            None,
            None,
            None,
        )?;

        Ok(files)
    }

    /// Clean up a cloned repository.
    pub fn cleanup(&self, repo: &Repository) -> Result<()> {
        if let Some(ref path) = repo.local_path {
            if path.exists() {
                info!("Cleaning up: {}", path.display());
                std::fs::remove_dir_all(path)?;
            }
        }
        Ok(())
    }

    /// Get repository information from a local path.
    pub fn get_repo_info(path: &Path) -> Result<LocalRepoInfo> {
        let repo = git2::Repository::open(path)?;

        let head = repo.head()?;
        let commit = head.peel_to_commit()?;

        let mut remotes = Vec::new();
        if let Ok(remote_names) = repo.remotes() {
            for name in remote_names.iter().flatten() {
                if let Ok(remote) = repo.find_remote(name) {
                    if let Some(url) = remote.url() {
                        remotes.push((name.to_string(), url.to_string()));
                    }
                }
            }
        }

        // Check dirty status before returning
        let is_dirty = repo.statuses(None).map(|s| !s.is_empty()).unwrap_or(false);

        Ok(LocalRepoInfo {
            path: path.to_path_buf(),
            head_sha: commit.id().to_string(),
            branch: head
                .shorthand()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "HEAD".to_string()),
            remotes,
            is_dirty,
        })
    }
}

/// Information about a local repository.
#[derive(Debug, Clone)]
pub struct LocalRepoInfo {
    pub path: PathBuf,
    pub head_sha: String,
    pub branch: String,
    pub remotes: Vec<(String, String)>,
    pub is_dirty: bool,
}

impl LocalRepoInfo {
    /// Get the origin remote URL.
    pub fn origin_url(&self) -> Option<&str> {
        self.remotes
            .iter()
            .find(|(name, _)| name == "origin")
            .map(|(_, url)| url.as_str())
    }

    /// Parse owner/name from origin URL.
    pub fn parse_github_info(&self) -> Option<(String, String)> {
        let url = self.origin_url()?;
        Repository::from_url(url).map(|r| (r.owner, r.name))
    }
}

/// File system traversal for repositories.
pub struct RepoTraverser {
    ignore_builder: ignore::gitignore::GitignoreBuilder,
    max_file_size: u64,
}

impl RepoTraverser {
    /// Create a new repository traverser.
    pub fn new(repo_path: &Path) -> Self {
        let mut ignore_builder = ignore::gitignore::GitignoreBuilder::new(repo_path);

        // Load .gitignore if present
        let gitignore_path = repo_path.join(".gitignore");
        if gitignore_path.exists() {
            let _ = ignore_builder.add(&gitignore_path);
        }

        // Add default ignores
        let _ = ignore_builder.add_line(None, "**/target/");
        let _ = ignore_builder.add_line(None, "**/node_modules/");
        let _ = ignore_builder.add_line(None, "**/.git/");
        let _ = ignore_builder.add_line(None, "**/vendor/");
        let _ = ignore_builder.add_line(None, "**/dist/");
        let _ = ignore_builder.add_line(None, "**/build/");

        Self {
            ignore_builder,
            max_file_size: 1024 * 1024, // 1 MB default
        }
    }

    /// Set maximum file size.
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Add custom ignore pattern.
    pub fn add_ignore_pattern(&mut self, pattern: &str) {
        let _ = self.ignore_builder.add_line(None, pattern);
    }

    /// Get all source files in the repository.
    pub fn get_source_files(&self, repo_path: &Path) -> Result<Vec<crate::models::SourceFile>> {
        use crate::models::{Language, SourceFile};

        let gitignore = self
            .ignore_builder
            .build()
            .map_err(|e| AuditorError::Analysis(format!("Failed to build gitignore: {}", e)))?;

        let mut files = Vec::new();

        for entry in walkdir::WalkDir::new(repo_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip directories
            if !path.is_file() {
                continue;
            }

            // Check file size
            if let Ok(metadata) = path.metadata() {
                if metadata.len() > self.max_file_size {
                    debug!("Skipping large file: {}", path.display());
                    continue;
                }
            }

            // Check gitignore
            let relative_path = path.strip_prefix(repo_path).unwrap_or(path);
            if matches!(
                gitignore.matched(relative_path, path.is_dir()),
                ignore::Match::Ignore(_)
            ) {
                continue;
            }

            // Detect language from extension
            let language = path
                .extension()
                .and_then(|e| e.to_str())
                .map(Language::from_extension)
                .unwrap_or(Language::Unknown);

            // Only include supported source files
            if language.is_supported() {
                files.push(SourceFile {
                    path: relative_path.to_path_buf(),
                    absolute_path: path.to_path_buf(),
                    language,
                    size: path.metadata().map(|m| m.len()).unwrap_or(0),
                    content: None,
                });
            }
        }

        info!("Found {} source files in {}", files.len(), repo_path.display());
        Ok(files)
    }
}

/// RAII guard for file-based locking.
///
/// Removes the lock file when dropped.
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Clean up the lock file
        if let Err(e) = std::fs::remove_file(&self.path) {
            // Only warn if it's not a "not found" error (could have been cleaned up already)
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to remove lock file {}: {}", self.path.display(), e);
            }
        }
    }
}
