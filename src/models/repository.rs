//! Repository data models.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a GitHub repository to be analyzed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    /// Repository owner (user or organization)
    pub owner: String,

    /// Repository name
    pub name: String,

    /// Full name (owner/name)
    pub full_name: String,

    /// Default branch
    pub default_branch: String,

    /// Latest commit SHA
    pub commit_sha: Option<String>,

    /// Repository URL
    pub url: String,

    /// Clone URL
    pub clone_url: String,

    /// Primary language
    pub language: Option<String>,

    /// All detected languages
    pub languages: Vec<String>,

    /// Star count
    pub stars: u64,

    /// Fork count
    pub forks: u64,

    /// Whether the repository is archived
    pub archived: bool,

    /// Whether the repository is a fork
    pub is_fork: bool,

    /// Repository description
    pub description: Option<String>,

    /// Topics/tags
    pub topics: Vec<String>,

    /// Last updated timestamp
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Local path after cloning
    #[serde(skip)]
    pub local_path: Option<PathBuf>,
}

impl Repository {
    /// Create a new repository from owner and name.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Self {
        let owner = owner.into();
        let name = name.into();
        let full_name = format!("{}/{}", owner, name);
        let url = format!("https://github.com/{}", full_name);
        let clone_url = format!("https://github.com/{}.git", full_name);

        Self {
            owner,
            name,
            full_name,
            default_branch: "main".to_string(),
            commit_sha: None,
            url,
            clone_url,
            language: None,
            languages: Vec::new(),
            stars: 0,
            forks: 0,
            archived: false,
            is_fork: false,
            description: None,
            topics: Vec::new(),
            updated_at: None,
            local_path: None,
        }
    }

    /// Parse a repository from a GitHub URL or owner/name string.
    pub fn from_url(input: &str) -> Option<Self> {
        // Handle full URLs
        let normalized = input
            .trim()
            .trim_end_matches('/')
            .trim_end_matches(".git");

        // Extract owner/name from URL or direct input
        let parts: Vec<&str> = if normalized.contains("github.com") {
            normalized
                .split("github.com")
                .last()?
                .trim_start_matches('/')
                .trim_start_matches(':')
                .split('/')
                .collect()
        } else {
            normalized.split('/').collect()
        };

        if parts.len() >= 2 {
            let owner = parts[parts.len() - 2].to_string();
            let name = parts[parts.len() - 1].to_string();
            Some(Self::new(owner, name))
        } else {
            None
        }
    }

    /// Check if this repository has been cloned locally.
    pub fn is_cloned(&self) -> bool {
        self.local_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)
    }
}

/// Source file within a repository.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Relative path from repository root
    pub path: PathBuf,

    /// Absolute path on disk
    pub absolute_path: PathBuf,

    /// Detected language
    pub language: Language,

    /// File size in bytes
    pub size: u64,

    /// File content (loaded on demand)
    pub content: Option<String>,
}

impl SourceFile {
    /// Load the file content if not already loaded.
    pub fn load_content(&mut self) -> std::io::Result<&str> {
        if self.content.is_none() {
            self.content = Some(std::fs::read_to_string(&self.absolute_path)?);
        }
        Ok(self.content.as_ref().unwrap())
    }
}

/// Supported programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    C,
    Cpp,
    Ruby,
    Unknown,
}

impl Language {
    /// Detect language from file extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "rs" => Language::Rust,
            "py" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "go" => Language::Go,
            "java" => Language::Java,
            "c" | "h" => Language::C,
            "cpp" | "cc" | "cxx" | "hpp" | "hh" => Language::Cpp,
            "rb" => Language::Ruby,
            _ => Language::Unknown,
        }
    }

    /// Get the tree-sitter language name.
    pub fn tree_sitter_name(&self) -> Option<&'static str> {
        match self {
            Language::Rust => Some("rust"),
            Language::Python => Some("python"),
            Language::JavaScript | Language::TypeScript => Some("javascript"),
            Language::Go => Some("go"),
            _ => None,
        }
    }

    /// Check if this language is supported for SAST.
    pub fn is_supported(&self) -> bool {
        self.tree_sitter_name().is_some()
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Rust => write!(f, "Rust"),
            Language::Python => write!(f, "Python"),
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::Go => write!(f, "Go"),
            Language::Java => write!(f, "Java"),
            Language::C => write!(f, "C"),
            Language::Cpp => write!(f, "C++"),
            Language::Ruby => write!(f, "Ruby"),
            Language::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Scan target representing what to analyze.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Single repository by owner/name
    Repository(Repository),

    /// Local directory path
    LocalPath(PathBuf),

    /// GitHub organization (all repos)
    Organization(String),

    /// GitHub user (all repos)
    User(String),

    /// Search query
    Search(String),
}

impl ScanTarget {
    /// Parse a scan target from CLI input.
    pub fn parse(input: &str) -> Self {
        let input = input.trim();

        // Check if it's a local path
        let path = PathBuf::from(input);
        if path.exists() {
            return ScanTarget::LocalPath(path);
        }

        // Check if it's a URL or owner/name
        if let Some(repo) = Repository::from_url(input) {
            return ScanTarget::Repository(repo);
        }

        // Check for org: or user: prefix
        if let Some(org) = input.strip_prefix("org:") {
            return ScanTarget::Organization(org.to_string());
        }
        if let Some(user) = input.strip_prefix("user:") {
            return ScanTarget::User(user.to_string());
        }

        // Treat as search query
        ScanTarget::Search(input.to_string())
    }
}
