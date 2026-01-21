#![recursion_limit = "1024"]
//! sec_auditor - High-Performance Rust Security Analysis Engine
//!
//! A comprehensive security analysis application for GitHub repositories,
//! combining SAST, SCA, and AI-driven vulnerability detection.
//!
//! # Features
//!
//! - **SAST (Static Application Security Testing)**: Tree-sitter based code analysis
//! - **SCA (Software Composition Analysis)**: OSV database integration for dependency vulnerabilities
//! - **Secret Detection**: High-entropy and pattern-based secret detection
//! - **Provenance Verification**: SLSA/Sigstore supply chain verification
//! - **AI Analysis**: Optional LLM-powered vulnerability detection
//! - **SARIF Output**: Industry-standard reporting format
//!
//! # Architecture
//!
//! The application uses a hybrid concurrency model:
//! - **Tokio** for async I/O operations (GitHub API, network requests)
//! - **Rayon** for parallel CPU-bound analysis (parsing, pattern matching)
//!
//! # Example Usage
//!
//! ```no_run
//! use sec_auditor::{Config, Scanner};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::default();
//!     let scanner = Scanner::new(config)?;
//!
//!     let result = scanner.scan_repository("owner/repo").await?;
//!     println!("Found {} findings", result.findings.len());
//!
//!     Ok(())
//! }
//! ```

pub mod ai;
pub mod analyzer;
pub mod concurrency;
pub mod config;
pub mod crawler;
pub mod crosslang;
pub mod error;
pub mod models;
pub mod privacy;
pub mod provenance;
pub mod reporter;

// Re-export commonly used types
pub use config::{Config, OutputFormat};
pub use error::{AuditorError, Result};
pub use models::{Finding, Repository, ScanResult, Severity, Vulnerability};

use analyzer::{SastEngine, ScaEngine, SecretDetector};
use crawler::{GitHubClient, GitOperations, RepoTraverser};
use models::ScanTarget;
use provenance::SlsaVerifier;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Main scanner orchestrating all analysis components.
pub struct Scanner {
    /// Configuration
    config: Config,

    /// GitHub client
    github: Option<GitHubClient>,

    /// Git operations handler
    git: GitOperations,

    /// SAST engine
    sast: SastEngine,

    /// SCA engine
    sca: ScaEngine,

    /// Secret detector
    secrets: SecretDetector,

    /// SLSA verifier
    slsa: SlsaVerifier,

    /// AI analyzer
    ai: ai::AiAnalyzer,
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: Config) -> Result<Self> {
        // Initialize GitHub client if token is available
        let github = if config.github.token.is_some() {
            Some(GitHubClient::new(config.github.clone())?)
        } else {
            warn!("No GitHub token provided. Some features may be limited.");
            None
        };

        // Initialize Git operations
        let temp_dir = config
            .analysis
            .temp_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("sec_auditor"));
        let git = GitOperations::new(temp_dir);

        // Initialize SAST engine
        let sast = SastEngine::new(config.analysis.clone())?;

        // Initialize other components
        let sca = ScaEngine::new();
        let secrets = SecretDetector::new(config.analysis.entropy_threshold);
        let slsa = SlsaVerifier::new();
        let ai = ai::AiAnalyzer::new();

        Ok(Self {
            config,
            github,
            git,
            sast,
            sca,
            secrets,
            slsa,
            ai,
        })
    }

    /// Scan a repository by owner/name.
    pub async fn scan_repository(&self, repo_spec: &str) -> Result<ScanResult> {
        let target = ScanTarget::parse(repo_spec);

        match target {
            ScanTarget::Repository(repo) => self.scan_github_repo(repo).await,
            ScanTarget::LocalPath(path) => self.scan_local_path(&path).await,
            ScanTarget::Organization(org) => self.scan_organization(&org).await,
            ScanTarget::User(user) => self.scan_user(&user).await,
            ScanTarget::Search(query) => self.scan_search(&query).await,
        }
    }

    /// Scan a GitHub repository.
    async fn scan_github_repo(&self, mut repo: Repository) -> Result<ScanResult> {
        let start_time = Instant::now();
        info!("Starting scan of repository: {}", repo.full_name);

        let mut result = ScanResult::new(&repo.full_name);

        // Get repository metadata if we have a GitHub client
        if let Some(ref github) = self.github {
            match github.get_repository(&repo.owner, &repo.name).await {
                Ok(metadata) => {
                    repo = metadata;
                    result.commit_sha = repo.commit_sha.clone();
                }
                Err(e) => {
                    warn!("Could not fetch repository metadata: {}", e);
                }
            }
        }

        // Clone the repository
        let local_path = self.git.clone_repository(&mut repo)?;

        // Perform the scan
        let scan_result = self.scan_local_path(&local_path).await?;

        // Merge results
        result.findings = scan_result.findings;
        result.stats = scan_result.stats;
        result.completed_at = chrono::Utc::now();
        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        // Clean up if configured
        if self.config.analysis.temp_dir.is_none() {
            // Only clean up if using system temp dir
            if let Err(e) = self.git.cleanup(&repo) {
                warn!("Failed to clean up cloned repository: {}", e);
            }
        }

        Ok(result)
    }

    /// Scan a local directory.
    pub async fn scan_local_path(&self, path: &Path) -> Result<ScanResult> {
        let start_time = Instant::now();
        info!("Starting scan of local path: {}", path.display());

        let mut result = ScanResult::new(path.display().to_string());

        // Get commit SHA if it's a git repository
        if let Ok(sha) = GitOperations::get_head_sha(path) {
            result.commit_sha = Some(sha);
        }

        // Get source files
        let traverser = RepoTraverser::new(path);
        let mut files = traverser.get_source_files(path)?;

        result.stats.files_scanned = files.len();
        result.stats.lines_analyzed = files.iter().map(|f| f.size as usize / 40).sum(); // Rough estimate

        // Run SAST analysis
        if self.config.analysis.enable_sast {
            info!("Running SAST analysis on {} files", files.len());
            match self.sast.analyze_files(&mut files) {
                Ok(findings) => {
                    result.stats.sast_findings = findings.len();
                    for finding in findings {
                        result.add_finding(finding);
                    }
                }
                Err(e) => {
                    error!("SAST analysis failed: {}", e);
                }
            }
        }

        // Run secret detection
        if self.config.analysis.enable_secrets {
            info!("Running secret detection");
            for file in &mut files {
                let file_path = file.path.clone();
                let language = file.language;

                if let Ok(content) = file.load_content() {
                    let content = content.to_string();
                    let secret_findings = self.secrets.detect(&content, &file_path, language);
                    for finding in secret_findings {
                        result.add_finding(finding);
                    }
                }
            }
        }

        // Run SCA analysis
        if self.config.analysis.enable_sca {
            info!("Running SCA analysis");
            match self.sca.analyze_repository(path).await {
                Ok(findings) => {
                    result.stats.sca_findings = findings.len();
                    for finding in findings {
                        result.add_finding(finding);
                    }
                }
                Err(e) => {
                    warn!("SCA analysis failed: {}", e);
                }
            }
        }

        // Run AI analysis if enabled
        if self.config.analysis.enable_ai && self.ai.is_available() {
            info!("Running AI-driven analysis");
            for file in &mut files {
                let file_path = file.path.clone();
                let language = file.language;

                if let Ok(content) = file.load_content() {
                    let content = content.to_string();
                    let context = ai::AnalysisContext {
                        file_path: file_path.clone(),
                        ..Default::default()
                    };

                    match self.ai.analyze_snippet(&content, language, &context).await {
                        Ok(findings) => {
                            for finding in findings {
                                result.add_finding(finding);
                            }
                        }
                        Err(e) => {
                            debug!("AI analysis failed for {}: {}", file_path.display(), e);
                        }
                    }
                }
            }
        }

        // Run provenance verification if enabled
        if self.config.analysis.enable_provenance {
            info!("Running provenance verification");
            match self.verify_provenance(path).await {
                Ok(findings) => {
                    for finding in findings {
                        result.add_finding(finding);
                    }
                }
                Err(e) => {
                    warn!("Provenance verification failed: {}", e);
                }
            }
        }

        result.completed_at = chrono::Utc::now();
        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Scan complete. Found {} findings in {}ms",
            result.findings.len(),
            result.stats.duration_ms
        );

        Ok(result)
    }

    /// Scan all repositories in an organization.
    async fn scan_organization(&self, org: &str) -> Result<ScanResult> {
        let github = self
            .github
            .as_ref()
            .ok_or_else(|| AuditorError::AuthRequired)?;

        let repos = github
            .list_org_repos(org, self.config.github.max_repos)
            .await?;

        self.scan_multiple_repos(repos).await
    }

    /// Scan all repositories for a user.
    async fn scan_user(&self, user: &str) -> Result<ScanResult> {
        let github = self
            .github
            .as_ref()
            .ok_or_else(|| AuditorError::AuthRequired)?;

        let repos = github
            .list_user_repos(user, self.config.github.max_repos)
            .await?;

        self.scan_multiple_repos(repos).await
    }

    /// Scan repositories matching a search query.
    async fn scan_search(&self, query: &str) -> Result<ScanResult> {
        let github = self
            .github
            .as_ref()
            .ok_or_else(|| AuditorError::AuthRequired)?;

        let repos = github
            .search_repos(query, self.config.github.max_repos)
            .await?;

        self.scan_multiple_repos(repos).await
    }

    /// Scan multiple repositories and aggregate results.
    async fn scan_multiple_repos(&self, repos: Vec<Repository>) -> Result<ScanResult> {
        let start_time = Instant::now();
        let mut combined_result = ScanResult::new(format!("{} repositories", repos.len()));

        for repo in repos {
            if repo.archived {
                debug!("Skipping archived repository: {}", repo.full_name);
                continue;
            }

            match self.scan_github_repo(repo.clone()).await {
                Ok(result) => {
                    combined_result.stats.files_scanned += result.stats.files_scanned;
                    combined_result.stats.lines_analyzed += result.stats.lines_analyzed;
                    combined_result.stats.sast_findings += result.stats.sast_findings;
                    combined_result.stats.sca_findings += result.stats.sca_findings;
                    combined_result.stats.secrets_found += result.stats.secrets_found;

                    for mut finding in result.findings {
                        // Prefix finding location with repo name
                        finding.location.file = std::path::PathBuf::from(&repo.full_name)
                            .join(&finding.location.file);
                        combined_result.add_finding(finding);
                    }
                }
                Err(e) => {
                    warn!("Failed to scan {}: {}", repo.full_name, e);
                }
            }

            // Rate limiting
            if let Some(ref github) = self.github {
                github.rate_limit_delay().await;
            }
        }

        combined_result.completed_at = chrono::Utc::now();
        combined_result.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(combined_result)
    }

    /// Verify provenance for dependencies.
    pub async fn verify_provenance(&self, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let cargo_lock = path.join("Cargo.lock");
        if cargo_lock.exists() {
            let lockfile = cargo_lock::Lockfile::load(&cargo_lock)?;

            for package in &lockfile.packages {
                let provenance = self
                    .slsa
                    .verify_crate(package.name.as_str(), &package.version.to_string())
                    .await?;

                findings.extend(
                    self.slsa
                        .generate_findings(package.name.as_str(), &provenance),
                );
            }
        }

        Ok(findings)
    }
}

/// Create a default scanner with environment-based configuration.
pub fn create_scanner() -> Result<Scanner> {
    let config = Config::default();
    Scanner::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = Config::builder()
            .enable_sast(true)
            .enable_sca(true)
            .build();

        let scanner = Scanner::new(config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scan_target_parsing() {
        assert!(matches!(
            ScanTarget::parse("owner/repo"),
            ScanTarget::Repository(_)
        ));

        assert!(matches!(
            ScanTarget::parse("https://github.com/owner/repo"),
            ScanTarget::Repository(_)
        ));

        assert!(matches!(
            ScanTarget::parse("org:myorg"),
            ScanTarget::Organization(_)
        ));

        assert!(matches!(
            ScanTarget::parse("user:myuser"),
            ScanTarget::User(_)
        ));
    }
}
