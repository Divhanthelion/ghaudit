//! sec_auditor - High-Performance Rust Security Analysis Engine

pub mod ai;
pub mod analyzer;
pub mod cache;
pub mod config;
pub mod crawler;
pub mod error;
pub mod models;
pub mod provenance;
pub mod reporter;

pub use config::{Config, OutputFormat};
pub use error::{AuditorError, Result};
pub use models::{Finding, Repository, ScanResult, ScanStats, Severity, Vulnerability};

use analyzer::{SastEngine, ScaEngine, SecretDetector};
use cache::{Cache, compute_content_hash};
use crawler::{GitHubClient, GitOperations, RepoTraverser};
use models::ScanTarget;
use provenance::SlsaVerifier;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Main scanner orchestrating all analysis components.
pub struct Scanner {
    config: Config,
    github: Option<GitHubClient>,
    git: GitOperations,
    sast: SastEngine,
    sca: ScaEngine,
    secrets: SecretDetector,
    slsa: SlsaVerifier,
    ai: ai::AiAnalyzer,
    cache: Option<Mutex<Cache>>,
}

impl Scanner {
    /// Create a new scanner with the given configuration.
    pub fn new(config: Config) -> Result<Self> {
        let github = if config.github.token.is_some() {
            Some(GitHubClient::new(config.github.clone())?)
        } else {
            warn!("No GitHub token provided. Some features may be limited.");
            None
        };

        let temp_dir = config
            .analysis
            .temp_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("sec_auditor"));
        let git = GitOperations::new(temp_dir);
        let sast = SastEngine::new(config.analysis.clone())?;
        let sca = ScaEngine::new();
        let secrets = SecretDetector::new(config.analysis.entropy_threshold);
        let slsa = SlsaVerifier::new();
        let ai = ai::AiAnalyzer::new();

        // Initialize cache if enabled
        let cache = if std::env::var("SEC_AUDITOR_NO_CACHE").is_err() {
            match Cache::default_cache() {
                Ok(cache) => {
                    info!("Cache initialized at {:?}", cache.stats().cache_dir);
                    Some(Mutex::new(cache))
                }
                Err(e) => {
                    warn!("Failed to initialize cache: {}", e);
                    None
                }
            }
        } else {
            info!("Cache disabled via SEC_AUDITOR_NO_CACHE");
            None
        };

        Ok(Self {
            config,
            github,
            git,
            sast,
            sca,
            secrets,
            slsa,
            ai,
            cache,
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

        let local_path = self.git.clone_repository(&mut repo)?;
        let scan_result = self.scan_local_path(&local_path).await?;

        result.findings = scan_result.findings;
        result.stats = scan_result.stats;
        result.completed_at = chrono::Utc::now();
        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        if self.config.analysis.temp_dir.is_none() {
            if let Err(e) = self.git.cleanup(&repo) {
                warn!("Failed to clean up cloned repository: {}", e);
            }
        }

        Ok(result)
    }

    /// Scan a local directory with concurrent analysis phases.
    pub async fn scan_local_path(&self, path: &Path) -> Result<ScanResult> {
        let start_time = Instant::now();
        info!("Starting scan of local path: {}", path.display());

        let mut result = ScanResult::new(path.display().to_string());

        // Get commit SHA for caching
        let commit_sha = GitOperations::get_head_sha(path).ok();
        result.commit_sha = commit_sha.clone();

        // Check for cached scan result
        if let Some(ref cache_mutex) = self.cache {
            let cache = cache_mutex.lock().await;
            let file_hashes = self.compute_file_hashes(path).await?;
            
            if let Some(cached) = cache.get_scan_result(&result.repository, commit_sha.as_deref().unwrap_or(""), &file_hashes) {
                info!("Using cached scan result for {}", result.repository);
                let mut cached_result = result.clone();
                cached_result.findings = cached.findings.clone();
                cached_result.stats = ScanStats {
                    files_scanned: cached.file_hashes.len(),
                    ..Default::default()
                };
                cached_result.completed_at = chrono::Utc::now();
                return Ok(cached_result);
            }
        }

        let traverser = RepoTraverser::new(path);
        let mut files = traverser.get_source_files(path)?;
        
        // Calculate actual lines analyzed
        let total_lines: usize = files
            .iter()
            .filter_map(|f| std::fs::read_to_string(&f.absolute_path).ok())
            .map(|content| content.lines().count())
            .sum();

        result.stats.files_scanned = files.len();
        result.stats.lines_analyzed = total_lines;

        // Run analysis phases concurrently using tokio::join!
        let (sast_findings, secret_findings, sca_findings, ai_findings, provenance_findings) = tokio::join!(
            self.run_sast_analysis(&files),
            self.run_secret_detection(&files),
            self.run_sca_analysis(path),
            self.run_ai_analysis(&files),
            self.run_provenance_analysis(path),
        );

        // Collect SAST findings
        match sast_findings {
            Ok(findings) => {
                result.stats.sast_findings = findings.len();
                for finding in findings {
                    result.add_finding(finding);
                }
            }
            Err(e) => error!("SAST analysis failed: {}", e),
        }

        // Collect secret findings
        match secret_findings {
            Ok(findings) => {
                for finding in findings {
                    result.add_finding(finding);
                }
            }
            Err(e) => error!("Secret detection failed: {}", e),
        }

        // Collect SCA findings
        match sca_findings {
            Ok(findings) => {
                result.stats.sca_findings = findings.len();
                for finding in findings {
                    result.add_finding(finding);
                }
            }
            Err(e) => warn!("SCA analysis failed: {}", e),
        }

        // Collect AI findings
        match ai_findings {
            Ok(findings) => {
                for finding in findings {
                    result.add_finding(finding);
                }
            }
            Err(e) => debug!("AI analysis failed: {}", e),
        }

        // Collect provenance findings
        match provenance_findings {
            Ok(findings) => {
                for finding in findings {
                    result.add_finding(finding);
                }
            }
            Err(e) => warn!("Provenance verification failed: {}", e),
        }

        result.completed_at = chrono::Utc::now();
        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        // Cache the result
        if let Some(ref cache_mutex) = self.cache {
            let mut cache = cache_mutex.lock().await;
            let file_hashes = self.compute_file_hashes(path).await?;
            let _ = cache.put_scan_result(
                &result.repository,
                commit_sha.as_deref().unwrap_or(""),
                result.findings.clone(),
                file_hashes,
            );
        }

        info!(
            "Scan complete. Found {} findings in {}ms",
            result.findings.len(),
            result.stats.duration_ms
        );

        Ok(result)
    }

    /// Compute content hashes for all source files (for caching).
    async fn compute_file_hashes(&self, path: &Path) -> Result<HashMap<PathBuf, String>> {
        let traverser = RepoTraverser::new(path);
        let files = traverser.get_source_files(path)?;
        
        let mut hashes = HashMap::with_capacity(files.len());
        for file in files {
            if let Ok(content) = tokio::fs::read_to_string(&file.absolute_path).await {
                hashes.insert(file.path, compute_content_hash(&content));
            }
        }
        
        Ok(hashes)
    }

    /// Run SAST analysis (concurrent task).
    async fn run_sast_analysis(&self, files: &[crate::models::SourceFile]) -> Result<Vec<Finding>> {
        if !self.config.analysis.enable_sast {
            return Ok(Vec::new());
        }
        
        info!("Running SAST analysis on {} files", files.len());
        
        // Clone files for analysis (they need to be mutable)
        let mut files: Vec<_> = files.to_vec();
        self.sast.analyze_files(&mut files)
    }

    /// Run secret detection (concurrent task).
    async fn run_secret_detection(&self, files: &[crate::models::SourceFile]) -> Result<Vec<Finding>> {
        if !self.config.analysis.enable_secrets {
            return Ok(Vec::new());
        }
        
        info!("Running secret detection");
        let mut findings = Vec::new();
        
        for file in files {
            let file_path = &file.path;
            let language = file.language;

            // Skip test/fixture/example directories for secret detection (high FP rate)
            let path_str = file_path.to_string_lossy().to_lowercase();
            if is_test_file(&path_str) {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&file.absolute_path) {
                let secret_findings = self.secrets.detect(&content, file_path, language);
                findings.extend(secret_findings);
            }
        }
        
        Ok(findings)
    }

    /// Run SCA analysis (concurrent task).
    async fn run_sca_analysis(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.config.analysis.enable_sca {
            return Ok(Vec::new());
        }
        
        info!("Running SCA analysis");
        self.sca.analyze_repository(path).await
    }

    /// Run AI analysis (concurrent task).
    async fn run_ai_analysis(&self, files: &[crate::models::SourceFile]) -> Result<Vec<Finding>> {
        if !self.config.analysis.enable_ai {
            return Ok(Vec::new());
        }
        
        // Check if AI is available
        if !self.ai.is_available().await {
            debug!("AI analysis skipped - LM Studio not available");
            return Ok(Vec::new());
        }
        
        info!("Running AI-driven analysis on {} files", files.len());
        let mut findings = Vec::new();
        
        for file in files {
            let file_path = file.path.clone();
            let language = file.language;

            if let Ok(content) = std::fs::read_to_string(&file.absolute_path) {
                let context = ai::AnalysisContext {
                    file_path: file_path.clone(),
                    ..Default::default()
                };

                match self.ai.analyze_snippet(&content, language, &context).await {
                    Ok(ai_findings) => {
                        findings.extend(ai_findings);
                    }
                    Err(e) => {
                        debug!("AI analysis failed for {}: {}", file_path.display(), e);
                    }
                }
            }
        }
        
        Ok(findings)
    }

    /// Run provenance analysis (concurrent task).
    async fn run_provenance_analysis(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.config.analysis.enable_provenance {
            return Ok(Vec::new());
        }
        
        info!("Running provenance verification");
        self.verify_provenance(path).await
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
                        finding.location.file = std::path::PathBuf::from(&repo.full_name)
                            .join(&finding.location.file);
                        combined_result.add_finding(finding);
                    }
                }
                Err(e) => {
                    warn!("Failed to scan {}: {}", repo.full_name, e);
                }
            }

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

/// Check if a file path is a test file (to reduce false positives).
fn is_test_file(path_str: &str) -> bool {
    path_str.contains("/test/")
        || path_str.contains("/tests/")
        || path_str.contains("/__tests__/")
        || path_str.contains("/fixtures/")
        || path_str.contains("/test_")
        || path_str.ends_with("_test.py")
        || path_str.ends_with("_test.go")
        || path_str.ends_with(".test.js")
        || path_str.ends_with(".test.ts")
        || path_str.ends_with(".spec.js")
        || path_str.ends_with(".spec.ts")
        || path_str.ends_with("_spec.rb")
        || path_str.ends_with("_test.rs")
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
