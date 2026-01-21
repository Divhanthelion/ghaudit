//! GitHub API client using octocrab.

use crate::config::GitHubConfig;
use crate::error::{AuditorError, Result};
use crate::models::Repository;
use octocrab::Octocrab;
use tracing::{debug, info, warn};

/// GitHub API client for discovering and fetching repository metadata.
pub struct GitHubClient {
    client: Octocrab,
    config: GitHubConfig,
}

impl GitHubClient {
    /// Create a new GitHub client.
    pub fn new(config: GitHubConfig) -> Result<Self> {
        let mut builder = Octocrab::builder();

        if let Some(ref token) = config.token {
            builder = builder.personal_token(token.clone());
        }

        if config.api_url != "https://api.github.com" {
            builder = builder.base_uri(&config.api_url)?;
        }

        let client = builder.build()?;

        Ok(Self { client, config })
    }

    /// Create a client from environment variables.
    pub fn from_env() -> Result<Self> {
        Self::new(GitHubConfig::default())
    }

    /// Get repository metadata.
    pub async fn get_repository(&self, owner: &str, name: &str) -> Result<Repository> {
        info!("Fetching repository metadata: {}/{}", owner, name);

        let repo = self
            .client
            .repos(owner, name)
            .get()
            .await
            .map_err(|e| AuditorError::GitHub(format!("Failed to get repo {}/{}: {}", owner, name, e)))?;

        let mut repository = Repository::new(owner, name);

        repository.default_branch = repo
            .default_branch
            .clone()
            .unwrap_or_else(|| "main".to_string());
        repository.description = repo.description.clone();
        repository.language = repo.language.as_ref().and_then(|v| v.as_str()).map(|s| s.to_string());
        repository.stars = repo.stargazers_count.unwrap_or(0) as u64;
        repository.forks = repo.forks_count.unwrap_or(0) as u64;
        repository.archived = repo.archived.unwrap_or(false);
        repository.is_fork = repo.fork.unwrap_or(false);
        repository.topics = repo.topics.clone().unwrap_or_default();
        repository.updated_at = repo.updated_at;

        if let Some(ref html_url) = repo.html_url {
            repository.url = html_url.to_string();
        }
        if let Some(ref clone_url) = repo.clone_url {
            repository.clone_url = clone_url.to_string();
        }

        // Get latest commit SHA
        if let Ok(commits) = self
            .client
            .repos(owner, name)
            .list_commits()
            .per_page(1)
            .send()
            .await
        {
            if let Some(commit) = commits.items.first() {
                repository.commit_sha = Some(commit.sha.clone());
            }
        }

        // Get languages
        if let Ok(languages) = self.get_languages(owner, name).await {
            repository.languages = languages;
        }

        debug!("Repository metadata fetched: {:?}", repository);
        Ok(repository)
    }

    /// Get languages used in a repository.
    pub async fn get_languages(&self, owner: &str, name: &str) -> Result<Vec<String>> {
        let languages = self
            .client
            .repos(owner, name)
            .list_languages()
            .await
            .map_err(|e| AuditorError::GitHub(format!("Failed to get languages: {}", e)))?;

        Ok(languages.into_keys().collect())
    }

    /// List repositories for a user.
    pub async fn list_user_repos(&self, username: &str, limit: usize) -> Result<Vec<Repository>> {
        info!("Listing repositories for user: {}", username);

        let page = self
            .client
            .users(username)
            .repos()
            .per_page(limit.min(100) as u8)
            .send()
            .await?;

        let mut repos = Vec::new();
        for repo in page.items.into_iter().take(limit) {
            if let (Some(owner), name) = (repo.owner, repo.name) {
                let mut repository = Repository::new(owner.login, name);
                repository.default_branch = repo.default_branch.unwrap_or_else(|| "main".to_string());
                repository.description = repo.description;
                repository.language = repo.language.as_ref().and_then(|v| v.as_str()).map(|s| s.to_string());
                repository.archived = repo.archived.unwrap_or(false);
                repository.is_fork = repo.fork.unwrap_or(false);
                if let Some(ref clone_url) = repo.clone_url {
                    repository.clone_url = clone_url.to_string();
                }
                repos.push(repository);
            }
        }

        info!("Found {} repositories for user {}", repos.len(), username);
        Ok(repos)
    }

    /// List repositories for an organization.
    pub async fn list_org_repos(&self, org: &str, limit: usize) -> Result<Vec<Repository>> {
        info!("Listing repositories for organization: {}", org);

        let page = self
            .client
            .orgs(org)
            .list_repos()
            .per_page(limit.min(100) as u8)
            .send()
            .await?;

        let mut repos = Vec::new();
        for repo in page.items.into_iter().take(limit) {
            if let (Some(owner), name) = (repo.owner, repo.name) {
                let mut repository = Repository::new(owner.login, name);
                repository.default_branch = repo.default_branch.unwrap_or_else(|| "main".to_string());
                repository.description = repo.description;
                repository.language = repo.language.as_ref().and_then(|v| v.as_str()).map(|s| s.to_string());
                repository.archived = repo.archived.unwrap_or(false);
                repository.is_fork = repo.fork.unwrap_or(false);
                if let Some(ref clone_url) = repo.clone_url {
                    repository.clone_url = clone_url.to_string();
                }
                repos.push(repository);
            }
        }

        info!("Found {} repositories for org {}", repos.len(), org);
        Ok(repos)
    }

    /// Search for repositories.
    pub async fn search_repos(&self, query: &str, limit: usize) -> Result<Vec<Repository>> {
        info!("Searching repositories: {}", query);

        let page = self
            .client
            .search()
            .repositories(query)
            .per_page(limit.min(100) as u8)
            .send()
            .await?;

        let mut repos = Vec::new();
        for repo in page.items.into_iter().take(limit) {
            if let (Some(owner), name) = (repo.owner, repo.name) {
                let mut repository = Repository::new(owner.login, name);
                repository.default_branch = repo.default_branch.unwrap_or_else(|| "main".to_string());
                repository.description = repo.description;
                repository.language = repo.language.as_ref().and_then(|v| v.as_str()).map(|s| s.to_string());
                repository.stars = repo.stargazers_count.unwrap_or(0) as u64;
                repository.forks = repo.forks_count.unwrap_or(0) as u64;
                repository.archived = repo.archived.unwrap_or(false);
                repository.is_fork = repo.fork.unwrap_or(false);
                if let Some(ref clone_url) = repo.clone_url {
                    repository.clone_url = clone_url.to_string();
                }
                repos.push(repository);
            }
        }

        info!("Found {} repositories matching '{}'", repos.len(), query);
        Ok(repos)
    }

    /// Get security advisories for a repository.
    pub async fn get_security_advisories(
        &self,
        owner: &str,
        name: &str,
    ) -> Result<Vec<SecurityAdvisory>> {
        debug!("Fetching security advisories for {}/{}", owner, name);

        // Use the GraphQL API or REST API for security advisories
        // For now, we'll use the REST API vulnerability alerts endpoint
        let url = format!(
            "{}/repos/{}/{}/vulnerability-alerts",
            self.config.api_url, owner, name
        );

        // This endpoint requires special headers
        let response: std::result::Result<serde_json::Value, _> = self
            .client
            .get(&url, None::<&()>)
            .await;

        match response {
            Ok(value) => {
                debug!("Security advisories response: {:?}", value);
                // Parse the response into advisories
                Ok(Vec::new()) // Placeholder - actual parsing depends on response format
            }
            Err(e) => {
                warn!("Could not fetch security advisories: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Check rate limit status.
    pub async fn check_rate_limit(&self) -> Result<RateLimitStatus> {
        let rate_limit = self.client.ratelimit().get().await?;

        Ok(RateLimitStatus {
            limit: rate_limit.resources.core.limit as u32,
            remaining: rate_limit.resources.core.remaining as u32,
            reset: rate_limit.resources.core.reset as u64,
        })
    }

    /// Apply rate limiting delay if needed.
    pub async fn rate_limit_delay(&self) {
        if self.config.rate_limit_delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                self.config.rate_limit_delay_ms,
            ))
            .await;
        }
    }
}

/// GitHub security advisory.
#[derive(Debug, Clone)]
pub struct SecurityAdvisory {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub severity: String,
    pub summary: String,
    pub description: Option<String>,
    pub vulnerabilities: Vec<AdvisoryVulnerability>,
}

/// Vulnerability within a security advisory.
#[derive(Debug, Clone)]
pub struct AdvisoryVulnerability {
    pub package: String,
    pub ecosystem: String,
    pub vulnerable_version_range: String,
    pub first_patched_version: Option<String>,
}

/// Rate limit status.
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    pub limit: u32,
    pub remaining: u32,
    pub reset: u64,
}

impl RateLimitStatus {
    /// Check if we're rate limited.
    pub fn is_limited(&self) -> bool {
        self.remaining == 0
    }

    /// Seconds until reset.
    pub fn seconds_until_reset(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.reset.saturating_sub(now)
    }
}
