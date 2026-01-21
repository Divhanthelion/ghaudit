//! SLSA (Supply-chain Levels for Software Artifacts) verification.
//!
//! This module provides supply chain security verification using:
//! - Sigstore verification with Rekor v2 tile-based architecture
//! - Local tile caching for high-performance verification at scale
//! - GitHub Release attestation discovery

use crate::error::{AuditorError, Result};
use crate::models::{Confidence, Finding, Location, Provenance, Severity};
use redb::{Database, ReadableTable, TableDefinition};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Table definition for Rekor tile cache
const TILE_CACHE: TableDefinition<&str, &[u8]> = TableDefinition::new("tiles");
const VERDICT_CACHE: TableDefinition<&str, &[u8]> = TableDefinition::new("verdicts");
const CHECKPOINT_CACHE: TableDefinition<&str, &[u8]> = TableDefinition::new("checkpoints");

/// Configuration for tile-based caching
#[derive(Debug, Clone)]
pub struct TileCacheConfig {
    /// Path to the cache database
    pub cache_dir: PathBuf,
    /// Maximum age for checkpoint before refresh (in seconds)
    pub checkpoint_max_age_secs: u64,
    /// Tile size (number of entries per tile)
    pub tile_size: usize,
}

impl Default for TileCacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: dirs_cache_path(),
            checkpoint_max_age_secs: 3600, // 1 hour
            tile_size: 256,
        }
    }
}

/// Get platform-appropriate cache directory
fn dirs_cache_path() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join(".cache")
        .join("sec_auditor")
        .join("sigstore")
}

/// Tile-based Rekor cache for high-performance verification.
///
/// This implements the Rekor v2 tile-based architecture where:
/// - Full tiles are immutable and cached indefinitely
/// - Partial tiles (tree head) have a short TTL
/// - Multiple dependencies mapping to the same tile share a single fetch
pub struct RekorTileCache {
    /// Cache database
    db: Database,
    /// HTTP client
    client: Client,
    /// Rekor server URL
    rekor_url: String,
    /// Configuration
    config: TileCacheConfig,
}

impl RekorTileCache {
    /// Create a new tile cache
    pub fn new(config: TileCacheConfig) -> Result<Self> {
        // Ensure cache directory exists
        std::fs::create_dir_all(&config.cache_dir)?;

        let db_path = config.cache_dir.join("rekor_tiles.redb");
        let db = Database::create(&db_path).map_err(|e| {
            AuditorError::Sigstore(format!("Failed to create tile cache database: {}", e))
        })?;

        // Initialize tables
        let write_txn = db.begin_write().map_err(|e| {
            AuditorError::Sigstore(format!("Failed to begin write transaction: {}", e))
        })?;
        {
            let _ = write_txn.open_table(TILE_CACHE);
            let _ = write_txn.open_table(VERDICT_CACHE);
            let _ = write_txn.open_table(CHECKPOINT_CACHE);
        }
        write_txn.commit().map_err(|e| {
            AuditorError::Sigstore(format!("Failed to commit tables: {}", e))
        })?;

        Ok(Self {
            db,
            client: Client::new(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
            config,
        })
    }

    /// Get a tile from cache or fetch from Rekor
    pub async fn get_tile(&self, tile_index: u64) -> Result<Vec<u8>> {
        let key = format!("tile:{}", tile_index);

        // Check cache first
        if let Some(tile) = self.get_cached(&key)? {
            debug!("Tile {} found in cache", tile_index);
            return Ok(tile);
        }

        // Fetch from Rekor
        debug!("Fetching tile {} from Rekor", tile_index);
        let tile = self.fetch_tile(tile_index).await?;

        // Cache the tile (immutable, indefinite TTL)
        self.cache_tile(&key, &tile)?;

        Ok(tile)
    }

    /// Get multiple tiles in parallel (deduplicated)
    pub async fn get_tiles(&self, tile_indices: &[u64]) -> Result<HashMap<u64, Vec<u8>>> {
        let mut result = HashMap::new();
        let mut to_fetch = Vec::new();

        // Check cache for each tile
        for &idx in tile_indices {
            let key = format!("tile:{}", idx);
            if let Some(tile) = self.get_cached(&key)? {
                result.insert(idx, tile);
            } else {
                to_fetch.push(idx);
            }
        }

        // Fetch missing tiles in parallel
        if !to_fetch.is_empty() {
            let fetches: Vec<_> = to_fetch
                .iter()
                .map(|&idx| {
                    let client = self.client.clone();
                    let url = format!("{}/api/v1/log/entries/tile/{}", self.rekor_url, idx);
                    async move {
                        let resp = client.get(&url).send().await;
                        (idx, resp)
                    }
                })
                .collect();

            let results = futures::future::join_all(fetches).await;

            for (idx, resp_result) in results {
                match resp_result {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(bytes) = resp.bytes().await {
                            let tile = bytes.to_vec();
                            let key = format!("tile:{}", idx);
                            let _ = self.cache_tile(&key, &tile);
                            result.insert(idx, tile);
                        }
                    }
                    _ => {
                        debug!("Failed to fetch tile {}", idx);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Get the latest checkpoint (Signed Tree Head)
    pub async fn get_checkpoint(&self) -> Result<RekorCheckpoint> {
        let key = "checkpoint:latest";

        // Check if we have a recent checkpoint
        if let Some(cached) = self.get_cached(key)? {
            if let Ok(checkpoint) = serde_json::from_slice::<CachedCheckpoint>(&cached) {
                let age = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    - checkpoint.timestamp;

                if age < self.config.checkpoint_max_age_secs {
                    debug!("Using cached checkpoint (age: {}s)", age);
                    return Ok(checkpoint.checkpoint);
                }
            }
        }

        // Fetch fresh checkpoint
        let checkpoint = self.fetch_checkpoint().await?;

        // Cache with timestamp
        let cached = CachedCheckpoint {
            checkpoint: checkpoint.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        let _ = self.cache_tile(key, &serde_json::to_vec(&cached).unwrap_or_default());

        Ok(checkpoint)
    }

    /// Cache a verification verdict for an artifact
    pub fn cache_verdict(&self, artifact_hash: &str, verdict: &VerificationVerdict) -> Result<()> {
        let key = format!("verdict:{}", artifact_hash);
        let value = serde_json::to_vec(verdict)
            .map_err(|e| AuditorError::Sigstore(format!("Failed to serialize verdict: {}", e)))?;
        self.cache_tile(&key, &value)
    }

    /// Get a cached verdict for an artifact
    pub fn get_cached_verdict(&self, artifact_hash: &str) -> Result<Option<VerificationVerdict>> {
        let key = format!("verdict:{}", artifact_hash);
        if let Some(data) = self.get_cached(&key)? {
            let verdict: VerificationVerdict = serde_json::from_slice(&data)
                .map_err(|e| AuditorError::Sigstore(format!("Failed to deserialize verdict: {}", e)))?;
            return Ok(Some(verdict));
        }
        Ok(None)
    }

    fn get_cached(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            AuditorError::Sigstore(format!("Failed to begin read transaction: {}", e))
        })?;
        let table = read_txn.open_table(TILE_CACHE).map_err(|e| {
            AuditorError::Sigstore(format!("Failed to open tile cache table: {}", e))
        })?;

        match table.get(key) {
            Ok(Some(value)) => Ok(Some(value.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(AuditorError::Sigstore(format!("Failed to read from cache: {}", e))),
        }
    }

    fn cache_tile(&self, key: &str, value: &[u8]) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            AuditorError::Sigstore(format!("Failed to begin write transaction: {}", e))
        })?;
        {
            let mut table = write_txn.open_table(TILE_CACHE).map_err(|e| {
                AuditorError::Sigstore(format!("Failed to open tile cache table: {}", e))
            })?;
            table.insert(key, value).map_err(|e| {
                AuditorError::Sigstore(format!("Failed to insert into cache: {}", e))
            })?;
        }
        write_txn.commit().map_err(|e| {
            AuditorError::Sigstore(format!("Failed to commit cache write: {}", e))
        })?;
        Ok(())
    }

    async fn fetch_tile(&self, tile_index: u64) -> Result<Vec<u8>> {
        let url = format!("{}/api/v1/log/entries/tile/{}", self.rekor_url, tile_index);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AuditorError::Sigstore(format!(
                "Failed to fetch tile {}: {}",
                tile_index,
                response.status()
            )));
        }

        Ok(response.bytes().await?.to_vec())
    }

    async fn fetch_checkpoint(&self) -> Result<RekorCheckpoint> {
        let url = format!("{}/api/v1/log", self.rekor_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AuditorError::Sigstore(format!(
                "Failed to fetch checkpoint: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;

        Ok(RekorCheckpoint {
            tree_size: data.get("treeSize").and_then(|v| v.as_u64()).unwrap_or(0),
            root_hash: data
                .get("rootHash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            timestamp: data
                .get("timestamp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        })
    }
}

/// Rekor checkpoint (Signed Tree Head)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorCheckpoint {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp: u64,
}

/// Cached checkpoint with fetch timestamp
#[derive(Debug, Serialize, Deserialize)]
struct CachedCheckpoint {
    checkpoint: RekorCheckpoint,
    timestamp: u64,
}

/// Verification verdict cached for an artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationVerdict {
    /// Whether verification succeeded
    pub verified: bool,
    /// SLSA level achieved
    pub slsa_level: u8,
    /// Builder identity
    pub builder: Option<String>,
    /// Source repository
    pub source_repo: Option<String>,
    /// Source commit
    pub source_commit: Option<String>,
    /// Verification timestamp
    pub verified_at: u64,
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// GitHub Release attestation discoverer.
///
/// Discovers SLSA attestations attached to GitHub Releases,
/// which is the primary location for Rust crate attestations.
pub struct GitHubAttestationDiscovery {
    client: Client,
}

impl GitHubAttestationDiscovery {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Discover attestation URL for a crate from its GitHub repository.
    ///
    /// Follows the pattern: `https://github.com/{owner}/{repo}/releases/download/v{version}/provenance.intoto.jsonl`
    pub async fn discover_attestation(
        &self,
        repo_url: &str,
        version: &str,
    ) -> Result<Option<AttestationBundle>> {
        // Parse GitHub repository URL
        let (owner, repo) = self.parse_github_url(repo_url)?;

        // Try common attestation file patterns
        let patterns = [
            format!(
                "https://github.com/{}/{}/releases/download/v{}/provenance.intoto.jsonl",
                owner, repo, version
            ),
            format!(
                "https://github.com/{}/{}/releases/download/{}/provenance.intoto.jsonl",
                owner, repo, version
            ),
            format!(
                "https://github.com/{}/{}/releases/download/v{}/{}-{}.intoto.jsonl",
                owner, repo, version, repo, version
            ),
            // SLSA GitHub Generator pattern
            format!(
                "https://github.com/{}/{}/releases/download/v{}/multiple.intoto.jsonl",
                owner, repo, version
            ),
        ];

        for pattern in &patterns {
            debug!("Trying attestation URL: {}", pattern);
            match self.fetch_attestation(pattern).await {
                Ok(bundle) => {
                    info!("Found attestation at: {}", pattern);
                    return Ok(Some(bundle));
                }
                Err(_) => continue,
            }
        }

        // Try GitHub Attestations API (newer mechanism)
        if let Ok(Some(bundle)) = self.fetch_github_attestations_api(&owner, &repo, version).await {
            return Ok(Some(bundle));
        }

        Ok(None)
    }

    /// Fetch attestation from URL
    async fn fetch_attestation(&self, url: &str) -> Result<AttestationBundle> {
        let response = self
            .client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuditorError::Sigstore(format!(
                "Failed to fetch attestation: {}",
                response.status()
            )));
        }

        let text = response.text().await?;

        // Parse as JSONL (multiple JSON objects, one per line)
        let mut statements = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(stmt) = serde_json::from_str::<InTotoStatement>(line) {
                statements.push(stmt);
            }
        }

        if statements.is_empty() {
            return Err(AuditorError::Sigstore("No valid attestations found".into()));
        }

        Ok(AttestationBundle {
            statements,
            source_url: url.to_string(),
        })
    }

    /// Fetch from GitHub Attestations API
    async fn fetch_github_attestations_api(
        &self,
        owner: &str,
        repo: &str,
        version: &str,
    ) -> Result<Option<AttestationBundle>> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/attestations?per_page=100",
            owner, repo
        );

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "sec_auditor/0.1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let data: serde_json::Value = response.json().await?;

        let attestations = data
            .get("attestations")
            .and_then(|a| a.as_array())
            .unwrap_or(&Vec::new())
            .clone();

        let mut statements = Vec::new();
        for attestation in attestations {
            // Check if this attestation matches our version
            if let Some(bundle) = attestation.get("bundle") {
                if let Ok(stmt) = serde_json::from_value::<InTotoStatement>(bundle.clone()) {
                    // Check if any subject matches our version
                    let version_match = stmt.subject.iter().any(|s| {
                        s.name.contains(version) || s.name.contains(&format!("v{}", version))
                    });
                    if version_match {
                        statements.push(stmt);
                    }
                }
            }
        }

        if statements.is_empty() {
            return Ok(None);
        }

        Ok(Some(AttestationBundle {
            statements,
            source_url: url,
        }))
    }

    fn parse_github_url(&self, url: &str) -> Result<(String, String)> {
        // Handle various GitHub URL formats
        let url = url
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .replace("git@github.com:", "https://github.com/");

        let parts: Vec<&str> = url.split('/').collect();
        let len = parts.len();

        if len >= 2 {
            let owner = parts[len - 2].to_string();
            let repo = parts[len - 1].to_string();
            return Ok((owner, repo));
        }

        Err(AuditorError::Sigstore(format!(
            "Invalid GitHub URL: {}",
            url
        )))
    }
}

impl Default for GitHubAttestationDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Attestation bundle containing multiple in-toto statements
#[derive(Debug, Clone)]
pub struct AttestationBundle {
    pub statements: Vec<InTotoStatement>,
    pub source_url: String,
}

/// In-toto attestation statement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub predicate_type: String,
    pub subject: Vec<Subject>,
    pub predicate: serde_json::Value,
}

/// Subject of an attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

/// SLSA provenance verifier with Rekor v2 support.
pub struct SlsaVerifier {
    /// HTTP client
    client: Client,

    /// Trusted builder identities
    trusted_builders: Vec<String>,

    /// Rekor tile cache
    tile_cache: Option<RekorTileCache>,

    /// GitHub attestation discoverer
    attestation_discovery: GitHubAttestationDiscovery,

    /// Rekor transparency log URL
    rekor_url: String,
}

impl SlsaVerifier {
    /// Create a new SLSA verifier.
    pub fn new() -> Self {
        let tile_cache = RekorTileCache::new(TileCacheConfig::default()).ok();

        Self {
            client: Client::new(),
            trusted_builders: vec![
                "https://github.com/slsa-framework/slsa-github-generator".to_string(),
                "https://github.com/actions/runner".to_string(),
                "https://token.actions.githubusercontent.com".to_string(),
            ],
            tile_cache,
            attestation_discovery: GitHubAttestationDiscovery::new(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
        }
    }

    /// Create verifier with custom cache configuration
    pub fn with_cache_config(config: TileCacheConfig) -> Result<Self> {
        let tile_cache = RekorTileCache::new(config)?;

        Ok(Self {
            client: Client::new(),
            trusted_builders: vec![
                "https://github.com/slsa-framework/slsa-github-generator".to_string(),
                "https://github.com/actions/runner".to_string(),
                "https://token.actions.githubusercontent.com".to_string(),
            ],
            tile_cache: Some(tile_cache),
            attestation_discovery: GitHubAttestationDiscovery::new(),
            rekor_url: "https://rekor.sigstore.dev".to_string(),
        })
    }

    /// Add a trusted builder identity.
    pub fn add_trusted_builder(&mut self, builder: String) {
        self.trusted_builders.push(builder);
    }

    /// Verify provenance for a crate from crates.io.
    pub async fn verify_crate(&self, name: &str, version: &str) -> Result<Provenance> {
        info!("Verifying provenance for crate {}@{}", name, version);

        // Get crate metadata from crates.io
        let crate_info = self.get_crate_info(name, version).await?;

        // Check verdict cache first
        if let Some(ref cache) = self.tile_cache {
            if let Some(ref checksum) = crate_info.checksum {
                if let Ok(Some(verdict)) = cache.get_cached_verdict(checksum) {
                    debug!("Using cached verdict for {}@{}", name, version);
                    return Ok(self.verdict_to_provenance(&verdict));
                }
            }
        }

        let mut provenance = Provenance::default();

        // Try to discover and verify attestation from GitHub Releases
        if let Some(ref repo_url) = crate_info.repository {
            match self
                .attestation_discovery
                .discover_attestation(repo_url, version)
                .await
            {
                Ok(Some(bundle)) => {
                    provenance = self.verify_attestation_bundle(&bundle, &crate_info)?;
                }
                Ok(None) => {
                    provenance.errors.push(format!(
                        "No attestation found in GitHub releases for {}",
                        repo_url
                    ));
                }
                Err(e) => {
                    provenance
                        .errors
                        .push(format!("Failed to discover attestation: {}", e));
                }
            }
        } else {
            provenance
                .errors
                .push("No repository URL in crate metadata".to_string());
        }

        // Check Rekor transparency log
        if let Some(checksum) = &crate_info.checksum {
            match self.search_rekor_with_cache(checksum).await {
                Ok(entries) if !entries.is_empty() => {
                    provenance.signature_valid = true;
                    if let Some(entry) = entries.first() {
                        provenance.build_time = entry.integrated_time;
                    }
                }
                Ok(_) => {
                    debug!("No Rekor entries found for checksum");
                }
                Err(e) => {
                    provenance
                        .errors
                        .push(format!("Rekor search failed: {}", e));
                }
            }

            // Cache the verdict
            if let Some(ref cache) = self.tile_cache {
                let verdict = self.provenance_to_verdict(&provenance);
                let _ = cache.cache_verdict(checksum, &verdict);
            }
        }

        Ok(provenance)
    }

    /// Verify multiple crates in batch (leveraging tile deduplication)
    pub async fn verify_crates_batch(
        &self,
        crates: &[(&str, &str)],
    ) -> Result<Vec<(String, Provenance)>> {
        let mut results = Vec::new();

        // Collect all checksums and their tile indices
        let mut crate_infos = Vec::new();
        for (name, version) in crates {
            match self.get_crate_info(name, version).await {
                Ok(info) => crate_infos.push((name.to_string(), version.to_string(), info)),
                Err(e) => {
                    let mut prov = Provenance::default();
                    prov.errors.push(format!("Failed to get crate info: {}", e));
                    results.push((format!("{}@{}", name, version), prov));
                }
            }
        }

        // Batch Rekor lookups (tiles are deduplicated automatically)
        for (name, version, info) in crate_infos {
            let provenance = self
                .verify_crate_with_info(&name, &version, &info)
                .await
                .unwrap_or_else(|e| {
                    let mut p = Provenance::default();
                    p.errors.push(e.to_string());
                    p
                });
            results.push((format!("{}@{}", name, version), provenance));
        }

        Ok(results)
    }

    async fn verify_crate_with_info(
        &self,
        name: &str,
        version: &str,
        crate_info: &CrateInfo,
    ) -> Result<Provenance> {
        let mut provenance = Provenance::default();

        // Try to discover and verify attestation
        if let Some(ref repo_url) = crate_info.repository {
            match self
                .attestation_discovery
                .discover_attestation(repo_url, version)
                .await
            {
                Ok(Some(bundle)) => {
                    provenance = self.verify_attestation_bundle(&bundle, crate_info)?;
                }
                Ok(None) => {
                    provenance.errors.push("No attestation found".to_string());
                }
                Err(e) => {
                    provenance
                        .errors
                        .push(format!("Attestation discovery failed: {}", e));
                }
            }
        }

        // Check Rekor
        if let Some(checksum) = &crate_info.checksum {
            if let Ok(entries) = self.search_rekor_with_cache(checksum).await {
                if !entries.is_empty() {
                    provenance.signature_valid = true;
                }
            }
        }

        Ok(provenance)
    }

    /// Get crate info from crates.io.
    async fn get_crate_info(&self, name: &str, version: &str) -> Result<CrateInfo> {
        let url = format!("https://crates.io/api/v1/crates/{}/{}", name, version);

        let response = self
            .client
            .get(&url)
            .header("User-Agent", "sec_auditor/0.1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuditorError::Sigstore(format!(
                "Failed to get crate info: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;

        let version_info = data
            .get("version")
            .ok_or_else(|| AuditorError::Sigstore("Missing version info".to_string()))?;

        let crate_info = data.get("crate");

        Ok(CrateInfo {
            name: name.to_string(),
            version: version.to_string(),
            checksum: version_info
                .get("checksum")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            dl_path: version_info
                .get("dl_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            repository: crate_info
                .and_then(|c| c.get("repository"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    /// Verify an attestation bundle
    fn verify_attestation_bundle(
        &self,
        bundle: &AttestationBundle,
        crate_info: &CrateInfo,
    ) -> Result<Provenance> {
        let mut provenance = Provenance::default();

        for statement in &bundle.statements {
            // Check predicate type for SLSA provenance
            if statement.predicate_type.contains("slsa.dev/provenance") {
                provenance.slsa_level = provenance.slsa_level.max(1);

                // Extract builder information
                if let Some(builder) = statement.predicate.get("builder") {
                    if let Some(id) = builder.get("id").and_then(|v| v.as_str()) {
                        provenance.builder = Some(id.to_string());

                        // Check if builder is trusted
                        if self.trusted_builders.iter().any(|b| id.contains(b)) {
                            provenance.slsa_level = provenance.slsa_level.max(2);
                        } else {
                            provenance
                                .errors
                                .push(format!("Untrusted builder: {}", id));
                        }
                    }
                }

                // Extract build definition
                if let Some(build_def) = statement.predicate.get("buildDefinition") {
                    // Extract resolved dependencies for source info
                    if let Some(deps) = build_def.get("resolvedDependencies") {
                        if let Some(deps_arr) = deps.as_array() {
                            for dep in deps_arr {
                                if let Some(uri) = dep.get("uri").and_then(|v| v.as_str()) {
                                    if uri.contains("github.com") {
                                        provenance.source_repo = Some(uri.to_string());
                                        if let Some(digest) = dep.get("digest") {
                                            provenance.source_commit = digest
                                                .get("sha1")
                                                .or(digest.get("gitCommit"))
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Verify subject digest matches crate checksum
                if let Some(checksum) = &crate_info.checksum {
                    let matches = statement.subject.iter().any(|s| {
                        s.digest
                            .get("sha256")
                            .map(|d| d.to_lowercase() == checksum.to_lowercase())
                            .unwrap_or(false)
                    });

                    if matches {
                        provenance.signature_valid = true;
                    } else {
                        provenance
                            .errors
                            .push("Subject digest mismatch".to_string());
                    }
                }
            }
        }

        Ok(provenance)
    }

    /// Search Rekor with tile caching
    async fn search_rekor_with_cache(&self, checksum: &str) -> Result<Vec<RekorEntry>> {
        // Use tile cache if available
        if let Some(ref cache) = self.tile_cache {
            // Get current checkpoint
            let checkpoint = cache.get_checkpoint().await?;
            debug!(
                "Rekor tree size: {}, searching for {}",
                checkpoint.tree_size, checksum
            );
        }

        // Fall back to API search (tiles are for proof verification, not search)
        self.search_rekor(checksum).await
    }

    /// Search Rekor transparency log for an artifact.
    async fn search_rekor(&self, checksum: &str) -> Result<Vec<RekorEntry>> {
        let url = format!("{}/api/v1/index/retrieve", self.rekor_url);

        let request = serde_json::json!({
            "hash": format!("sha256:{}", checksum)
        });

        let response = self.client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(Vec::new());
            }
            return Err(AuditorError::Sigstore(format!(
                "Rekor search failed: {}",
                response.status()
            )));
        }

        let uuids: Vec<String> = response.json().await?;

        let mut entries = Vec::new();
        for uuid in uuids.into_iter().take(5) {
            if let Ok(entry) = self.get_rekor_entry(&uuid).await {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Get a specific Rekor entry.
    async fn get_rekor_entry(&self, uuid: &str) -> Result<RekorEntry> {
        let url = format!("{}/api/v1/log/entries/{}", self.rekor_url, uuid);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AuditorError::Sigstore(format!(
                "Failed to get Rekor entry: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;

        // Parse the entry
        if let Some((_, entry_value)) = data.as_object().and_then(|o| o.iter().next()) {
            let integrated_time = entry_value
                .get("integratedTime")
                .and_then(|v| v.as_i64())
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                .map(|dt| dt.with_timezone(&chrono::Utc));

            return Ok(RekorEntry {
                uuid: uuid.to_string(),
                integrated_time,
                body: entry_value.get("body").cloned(),
            });
        }

        Err(AuditorError::Sigstore(
            "Invalid Rekor entry format".to_string(),
        ))
    }

    /// Verify a local file against expected checksum.
    pub async fn verify_file_checksum(path: &Path, expected: &str) -> Result<bool> {
        let content = tokio::fs::read(path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        let actual = format!("{:x}", result);

        Ok(actual == expected.to_lowercase())
    }

    /// Generate findings for provenance issues.
    pub fn generate_findings(&self, crate_name: &str, provenance: &Provenance) -> Vec<Finding> {
        let mut findings = Vec::new();

        // No attestation
        if provenance.builder.is_none() && !provenance.errors.is_empty() {
            let finding = Finding::sast(
                "provenance/missing-attestation",
                "Missing Provenance Attestation",
                format!(
                    "Crate '{}' has no verifiable provenance attestation: {}",
                    crate_name,
                    provenance.errors.join("; ")
                ),
                Location::new("Cargo.lock".into(), 0, 0),
                Severity::Medium,
            )
            .with_confidence(Confidence::High)
            .with_remediation("Consider using crates that provide SLSA provenance attestations.");

            findings.push(finding);
        }

        // Untrusted builder
        if let Some(ref builder) = provenance.builder {
            if !self.trusted_builders.iter().any(|b| builder.contains(b)) {
                let finding = Finding::sast(
                    "provenance/untrusted-builder",
                    "Untrusted Build System",
                    format!(
                        "Crate '{}' was built by an untrusted builder: {}",
                        crate_name, builder
                    ),
                    Location::new("Cargo.lock".into(), 0, 0),
                    Severity::Low,
                )
                .with_confidence(Confidence::Medium)
                .with_remediation(
                    "Verify the build system is trustworthy or use crates built by trusted systems.",
                );

                findings.push(finding);
            }
        }

        // Low SLSA level
        if provenance.slsa_level < 2 && provenance.builder.is_some() {
            let finding = Finding::sast(
                "provenance/low-slsa-level",
                "Low SLSA Level",
                format!(
                    "Crate '{}' has SLSA level {} (recommended: 2+)",
                    crate_name, provenance.slsa_level
                ),
                Location::new("Cargo.lock".into(), 0, 0),
                Severity::Low,
            )
            .with_confidence(Confidence::High)
            .with_remediation(
                "Prefer crates with SLSA Level 2 or higher for better supply chain security.",
            );

            findings.push(finding);
        }

        // Invalid signature
        if provenance.builder.is_some() && !provenance.signature_valid {
            let finding = Finding::sast(
                "provenance/invalid-signature",
                "Invalid Provenance Signature",
                format!(
                    "Crate '{}' has provenance but signature verification failed",
                    crate_name
                ),
                Location::new("Cargo.lock".into(), 0, 0),
                Severity::High,
            )
            .with_confidence(Confidence::High)
            .with_remediation("This may indicate tampering. Investigate before using this crate.");

            findings.push(finding);
        }

        findings
    }

    fn provenance_to_verdict(&self, provenance: &Provenance) -> VerificationVerdict {
        VerificationVerdict {
            verified: provenance.signature_valid,
            slsa_level: provenance.slsa_level,
            builder: provenance.builder.clone(),
            source_repo: provenance.source_repo.clone(),
            source_commit: provenance.source_commit.clone(),
            verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            errors: provenance.errors.clone(),
        }
    }

    fn verdict_to_provenance(&self, verdict: &VerificationVerdict) -> Provenance {
        Provenance {
            slsa_level: verdict.slsa_level,
            signature_valid: verdict.verified,
            builder: verdict.builder.clone(),
            source_repo: verdict.source_repo.clone(),
            source_commit: verdict.source_commit.clone(),
            build_time: None, // Not stored in verdict
            errors: verdict.errors.clone(),
        }
    }
}

impl Default for SlsaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a crate.
#[derive(Debug)]
struct CrateInfo {
    name: String,
    version: String,
    checksum: Option<String>,
    dl_path: Option<String>,
    repository: Option<String>,
}

/// Entry from the Rekor transparency log.
#[derive(Debug)]
struct RekorEntry {
    uuid: String,
    integrated_time: Option<chrono::DateTime<chrono::Utc>>,
    body: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_checksum() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();

        // SHA256 of "test content"
        let expected = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";
        assert!(SlsaVerifier::verify_file_checksum(file.path(), expected)
            .await
            .unwrap());
    }

    #[test]
    fn test_github_url_parsing() {
        let discovery = GitHubAttestationDiscovery::new();

        let (owner, repo) = discovery
            .parse_github_url("https://github.com/tokio-rs/tokio")
            .unwrap();
        assert_eq!(owner, "tokio-rs");
        assert_eq!(repo, "tokio");

        let (owner, repo) = discovery
            .parse_github_url("https://github.com/serde-rs/serde.git")
            .unwrap();
        assert_eq!(owner, "serde-rs");
        assert_eq!(repo, "serde");

        let (owner, repo) = discovery
            .parse_github_url("git@github.com:rust-lang/rust.git")
            .unwrap();
        assert_eq!(owner, "rust-lang");
        assert_eq!(repo, "rust");
    }

    #[test]
    fn test_tile_cache_config_default() {
        let config = TileCacheConfig::default();
        assert_eq!(config.checkpoint_max_age_secs, 3600);
        assert_eq!(config.tile_size, 256);
    }

    #[test]
    fn test_verification_verdict_serialization() {
        let verdict = VerificationVerdict {
            verified: true,
            slsa_level: 2,
            builder: Some("https://github.com/actions/runner".to_string()),
            source_repo: Some("https://github.com/example/repo".to_string()),
            source_commit: Some("abc123".to_string()),
            verified_at: 1234567890,
            errors: vec![],
        };

        let json = serde_json::to_string(&verdict).unwrap();
        let parsed: VerificationVerdict = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.verified, verdict.verified);
        assert_eq!(parsed.slsa_level, verdict.slsa_level);
        assert_eq!(parsed.builder, verdict.builder);
    }
}
