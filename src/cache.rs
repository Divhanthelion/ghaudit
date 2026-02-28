//! Caching system for the security auditor.
//!
//! Provides persistent caching for:
//! - Parsed ASTs (to avoid re-parsing files)
//! - OSV query results (to avoid redundant API calls)
//! - Scan results (for incremental scanning)

use crate::error::{AuditorError, Result};
use crate::models::{Finding, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Cache entry with expiration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry<T> {
    /// Cached data
    data: T,
    /// Timestamp when entry was created
    created_at: SystemTime,
    /// Time-to-live in seconds (0 = no expiration)
    ttl_secs: u64,
    /// Version of the cached data format
    version: u32,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl_secs: u64, version: u32) -> Self {
        Self {
            data,
            created_at: SystemTime::now(),
            ttl_secs,
            version,
        }
    }

    fn is_expired(&self) -> bool {
        if self.ttl_secs == 0 {
            return false;
        }
        match self.created_at.elapsed() {
            Ok(elapsed) => elapsed.as_secs() > self.ttl_secs,
            Err(_) => true, // Clock moved backwards, treat as expired
        }
    }
}

/// AST cache entry containing the serialized tree-sitter tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstCacheEntry {
    /// File path (relative to repo root)
    pub file_path: PathBuf,
    /// File content hash (to detect changes)
    pub content_hash: String,
    /// Serialized AST (stored as a simplified representation)
    pub ast_data: Vec<u8>,
    /// Language
    pub language: String,
}

/// OSV cache entry for vulnerability lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvCacheEntry {
    /// Package name
    pub package: String,
    /// Package version
    pub version: String,
    /// Ecosystem
    pub ecosystem: String,
    /// Cached vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Scan result cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCacheEntry {
    /// Repository identifier (URL or path)
    pub repository: String,
    /// Commit SHA
    pub commit_sha: String,
    /// Cached findings
    pub findings: Vec<Finding>,
    /// Files scanned (path -> content hash)
    pub file_hashes: HashMap<PathBuf, String>,
}

/// Persistent cache manager using redb for storage.
pub struct Cache {
    /// Cache directory
    cache_dir: PathBuf,
    /// AST cache file
    ast_cache_path: PathBuf,
    /// OSV cache file
    osv_cache_path: PathBuf,
    /// Scan result cache file
    scan_cache_path: PathBuf,
    /// In-memory AST cache (LRU-like behavior via HashMap limits)
    ast_cache: HashMap<String, AstCacheEntry>,
    /// In-memory OSV cache
    osv_cache: HashMap<String, OsvCacheEntry>,
    /// In-memory scan cache
    scan_cache: HashMap<String, ScanCacheEntry>,
    /// Max AST cache entries in memory
    max_ast_entries: usize,
    /// Default TTL for AST entries (24 hours)
    ast_ttl_secs: u64,
    /// Default TTL for OSV entries (7 days)
    osv_ttl_secs: u64,
    /// Default TTL for scan results (1 hour - commits change frequently)
    scan_ttl_secs: u64,
    /// Cache format version
    version: u32,
}

impl Cache {
    /// Create a new cache manager.
    pub fn new(cache_dir: impl AsRef<Path>) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&cache_dir)?;

        let ast_cache_path = cache_dir.join("ast_cache.json");
        let osv_cache_path = cache_dir.join("osv_cache.json");
        let scan_cache_path = cache_dir.join("scan_cache.json");

        let mut cache = Self {
            cache_dir,
            ast_cache_path,
            osv_cache_path,
            scan_cache_path,
            ast_cache: HashMap::new(),
            osv_cache: HashMap::new(),
            scan_cache: HashMap::new(),
            max_ast_entries: 1000,
            ast_ttl_secs: 24 * 60 * 60,      // 24 hours
            osv_ttl_secs: 7 * 24 * 60 * 60,  // 7 days
            scan_ttl_secs: 60 * 60,          // 1 hour
            version: 1,
        };

        // Load existing caches
        cache.load_ast_cache()?;
        cache.load_osv_cache()?;
        cache.load_scan_cache()?;

        info!(
            "Cache initialized: {} AST, {} OSV, {} scan entries",
            cache.ast_cache.len(),
            cache.osv_cache.len(),
            cache.scan_cache.len()
        );

        Ok(cache)
    }

    /// Create cache in the default location (~/.cache/sec_auditor).
    pub fn default_cache() -> Result<Self> {
        let home = dirs::cache_dir().unwrap_or_else(|| std::env::temp_dir());
        let cache_dir = home.join("sec_auditor");
        Self::new(cache_dir)
    }

    // ==========================================================================
    // AST Cache
    // ==========================================================================

    /// Get AST from cache if available and not expired.
    pub fn get_ast(&self, file_path: &Path, content_hash: &str) -> Option<&AstCacheEntry> {
        let key = format!("{}:{}", file_path.display(), content_hash);
        self.ast_cache.get(&key).filter(|e| !self.is_ast_expired(e))
    }

    /// Store AST in cache.
    pub fn put_ast(&mut self, file_path: &Path, content_hash: &str, entry: AstCacheEntry) -> Result<()> {
        let key = format!("{}:{}", file_path.display(), content_hash);
        
        // Evict oldest entries if cache is full (simple eviction)
        if self.ast_cache.len() >= self.max_ast_entries {
            self.evict_oldest_ast_entries(100);
        }

        self.ast_cache.insert(key, entry);
        
        // Periodically persist to disk (every 100 inserts)
        if self.ast_cache.len() % 100 == 0 {
            self.persist_ast_cache()?;
        }
        
        Ok(())
    }

    fn is_ast_expired(&self, entry: &AstCacheEntry) -> bool {
        // AST entries expire based on content hash change, not time
        // But we can also have a TTL for cleanup purposes
        false
    }

    fn evict_oldest_ast_entries(&mut self, count: usize) {
        // Simple eviction: remove arbitrary entries
        let keys_to_remove: Vec<_> = self.ast_cache.keys().take(count).cloned().collect();
        for key in keys_to_remove {
            self.ast_cache.remove(&key);
        }
        debug!("Evicted {} AST cache entries", count);
    }

    fn load_ast_cache(&mut self) -> Result<()> {
        if !self.ast_cache_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.ast_cache_path)?;
        let entries: HashMap<String, CacheEntry<AstCacheEntry>> = serde_json::from_str(&content)?;

        for (key, entry) in entries {
            if !entry.is_expired() && entry.version == self.version {
                self.ast_cache.insert(key, entry.data);
            }
        }

        Ok(())
    }

    fn persist_ast_cache(&self) -> Result<()> {
        let entries: HashMap<String, CacheEntry<AstCacheEntry>> = self
            .ast_cache
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    CacheEntry::new(v.clone(), self.ast_ttl_secs, self.version),
                )
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&self.ast_cache_path, json)?;
        
        Ok(())
    }

    // ==========================================================================
    // OSV Cache
    // ==========================================================================

    /// Get OSV results from cache.
    pub fn get_osv(&self, package: &str, version: &str, ecosystem: &str) -> Option<&Vec<Vulnerability>> {
        let key = format!("{}:{}:{}", ecosystem, package, version);
        self.osv_cache
            .get(&key)
            .filter(|e| !self.is_osv_expired(e))
            .map(|e| &e.vulnerabilities)
    }

    /// Store OSV results in cache.
    pub fn put_osv(&mut self, package: &str, version: &str, ecosystem: &str, vulnerabilities: Vec<Vulnerability>) -> Result<()> {
        let key = format!("{}:{}:{}", ecosystem, package, version);
        let entry = OsvCacheEntry {
            package: package.to_string(),
            version: version.to_string(),
            ecosystem: ecosystem.to_string(),
            vulnerabilities,
        };
        
        self.osv_cache.insert(key, entry);
        
        // Persist periodically
        if self.osv_cache.len() % 10 == 0 {
            self.persist_osv_cache()?;
        }
        
        Ok(())
    }

    fn is_osv_expired(&self, entry: &OsvCacheEntry) -> bool {
        // Check if entry is older than TTL
        // We don't store timestamp in entry currently, so we use a simple check
        // In production, you'd want to track when each entry was added
        false // For now, OSV cache doesn't expire (vulnerabilities don't change often)
    }

    fn load_osv_cache(&mut self) -> Result<()> {
        if !self.osv_cache_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.osv_cache_path)?;
        let entries: HashMap<String, CacheEntry<OsvCacheEntry>> = serde_json::from_str(&content)?;

        for (key, entry) in entries {
            if !entry.is_expired() && entry.version == self.version {
                self.osv_cache.insert(key, entry.data);
            }
        }

        Ok(())
    }

    fn persist_osv_cache(&self) -> Result<()> {
        let entries: HashMap<String, CacheEntry<OsvCacheEntry>> = self
            .osv_cache
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    CacheEntry::new(v.clone(), self.osv_ttl_secs, self.version),
                )
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&self.osv_cache_path, json)?;
        
        Ok(())
    }

    // ==========================================================================
    // Scan Result Cache
    // ==========================================================================

    /// Get cached scan result if available and valid.
    pub fn get_scan_result(&self, repository: &str, commit_sha: &str, file_hashes: &HashMap<PathBuf, String>) -> Option<&ScanCacheEntry> {
        let key = format!("{}:{}", repository, commit_sha);
        
        self.scan_cache.get(&key).and_then(|entry| {
            // Validate that file hashes match
            if entry.file_hashes == *file_hashes {
                Some(entry)
            } else {
                None
            }
        })
    }

    /// Store scan result in cache.
    pub fn put_scan_result(&mut self, repository: &str, commit_sha: &str, findings: Vec<Finding>, file_hashes: HashMap<PathBuf, String>) -> Result<()> {
        let key = format!("{}:{}", repository, commit_sha);
        let entry = ScanCacheEntry {
            repository: repository.to_string(),
            commit_sha: commit_sha.to_string(),
            findings,
            file_hashes,
        };
        
        self.scan_cache.insert(key, entry);
        
        // Persist immediately for scan results
        self.persist_scan_cache()?;
        
        Ok(())
    }

    fn load_scan_cache(&mut self) -> Result<()> {
        if !self.scan_cache_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.scan_cache_path)?;
        let entries: HashMap<String, CacheEntry<ScanCacheEntry>> = serde_json::from_str(&content)?;

        for (key, entry) in entries {
            if !entry.is_expired() && entry.version == self.version {
                self.scan_cache.insert(key, entry.data);
            }
        }

        Ok(())
    }

    fn persist_scan_cache(&self) -> Result<()> {
        let entries: HashMap<String, CacheEntry<ScanCacheEntry>> = self
            .scan_cache
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    CacheEntry::new(v.clone(), self.scan_ttl_secs, self.version),
                )
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)?;
        std::fs::write(&self.scan_cache_path, json)?;
        
        Ok(())
    }

    // ==========================================================================
    // Cache Management
    // ==========================================================================

    /// Persist all caches to disk.
    pub fn persist_all(&self) -> Result<()> {
        self.persist_ast_cache()?;
        self.persist_osv_cache()?;
        self.persist_scan_cache()?;
        info!("All caches persisted to disk");
        Ok(())
    }

    /// Clear all caches.
    pub fn clear_all(&mut self) -> Result<()> {
        self.ast_cache.clear();
        self.osv_cache.clear();
        self.scan_cache.clear();
        
        let _ = std::fs::remove_file(&self.ast_cache_path);
        let _ = std::fs::remove_file(&self.osv_cache_path);
        let _ = std::fs::remove_file(&self.scan_cache_path);
        
        info!("All caches cleared");
        Ok(())
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            ast_entries: self.ast_cache.len(),
            osv_entries: self.osv_cache.len(),
            scan_entries: self.scan_cache.len(),
            cache_dir: self.cache_dir.clone(),
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub ast_entries: usize,
    pub osv_entries: usize,
    pub scan_entries: usize,
    pub cache_dir: PathBuf,
}

impl Drop for Cache {
    fn drop(&mut self) {
        // Try to persist on drop
        let _ = self.persist_all();
    }
}

/// Compute a simple content hash for caching purposes.
pub fn compute_content_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new("test", 1, 1);
        assert!(!entry.is_expired());
        
        // Wait a bit (can't easily test actual expiration without sleeping)
        std::thread::sleep(Duration::from_millis(10));
        // Still not expired because TTL is 1 second
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_content_hash() {
        let hash1 = compute_content_hash("hello world");
        let hash2 = compute_content_hash("hello world");
        let hash3 = compute_content_hash("different content");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
