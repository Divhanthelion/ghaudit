//! Software Composition Analysis (SCA) module with OSV integration.
//!
//! This module provides:
//! - PURL-based package identification (Package URL standard)
//! - OSV vulnerability database integration
//! - Support for multiple ecosystems (npm, PyPI, crates.io, Go)
//! - Ecosystem-specific version parsing (semver for npm/cargo, PEP 440 for PyPI)

use crate::error::{AuditorError, Result};
use crate::models::{Dependency, Finding, Reference, ReferenceType, Severity, VersionRange, Vulnerability, VulnerabilitySource};
use cargo_lock::Lockfile;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info, warn};

// ============================================================================
// Ecosystem-Specific Version Parsing
// ============================================================================

/// Supported package ecosystems for version parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// Rust crates (crates.io) - uses strict semver
    Cargo,
    /// Node.js packages (npm) - uses node-semver (more permissive)
    Npm,
    /// Python packages (PyPI) - uses PEP 440
    PyPI,
    /// Go modules - uses semantic versioning with v prefix
    Go,
    /// Maven packages - uses Maven version ordering
    Maven,
    /// Generic/unknown ecosystem - falls back to string comparison
    Unknown,
}

impl Ecosystem {
    /// Detect ecosystem from PURL type string.
    pub fn from_purl_type(purl_type: &str) -> Self {
        match purl_type.to_lowercase().as_str() {
            "cargo" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::PyPI,
            "golang" | "go" => Ecosystem::Go,
            "maven" => Ecosystem::Maven,
            _ => Ecosystem::Unknown,
        }
    }
}

/// Ecosystem-aware version parser that handles npm, PyPI, Cargo, and Go versioning schemes.
pub struct EcosystemVersionParser;

impl EcosystemVersionParser {
    /// Check if a version string satisfies a version range constraint.
    ///
    /// This method uses ecosystem-specific parsing:
    /// - npm: node-semver ranges (e.g., ">=1.0.0 <2.0.0", "^1.2.3", "~1.2.3")
    /// - PyPI: PEP 440 specifiers (e.g., ">=1.0,<2.0", "~=1.4.2", "==1.0.*")
    /// - Cargo: strict semver ranges
    /// - Go: semver with optional 'v' prefix
    pub fn version_in_range(
        ecosystem: Ecosystem,
        version: &str,
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> bool {
        match ecosystem {
            Ecosystem::Npm => Self::npm_version_in_range(version, introduced, fixed, last_affected),
            Ecosystem::PyPI => Self::pypi_version_in_range(version, introduced, fixed, last_affected),
            Ecosystem::Cargo | Ecosystem::Go => {
                Self::semver_version_in_range(version, introduced, fixed, last_affected)
            }
            _ => Self::fallback_version_in_range(version, introduced, fixed, last_affected),
        }
    }

    /// npm version range check using node-semver.
    fn npm_version_in_range(
        version: &str,
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> bool {
        // Parse the target version
        let target = match node_semver::Version::parse(version) {
            Ok(v) => v,
            Err(_) => return Self::fallback_version_in_range(version, introduced, fixed, last_affected),
        };

        // Check lower bound (introduced)
        if let Some(intro) = introduced {
            if let Ok(intro_ver) = node_semver::Version::parse(intro) {
                if target < intro_ver {
                    return false;
                }
            }
        }

        // Check upper bound (fixed - exclusive)
        if let Some(fix) = fixed {
            if let Ok(fix_ver) = node_semver::Version::parse(fix) {
                if target >= fix_ver {
                    return false;
                }
            }
            return true;
        }

        // Check last_affected (inclusive upper bound)
        if let Some(last) = last_affected {
            if let Ok(last_ver) = node_semver::Version::parse(last) {
                return target <= last_ver;
            }
        }

        true
    }

    /// npm range string matching (e.g., ">=1.0.0 <2.0.0").
    pub fn npm_satisfies(version: &str, range: &str) -> bool {
        let ver = match node_semver::Version::parse(version) {
            Ok(v) => v,
            Err(_) => return false,
        };

        match node_semver::Range::parse(range) {
            Ok(r) => r.satisfies(&ver),
            Err(_) => false,
        }
    }

    /// PyPI version range check using PEP 440.
    fn pypi_version_in_range(
        version: &str,
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> bool {
        use pep440_rs::{Version as Pep440Version, VersionSpecifier};
        use std::str::FromStr;

        // Parse the target version
        let target = match Pep440Version::from_str(version) {
            Ok(v) => v,
            Err(_) => return Self::fallback_version_in_range(version, introduced, fixed, last_affected),
        };

        // Check lower bound (introduced)
        if let Some(intro) = introduced {
            if let Ok(intro_ver) = Pep440Version::from_str(intro) {
                if target < intro_ver {
                    return false;
                }
            }
        }

        // Check upper bound (fixed - exclusive)
        if let Some(fix) = fixed {
            if let Ok(fix_ver) = Pep440Version::from_str(fix) {
                if target >= fix_ver {
                    return false;
                }
            }
            return true;
        }

        // Check last_affected (inclusive upper bound)
        if let Some(last) = last_affected {
            if let Ok(last_ver) = Pep440Version::from_str(last) {
                return target <= last_ver;
            }
        }

        true
    }

    /// PyPI specifier matching (e.g., ">=1.0,<2.0", "~=1.4.2").
    pub fn pypi_satisfies(version: &str, specifier: &str) -> bool {
        use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
        use std::str::FromStr;

        let ver = match Pep440Version::from_str(version) {
            Ok(v) => v,
            Err(_) => return false,
        };

        match VersionSpecifiers::from_str(specifier) {
            Ok(specs) => specs.contains(&ver),
            Err(_) => false,
        }
    }

    /// Cargo/Go version range check using strict semver.
    fn semver_version_in_range(
        version: &str,
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> bool {
        // Strip 'v' prefix for Go versions
        let version = version.strip_prefix('v').unwrap_or(version);

        let target = match semver::Version::parse(version) {
            Ok(v) => v,
            Err(_) => return Self::fallback_version_in_range(version, introduced, fixed, last_affected),
        };

        // Check lower bound
        if let Some(intro) = introduced {
            let intro = intro.strip_prefix('v').unwrap_or(intro);
            if let Ok(intro_ver) = semver::Version::parse(intro) {
                if target < intro_ver {
                    return false;
                }
            }
        }

        // Check upper bound (fixed - exclusive)
        if let Some(fix) = fixed {
            let fix = fix.strip_prefix('v').unwrap_or(fix);
            if let Ok(fix_ver) = semver::Version::parse(fix) {
                if target >= fix_ver {
                    return false;
                }
            }
            return true;
        }

        // Check last_affected
        if let Some(last) = last_affected {
            let last = last.strip_prefix('v').unwrap_or(last);
            if let Ok(last_ver) = semver::Version::parse(last) {
                return target <= last_ver;
            }
        }

        true
    }

    /// Cargo version requirement matching (e.g., "^1.0", ">=1.0, <2.0").
    pub fn cargo_satisfies(version: &str, requirement: &str) -> bool {
        let ver = match semver::Version::parse(version) {
            Ok(v) => v,
            Err(_) => return false,
        };

        match semver::VersionReq::parse(requirement) {
            Ok(req) => req.matches(&ver),
            Err(_) => false,
        }
    }

    /// Fallback version comparison using lexicographic ordering with numeric awareness.
    fn fallback_version_in_range(
        version: &str,
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> bool {
        let target_parts = Self::parse_version_parts(version);

        if let Some(intro) = introduced {
            let intro_parts = Self::parse_version_parts(intro);
            if Self::compare_version_parts(&target_parts, &intro_parts) == std::cmp::Ordering::Less {
                return false;
            }
        }

        if let Some(fix) = fixed {
            let fix_parts = Self::parse_version_parts(fix);
            if Self::compare_version_parts(&target_parts, &fix_parts) != std::cmp::Ordering::Less {
                return false;
            }
            return true;
        }

        if let Some(last) = last_affected {
            let last_parts = Self::parse_version_parts(last);
            return Self::compare_version_parts(&target_parts, &last_parts) != std::cmp::Ordering::Greater;
        }

        true
    }

    /// Parse version string into numeric and string parts for comparison.
    fn parse_version_parts(version: &str) -> Vec<VersionPart> {
        let mut parts = Vec::new();
        let mut current_num = String::new();
        let mut current_str = String::new();

        for c in version.chars() {
            if c.is_ascii_digit() {
                if !current_str.is_empty() {
                    parts.push(VersionPart::String(std::mem::take(&mut current_str)));
                }
                current_num.push(c);
            } else if c == '.' || c == '-' || c == '_' || c == '+' {
                if !current_num.is_empty() {
                    if let Ok(n) = current_num.parse::<u64>() {
                        parts.push(VersionPart::Numeric(n));
                    }
                    current_num.clear();
                }
                if !current_str.is_empty() {
                    parts.push(VersionPart::String(std::mem::take(&mut current_str)));
                }
            } else {
                if !current_num.is_empty() {
                    if let Ok(n) = current_num.parse::<u64>() {
                        parts.push(VersionPart::Numeric(n));
                    }
                    current_num.clear();
                }
                current_str.push(c);
            }
        }

        if !current_num.is_empty() {
            if let Ok(n) = current_num.parse::<u64>() {
                parts.push(VersionPart::Numeric(n));
            }
        }
        if !current_str.is_empty() {
            parts.push(VersionPart::String(current_str));
        }

        parts
    }

    /// Compare two version part lists.
    fn compare_version_parts(a: &[VersionPart], b: &[VersionPart]) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        for (pa, pb) in a.iter().zip(b.iter()) {
            match (pa, pb) {
                (VersionPart::Numeric(na), VersionPart::Numeric(nb)) => {
                    match na.cmp(nb) {
                        Ordering::Equal => continue,
                        other => return other,
                    }
                }
                (VersionPart::String(sa), VersionPart::String(sb)) => {
                    match sa.cmp(sb) {
                        Ordering::Equal => continue,
                        other => return other,
                    }
                }
                (VersionPart::Numeric(_), VersionPart::String(_)) => return Ordering::Greater,
                (VersionPart::String(_), VersionPart::Numeric(_)) => return Ordering::Less,
            }
        }

        a.len().cmp(&b.len())
    }
}

/// A part of a version string (either numeric or string).
#[derive(Debug, Clone)]
enum VersionPart {
    Numeric(u64),
    String(String),
}

/// Extension trait for VersionRange to support ecosystem-specific parsing.
pub trait VersionRangeExt {
    /// Check if a version is in range using ecosystem-specific parsing.
    fn contains_version(&self, version: &str, ecosystem: Ecosystem) -> bool;
}

impl VersionRangeExt for VersionRange {
    fn contains_version(&self, version: &str, ecosystem: Ecosystem) -> bool {
        EcosystemVersionParser::version_in_range(
            ecosystem,
            version,
            self.introduced.as_deref(),
            self.fixed.as_deref(),
            self.last_affected.as_deref(),
        )
    }
}

/// Package URL (PURL) - A standardized format for identifying software packages.
///
/// Format: `pkg:type/namespace/name@version?qualifiers#subpath`
///
/// Examples:
/// - `pkg:cargo/serde@1.0.193`
/// - `pkg:npm/@types/node@20.10.0`
/// - `pkg:pypi/requests@2.31.0`
/// - `pkg:golang/github.com/gin-gonic/gin@1.9.1`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageUrl {
    /// Package type (ecosystem): cargo, npm, pypi, golang, maven, etc.
    pub pkg_type: String,
    /// Namespace (optional): npm scope, Go module path prefix, Maven groupId
    pub namespace: Option<String>,
    /// Package name
    pub name: String,
    /// Package version (optional)
    pub version: Option<String>,
    /// Qualifiers (optional): key=value pairs
    pub qualifiers: HashMap<String, String>,
    /// Subpath (optional): path within the package
    pub subpath: Option<String>,
}

impl PackageUrl {
    /// Create a new PURL with required fields.
    pub fn new(pkg_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            pkg_type: pkg_type.into(),
            namespace: None,
            name: name.into(),
            version: None,
            qualifiers: HashMap::new(),
            subpath: None,
        }
    }

    /// Set the namespace.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Add a qualifier.
    pub fn with_qualifier(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.qualifiers.insert(key.into(), value.into());
        self
    }

    /// Set the subpath.
    pub fn with_subpath(mut self, subpath: impl Into<String>) -> Self {
        self.subpath = Some(subpath.into());
        self
    }

    /// Parse a PURL string.
    pub fn parse(purl: &str) -> Result<Self> {
        // Must start with "pkg:"
        if !purl.starts_with("pkg:") {
            return Err(AuditorError::Parse("PURL must start with 'pkg:'".to_string()));
        }

        let rest = &purl[4..];

        // Split off subpath first (after #)
        let (rest, subpath) = if let Some(hash_pos) = rest.find('#') {
            let subpath = Self::decode(&rest[hash_pos + 1..]);
            (&rest[..hash_pos], Some(subpath))
        } else {
            (rest, None)
        };

        // Split off qualifiers (after ?)
        let (rest, qualifiers) = if let Some(q_pos) = rest.find('?') {
            let quals = Self::parse_qualifiers(&rest[q_pos + 1..]);
            (&rest[..q_pos], quals)
        } else {
            (rest, HashMap::new())
        };

        // Split off version (after @)
        let (rest, version) = if let Some(at_pos) = rest.rfind('@') {
            let version = Self::decode(&rest[at_pos + 1..]);
            (&rest[..at_pos], Some(version))
        } else {
            (rest, None)
        };

        // Parse type/namespace/name
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.is_empty() {
            return Err(AuditorError::Parse("PURL missing type".to_string()));
        }

        let pkg_type = parts[0].to_lowercase();
        let name_part = parts.get(1).unwrap_or(&"");

        // Parse namespace and name based on type
        let (namespace, name) = Self::parse_name_with_namespace(&pkg_type, name_part)?;

        Ok(Self {
            pkg_type,
            namespace,
            name,
            version,
            qualifiers,
            subpath,
        })
    }

    /// Parse namespace and name based on package type conventions.
    fn parse_name_with_namespace(pkg_type: &str, name_part: &str) -> Result<(Option<String>, String)> {
        if name_part.is_empty() {
            return Err(AuditorError::Parse("PURL missing name".to_string()));
        }

        match pkg_type {
            // npm uses @scope/name format
            "npm" => {
                if name_part.starts_with('@') {
                    // @scope/name format
                    let parts: Vec<&str> = name_part.splitn(2, '/').collect();
                    if parts.len() == 2 {
                        Ok((Some(Self::decode(parts[0])), Self::decode(parts[1])))
                    } else {
                        Err(AuditorError::Parse("Invalid npm scoped package".to_string()))
                    }
                } else {
                    Ok((None, Self::decode(name_part)))
                }
            }
            // Go modules use the full import path as name
            "golang" => {
                // For Go, the full path is the name; namespace could be the host
                if let Some(slash_pos) = name_part.find('/') {
                    let host = &name_part[..slash_pos];
                    Ok((Some(Self::decode(host)), Self::decode(name_part)))
                } else {
                    Ok((None, Self::decode(name_part)))
                }
            }
            // Maven uses groupId/artifactId
            "maven" => {
                let parts: Vec<&str> = name_part.splitn(2, '/').collect();
                if parts.len() == 2 {
                    Ok((Some(Self::decode(parts[0])), Self::decode(parts[1])))
                } else {
                    Err(AuditorError::Parse("Maven PURL requires groupId/artifactId".to_string()))
                }
            }
            // Default: no namespace
            _ => {
                if let Some(slash_pos) = name_part.rfind('/') {
                    let namespace = &name_part[..slash_pos];
                    let name = &name_part[slash_pos + 1..];
                    Ok((Some(Self::decode(namespace)), Self::decode(name)))
                } else {
                    Ok((None, Self::decode(name_part)))
                }
            }
        }
    }

    /// Parse qualifiers from a query string.
    fn parse_qualifiers(query: &str) -> HashMap<String, String> {
        query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next()?;
                Some((Self::decode(key), Self::decode(value)))
            })
            .collect()
    }

    /// URL-decode a string.
    fn decode(s: &str) -> String {
        // Basic percent decoding
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// URL-encode a string for PURL.
    fn encode(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u8),
            })
            .collect()
    }

    /// Convert to a canonical PURL string.
    pub fn to_string(&self) -> String {
        let mut result = format!("pkg:{}/", self.pkg_type);

        // Add namespace if present
        if let Some(ref ns) = self.namespace {
            result.push_str(&Self::encode(ns));
            result.push('/');
        }

        // Add name
        result.push_str(&Self::encode(&self.name));

        // Add version
        if let Some(ref ver) = self.version {
            result.push('@');
            result.push_str(&Self::encode(ver));
        }

        // Add qualifiers
        if !self.qualifiers.is_empty() {
            result.push('?');
            let quals: Vec<String> = self
                .qualifiers
                .iter()
                .map(|(k, v)| format!("{}={}", Self::encode(k), Self::encode(v)))
                .collect();
            result.push_str(&quals.join("&"));
        }

        // Add subpath
        if let Some(ref subpath) = self.subpath {
            result.push('#');
            result.push_str(&Self::encode(subpath));
        }

        result
    }

    /// Get the OSV ecosystem name for this PURL type.
    pub fn osv_ecosystem(&self) -> &str {
        match self.pkg_type.as_str() {
            "cargo" => "crates.io",
            "npm" => "npm",
            "pypi" => "PyPI",
            "golang" => "Go",
            "maven" => "Maven",
            "nuget" => "NuGet",
            "gem" => "RubyGems",
            "composer" => "Packagist",
            "pub" => "Pub",
            "hex" => "Hex",
            "hackage" => "Hackage",
            "conan" => "ConanCenter",
            "swift" => "SwiftURL",
            _ => &self.pkg_type,
        }
    }

    /// Create a PURL from a Cargo.lock package.
    pub fn from_cargo(name: &str, version: &str) -> Self {
        Self::new("cargo", name).with_version(version)
    }

    /// Create a PURL from an npm package.
    pub fn from_npm(name: &str, version: &str) -> Self {
        if name.starts_with('@') {
            // Scoped package
            let parts: Vec<&str> = name.splitn(2, '/').collect();
            if parts.len() == 2 {
                return Self::new("npm", parts[1])
                    .with_namespace(parts[0])
                    .with_version(version);
            }
        }
        Self::new("npm", name).with_version(version)
    }

    /// Create a PURL from a PyPI package.
    pub fn from_pypi(name: &str, version: &str) -> Self {
        // PyPI normalizes names to lowercase with hyphens
        let normalized = name.to_lowercase().replace('_', "-");
        Self::new("pypi", normalized).with_version(version)
    }

    /// Create a PURL from a Go module.
    pub fn from_golang(module: &str, version: &str) -> Self {
        Self::new("golang", module).with_version(version)
    }
}

/// Default rate limit delay between OSV API calls (in milliseconds).
const DEFAULT_RATE_LIMIT_MS: u64 = 50;

/// SCA engine for analyzing dependencies.
pub struct ScaEngine {
    /// HTTP client for OSV API
    client: Client,

    /// OSV API base URL
    osv_url: String,

    /// Rate limit delay between API calls
    rate_limit_delay: Duration,
}

impl ScaEngine {
    /// Create a new SCA engine.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            osv_url: "https://api.osv.dev/v1".to_string(),
            rate_limit_delay: Duration::from_millis(DEFAULT_RATE_LIMIT_MS),
        }
    }

    /// Set the rate limit delay between API calls.
    pub fn with_rate_limit(mut self, delay_ms: u64) -> Self {
        self.rate_limit_delay = Duration::from_millis(delay_ms);
        self
    }

    /// Analyze dependencies from a Cargo.lock file.
    pub async fn analyze_cargo_lock(&self, lock_path: &Path) -> Result<Vec<Finding>> {
        info!("Analyzing Cargo.lock: {}", lock_path.display());

        let lockfile = Lockfile::load(lock_path)?;
        let dependencies = Self::parse_lockfile(&lockfile);

        info!("Found {} dependencies in lockfile", dependencies.len());

        let mut findings = Vec::new();

        for dep in &dependencies {
            // Apply rate limiting between API calls
            self.apply_rate_limit().await;

            match self.query_osv(&dep.name, &dep.version, "crates.io").await {
                Ok(vulns) => {
                    for vuln in vulns {
                        let finding = Finding::sca_with_source(vuln.clone(), &dep.name, &dep.version, Some(lock_path));
                        findings.push(finding);
                    }
                }
                Err(e) => {
                    warn!("Failed to query OSV for {}: {}", dep.name, e);
                }
            }
        }

        info!("SCA analysis complete. Found {} vulnerabilities", findings.len());
        Ok(findings)
    }

    /// Parse a Cargo lockfile into dependencies.
    fn parse_lockfile(lockfile: &Lockfile) -> Vec<Dependency> {
        lockfile
            .packages
            .iter()
            .map(|pkg| Dependency {
                name: pkg.name.as_str().to_string(),
                version: pkg.version.to_string(),
                source: pkg.source.as_ref().map(|s| s.to_string()),
                checksum: pkg.checksum.as_ref().map(|c| c.to_string()),
                is_direct: false, // Would need Cargo.toml to determine
                dependencies: pkg
                    .dependencies
                    .iter()
                    .map(|d| d.name.as_str().to_string())
                    .collect(),
            })
            .collect()
    }

    /// Apply rate limiting delay between API calls.
    async fn apply_rate_limit(&self) {
        if !self.rate_limit_delay.is_zero() {
            tokio::time::sleep(self.rate_limit_delay).await;
        }
    }

    /// Query OSV API for vulnerabilities using a PURL.
    pub async fn query_osv_purl(&self, purl: &PackageUrl) -> Result<Vec<Vulnerability>> {
        let ecosystem = purl.osv_ecosystem();
        let version = purl.version.as_deref().unwrap_or("");

        // For Go modules, use the full name; for others use just the name
        let name: String = if purl.pkg_type == "golang" {
            purl.name.clone()
        } else if let Some(ref ns) = purl.namespace {
            // For npm scoped packages, reconstruct the full name
            if purl.pkg_type == "npm" {
                format!("{}/{}", ns, purl.name)
            } else {
                purl.name.clone()
            }
        } else {
            purl.name.clone()
        };

        debug!("Querying OSV via PURL: {} -> {}@{} ({})", purl.to_string(), name, version, ecosystem);
        self.query_osv(&name, version, ecosystem).await
    }

    /// Query OSV API for vulnerabilities.
    pub async fn query_osv(
        &self,
        package: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<Vulnerability>> {
        debug!("Querying OSV for {}@{} ({})", package, version, ecosystem);

        let request = OsvQueryRequest {
            package: OsvPackage {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: version.to_string(),
        };

        let response = self
            .client
            .post(format!("{}/query", self.osv_url))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuditorError::Osv(format!(
                "OSV API returned {}",
                response.status()
            )));
        }

        let osv_response: OsvQueryResponse = response.json().await?;

        let vulnerabilities = osv_response
            .vulns
            .into_iter()
            .filter_map(|v| self.convert_osv_vuln(v))
            .collect();

        Ok(vulnerabilities)
    }

    /// Query OSV for a specific vulnerability ID.
    pub async fn get_vulnerability(&self, vuln_id: &str) -> Result<Option<Vulnerability>> {
        debug!("Fetching vulnerability: {}", vuln_id);

        let response = self
            .client
            .get(format!("{}/vulns/{}", self.osv_url, vuln_id))
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(AuditorError::Osv(format!(
                "OSV API returned {}",
                response.status()
            )));
        }

        let osv_vuln: OsvVulnerability = response.json().await?;
        Ok(self.convert_osv_vuln(osv_vuln))
    }

    /// Convert OSV vulnerability to our model.
    fn convert_osv_vuln(&self, osv: OsvVulnerability) -> Option<Vulnerability> {
        // Get severity from database_specific or severity field
        let severity = osv
            .severity
            .first()
            .and_then(|s| s.score.as_ref())
            .and_then(|score| score.parse::<f64>().ok())
            .map(Severity::from_cvss)
            .unwrap_or(Severity::Unknown);

        let cvss_score = osv
            .severity
            .first()
            .and_then(|s| s.score.as_ref())
            .and_then(|score| score.parse::<f64>().ok());

        // Get affected versions
        let affected_versions: Vec<VersionRange> = osv
            .affected
            .iter()
            .flat_map(|a| {
                a.ranges.iter().flat_map(|r| {
                    r.events.windows(2).filter_map(|w| {
                        let introduced = w.get(0).and_then(|e| e.introduced.clone());
                        let fixed = w.get(1).and_then(|e| e.fixed.clone());
                        if introduced.is_some() || fixed.is_some() {
                            Some(VersionRange {
                                introduced,
                                fixed,
                                last_affected: None,
                            })
                        } else {
                            None
                        }
                    })
                })
            })
            .collect();

        // Get fixed version
        let fixed_version = osv.affected.first().and_then(|a| {
            a.ranges.first().and_then(|r| {
                r.events.iter().find_map(|e| e.fixed.clone())
            })
        });

        // Get package name
        let package = osv
            .affected
            .first()
            .map(|a| a.package.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Convert references
        let references: Vec<Reference> = osv
            .references
            .iter()
            .map(|r| Reference {
                ref_type: match r.ref_type.as_str() {
                    "ADVISORY" => ReferenceType::Advisory,
                    "ARTICLE" => ReferenceType::Article,
                    "DETECTION" => ReferenceType::Detection,
                    "DISCUSSION" => ReferenceType::Discussion,
                    "REPORT" => ReferenceType::Report,
                    "FIX" => ReferenceType::Fix,
                    "INTRODUCED" => ReferenceType::Introduced,
                    "PACKAGE" => ReferenceType::Package,
                    "EVIDENCE" => ReferenceType::Evidence,
                    _ => ReferenceType::Web,
                },
                url: r.url.clone(),
            })
            .collect();

        // Get CWE IDs
        let cwes: Vec<String> = osv
            .database_specific
            .as_ref()
            .and_then(|d| d.get("cwes"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Some(Vulnerability {
            id: osv.id,
            aliases: osv.aliases,
            summary: osv.summary.unwrap_or_else(|| "No summary available".to_string()),
            details: osv.details,
            severity,
            cvss_score,
            package,
            affected_versions,
            fixed_version,
            references,
            cwes,
            published: osv.published.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&chrono::Utc))),
            modified: osv.modified.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&chrono::Utc))),
            source: VulnerabilitySource::Osv,
        })
    }

    /// Analyze a package.json file for npm dependencies.
    pub async fn analyze_package_json(&self, path: &Path) -> Result<Vec<Finding>> {
        info!("Analyzing package.json: {}", path.display());

        let content = tokio::fs::read_to_string(path).await?;
        let package: serde_json::Value = serde_json::from_str(&content)?;

        let mut findings = Vec::new();

        // Check dependencies
        if let Some(deps) = package.get("dependencies").and_then(|d| d.as_object()) {
            for (name, version) in deps {
                if let Some(version_str) = version.as_str() {
                    let clean_version = version_str.trim_start_matches(|c| c == '^' || c == '~' || c == '=' || c == '>' || c == '<');

                    self.apply_rate_limit().await;
                    match self.query_osv(name, clean_version, "npm").await {
                        Ok(vulns) => {
                            for vuln in vulns {
                                findings.push(Finding::sca_with_source(vuln, name, clean_version, Some(path)));
                            }
                        }
                        Err(e) => {
                            warn!("Failed to query OSV for npm/{}: {}", name, e);
                        }
                    }
                }
            }
        }

        // Check devDependencies
        if let Some(deps) = package.get("devDependencies").and_then(|d| d.as_object()) {
            for (name, version) in deps {
                if let Some(version_str) = version.as_str() {
                    let clean_version = version_str.trim_start_matches(|c| c == '^' || c == '~' || c == '=' || c == '>' || c == '<');

                    self.apply_rate_limit().await;
                    match self.query_osv(name, clean_version, "npm").await {
                        Ok(vulns) => {
                            for vuln in vulns {
                                findings.push(Finding::sca_with_source(vuln, name, clean_version, Some(path)));
                            }
                        }
                        Err(e) => {
                            debug!("Failed to query OSV for npm/{}: {}", name, e);
                        }
                    }
                }
            }
        }

        info!("npm SCA complete. Found {} vulnerabilities", findings.len());
        Ok(findings)
    }

    /// Analyze a requirements.txt file for Python dependencies.
    pub async fn analyze_requirements_txt(&self, path: &Path) -> Result<Vec<Finding>> {
        info!("Analyzing requirements.txt: {}", path.display());

        let content = tokio::fs::read_to_string(path).await?;
        let mut findings = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse package==version or package>=version etc.
            let parts: Vec<&str> = line.split(|c| c == '=' || c == '>' || c == '<' || c == '~' || c == '!' || c == '[')
                .collect();

            if parts.len() >= 2 {
                let name = parts[0].trim();
                let version = parts.last().unwrap_or(&"").trim();

                if !name.is_empty() && !version.is_empty() {
                    self.apply_rate_limit().await;
                    match self.query_osv(name, version, "PyPI").await {
                        Ok(vulns) => {
                            for vuln in vulns {
                                findings.push(Finding::sca_with_source(vuln, name, version, Some(path)));
                            }
                        }
                        Err(e) => {
                            debug!("Failed to query OSV for PyPI/{}: {}", name, e);
                        }
                    }
                }
            }
        }

        info!("Python SCA complete. Found {} vulnerabilities", findings.len());
        Ok(findings)
    }

    /// Analyze a go.sum file for Go dependencies.
    pub async fn analyze_go_sum(&self, path: &Path) -> Result<Vec<Finding>> {
        info!("Analyzing go.sum: {}", path.display());

        let content = tokio::fs::read_to_string(path).await?;
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 2 {
                let module = parts[0];
                let version = parts[1].trim_start_matches('v').split('/').next().unwrap_or("");

                // Skip duplicates (go.sum has both direct and /go.mod entries)
                let key = format!("{}@{}", module, version);
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);

                self.apply_rate_limit().await;
                match self.query_osv(module, version, "Go").await {
                    Ok(vulns) => {
                        for vuln in vulns {
                            findings.push(Finding::sca_with_source(vuln, module, version, Some(path)));
                        }
                    }
                    Err(e) => {
                        debug!("Failed to query OSV for Go/{}: {}", module, e);
                    }
                }
            }
        }

        info!("Go SCA complete. Found {} vulnerabilities", findings.len());
        Ok(findings)
    }

    /// Detect and analyze the appropriate lock file in a repository.
    pub async fn analyze_repository(&self, repo_path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for Cargo.lock (Rust)
        let cargo_lock = repo_path.join("Cargo.lock");
        if cargo_lock.exists() {
            findings.extend(self.analyze_cargo_lock(&cargo_lock).await?);
        }

        // Check for package-lock.json or package.json (npm)
        let package_json = repo_path.join("package.json");
        if package_json.exists() {
            findings.extend(self.analyze_package_json(&package_json).await?);
        }

        // Check for requirements.txt (Python)
        let requirements = repo_path.join("requirements.txt");
        if requirements.exists() {
            findings.extend(self.analyze_requirements_txt(&requirements).await?);
        }

        // Check for go.sum (Go)
        let go_sum = repo_path.join("go.sum");
        if go_sum.exists() {
            findings.extend(self.analyze_go_sum(&go_sum).await?);
        }

        Ok(findings)
    }
}

impl Default for ScaEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// deps.dev API Integration
// ============================================================================

/// deps.dev API client for batch dependency analysis.
///
/// deps.dev (https://deps.dev) is a Google-sponsored service that provides:
/// - Unified dependency metadata across ecosystems
/// - License information
/// - Known vulnerabilities (aggregated from multiple sources)
/// - Dependency graphs
/// - Scorecard security metrics
pub struct DepsDevClient {
    /// HTTP client for API requests.
    client: Client,
    /// Base URL for the deps.dev API.
    base_url: String,
    /// Maximum batch size for queries.
    max_batch_size: usize,
}

impl Default for DepsDevClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DepsDevClient {
    /// Create a new deps.dev client.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("sec_auditor/0.1.0")
                .build()
                .expect("Failed to create HTTP client"),
            base_url: "https://api.deps.dev/v3".to_string(),
            max_batch_size: 100,
        }
    }

    /// Set custom base URL (for testing).
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    /// Set maximum batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Query version information for a single package.
    pub async fn get_version(&self, purl: &PackageUrl) -> Result<DepsDevVersion> {
        let system = purl_to_deps_dev_system(&purl.pkg_type)?;
        let name = if let Some(ref ns) = purl.namespace {
            format!("{}/{}", ns, purl.name)
        } else {
            purl.name.clone()
        };
        let version = purl.version.as_deref().unwrap_or("latest");

        let url = format!(
            "{}/systems/{}/packages/{}/versions/{}",
            self.base_url,
            system,
            urlencoding::encode(&name),
            urlencoding::encode(version)
        );

        debug!("Querying deps.dev: {}", url);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AuditorError::Analysis(format!(
                "deps.dev API error: {} for {}",
                response.status(),
                url
            )));
        }

        let version_info: DepsDevVersion = response.json().await?;
        Ok(version_info)
    }

    /// Query dependencies for a package version.
    pub async fn get_dependencies(&self, purl: &PackageUrl) -> Result<DepsDevDependencies> {
        let system = purl_to_deps_dev_system(&purl.pkg_type)?;
        let name = if let Some(ref ns) = purl.namespace {
            format!("{}/{}", ns, purl.name)
        } else {
            purl.name.clone()
        };
        let version = purl.version.as_deref().unwrap_or("latest");

        let url = format!(
            "{}/systems/{}/packages/{}/versions/{}:dependencies",
            self.base_url,
            system,
            urlencoding::encode(&name),
            urlencoding::encode(version)
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AuditorError::Analysis(format!(
                "deps.dev API error: {}",
                response.status()
            )));
        }

        let deps: DepsDevDependencies = response.json().await?;
        Ok(deps)
    }

    /// Batch query for multiple packages.
    ///
    /// This is more efficient than individual queries as deps.dev supports
    /// batch requests (up to 100 packages per request).
    pub async fn batch_query(&self, purls: &[PackageUrl]) -> Result<Vec<DepsDevBatchResult>> {
        let mut results = Vec::new();

        // Process in batches
        for chunk in purls.chunks(self.max_batch_size) {
            let batch_results = self.query_batch_chunk(chunk).await?;
            results.extend(batch_results);
        }

        Ok(results)
    }

    /// Query a single batch chunk.
    async fn query_batch_chunk(&self, purls: &[PackageUrl]) -> Result<Vec<DepsDevBatchResult>> {
        // Build batch request
        let requests: Vec<DepsDevBatchRequest> = purls
            .iter()
            .filter_map(|purl| {
                let system = purl_to_deps_dev_system(&purl.pkg_type).ok()?;
                let name = if let Some(ref ns) = purl.namespace {
                    format!("{}/{}", ns, purl.name)
                } else {
                    purl.name.clone()
                };

                Some(DepsDevBatchRequest {
                    version_key: DepsDevVersionKey {
                        system: system.to_string(),
                        name,
                        version: purl.version.clone().unwrap_or_else(|| "latest".to_string()),
                    },
                })
            })
            .collect();

        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/query", self.base_url);

        let response = self
            .client
            .post(&url)
            .json(&DepsDevBatchQuery { requests })
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(AuditorError::Analysis(format!(
                "deps.dev batch API error: {}",
                response.status()
            )));
        }

        let batch_response: DepsDevBatchResponse = response.json().await?;
        Ok(batch_response.results)
    }

    /// Get security advisories for a package.
    pub async fn get_advisories(&self, purl: &PackageUrl) -> Result<Vec<DepsDevAdvisory>> {
        let version = self.get_version(purl).await?;
        Ok(version.advisories)
    }

    /// Analyze a list of packages and return security findings.
    pub async fn analyze_packages(&self, purls: &[PackageUrl]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let batch_results = self.batch_query(purls).await?;

        for result in batch_results {
            // Check for advisories
            for advisory in &result.version.advisories {
                let severity = match advisory.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" | "moderate" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Unknown,
                };

                let vuln = Vulnerability {
                    id: advisory.advisory_key.id.clone(),
                    aliases: vec![],
                    source: VulnerabilitySource::DepsDevAdvisory,
                    summary: advisory.title.clone().unwrap_or_else(|| advisory.advisory_key.id.clone()),
                    details: advisory.description.clone(),
                    severity,
                    cvss_score: None,
                    package: result.version.version_key.name.clone(),
                    affected_versions: vec![VersionRange {
                        introduced: None,
                        fixed: None,
                        last_affected: None,
                    }],
                    fixed_version: None,
                    references: advisory.url.as_ref().map(|u| vec![Reference {
                        ref_type: ReferenceType::Advisory,
                        url: u.clone(),
                    }]).unwrap_or_default(),
                    cwes: vec![],
                    published: None,
                    modified: None,
                };

                findings.push(Finding::sca_with_source(
                    vuln,
                    &result.version.version_key.name,
                    &result.version.version_key.version,
                    None, // deps.dev results don't have a specific lock file
                ));
            }
        }

        Ok(findings)
    }
}

/// Convert PURL type to deps.dev system name.
fn purl_to_deps_dev_system(purl_type: &str) -> Result<&'static str> {
    match purl_type.to_lowercase().as_str() {
        "cargo" => Ok("CARGO"),
        "npm" => Ok("NPM"),
        "pypi" => Ok("PYPI"),
        "golang" | "go" => Ok("GO"),
        "maven" => Ok("MAVEN"),
        "nuget" => Ok("NUGET"),
        _ => Err(AuditorError::Analysis(format!(
            "Unsupported deps.dev system: {}",
            purl_type
        ))),
    }
}

// deps.dev API types

/// Version information from deps.dev.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevVersion {
    /// Version identifier.
    pub version_key: DepsDevVersionKey,
    /// Whether this is the default version.
    #[serde(default)]
    pub is_default: bool,
    /// License information.
    #[serde(default)]
    pub licenses: Vec<String>,
    /// Security advisories affecting this version.
    #[serde(default)]
    pub advisories: Vec<DepsDevAdvisory>,
    /// Links to related resources.
    #[serde(default)]
    pub links: Vec<DepsDevLink>,
    /// Published timestamp.
    pub published_at: Option<String>,
}

/// Version key (system/name/version).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevVersionKey {
    /// Ecosystem (NPM, PYPI, etc.).
    pub system: String,
    /// Package name.
    pub name: String,
    /// Version string.
    pub version: String,
}

/// Security advisory from deps.dev.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevAdvisory {
    /// Advisory identifier.
    pub advisory_key: DepsDevAdvisoryKey,
    /// Advisory URL.
    pub url: Option<String>,
    /// Title.
    pub title: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Severity (CRITICAL, HIGH, MEDIUM, LOW).
    #[serde(default)]
    pub severity: String,
    /// Related CVE IDs.
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Advisory key.
#[derive(Debug, Clone, Deserialize)]
pub struct DepsDevAdvisoryKey {
    /// Advisory ID (e.g., GHSA-xxxx-xxxx-xxxx).
    pub id: String,
}

/// Link to related resource.
#[derive(Debug, Clone, Deserialize)]
pub struct DepsDevLink {
    /// Link label.
    pub label: String,
    /// URL.
    pub url: String,
}

/// Dependencies response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevDependencies {
    /// Direct dependencies.
    #[serde(default)]
    pub nodes: Vec<DepsDevDependencyNode>,
    /// Dependency edges.
    #[serde(default)]
    pub edges: Vec<DepsDevDependencyEdge>,
}

/// Dependency node.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevDependencyNode {
    /// Node version key.
    pub version_key: DepsDevVersionKey,
    /// Relationship type.
    #[serde(default)]
    pub relation: String,
}

/// Dependency edge.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsDevDependencyEdge {
    /// From node index.
    pub from_node: usize,
    /// To node index.
    pub to_node: usize,
    /// Requirement string.
    pub requirement: Option<String>,
}

/// Batch query request.
#[derive(Debug, Serialize)]
struct DepsDevBatchQuery {
    requests: Vec<DepsDevBatchRequest>,
}

/// Single request in batch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepsDevBatchRequest {
    version_key: DepsDevVersionKey,
}

/// Batch query response.
#[derive(Debug, Deserialize)]
struct DepsDevBatchResponse {
    #[serde(default)]
    results: Vec<DepsDevBatchResult>,
}

/// Single result in batch response.
#[derive(Debug, Clone, Deserialize)]
pub struct DepsDevBatchResult {
    /// Version information.
    pub version: DepsDevVersion,
}

// ============================================================================
// NVD (National Vulnerability Database) Client for CVSS Enrichment
// ============================================================================

/// NVD API client for fetching CVSS scores and enriching vulnerability data.
///
/// The NVD provides authoritative CVSS scores that may be more accurate than
/// scores from other sources. This client fetches CVE details to enrich
/// vulnerability findings with official CVSS metrics.
pub struct NvdClient {
    /// HTTP client.
    client: Client,
    /// NVD API base URL.
    base_url: String,
    /// API key (optional, increases rate limits).
    api_key: Option<String>,
    /// Request timeout.
    timeout: Duration,
    /// Rate limit delay between requests (2 seconds without API key, 0.6s with key).
    rate_limit_delay: Duration,
}

impl NvdClient {
    /// Create a new NVD client without an API key.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            api_key: None,
            timeout: Duration::from_secs(30),
            rate_limit_delay: Duration::from_secs(2), // 5 requests per 30 seconds without key
        }
    }

    /// Create a new NVD client with an API key.
    pub fn with_api_key(api_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            api_key: Some(api_key),
            timeout: Duration::from_secs(30),
            rate_limit_delay: Duration::from_millis(600), // 50 requests per 30 seconds with key
        }
    }

    /// Fetch CVE details from NVD.
    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<NvdCveData>> {
        // Validate CVE ID format
        if !cve_id.starts_with("CVE-") {
            return Ok(None);
        }

        let url = format!("{}?cveId={}", self.base_url, cve_id);

        let mut request = self.client.get(&url).timeout(self.timeout);

        if let Some(ref key) = self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            return Err(AuditorError::Analysis(format!(
                "NVD API error: {}",
                response.status()
            )));
        }

        let data: NvdApiResponse = response.json().await?;

        if let Some(vuln) = data.vulnerabilities.into_iter().next() {
            return Ok(Some(vuln.cve));
        }

        Ok(None)
    }

    /// Extract CVSS v3.1 score from CVE data.
    pub fn extract_cvss_v3(&self, cve: &NvdCveData) -> Option<CvssV3Data> {
        // Try CVSS v3.1 first, then v3.0
        if let Some(ref metrics) = cve.metrics {
            // Check cvssMetricV31 first
            if let Some(v31_list) = &metrics.cvss_metric_v31 {
                if let Some(metric) = v31_list.first() {
                    return Some(CvssV3Data {
                        version: "3.1".to_string(),
                        vector_string: metric.cvss_data.vector_string.clone(),
                        base_score: metric.cvss_data.base_score,
                        base_severity: metric.cvss_data.base_severity.clone(),
                        exploitability_score: metric.exploitability_score,
                        impact_score: metric.impact_score,
                    });
                }
            }

            // Fall back to cvssMetricV30
            if let Some(v30_list) = &metrics.cvss_metric_v30 {
                if let Some(metric) = v30_list.first() {
                    return Some(CvssV3Data {
                        version: "3.0".to_string(),
                        vector_string: metric.cvss_data.vector_string.clone(),
                        base_score: metric.cvss_data.base_score,
                        base_severity: metric.cvss_data.base_severity.clone(),
                        exploitability_score: metric.exploitability_score,
                        impact_score: metric.impact_score,
                    });
                }
            }
        }

        None
    }

    /// Extract CWE IDs from CVE data.
    pub fn extract_cwes(&self, cve: &NvdCveData) -> Vec<String> {
        let mut cwes = Vec::new();

        if let Some(ref weaknesses) = cve.weaknesses {
            for weakness in weaknesses {
                for desc in &weakness.description {
                    if desc.lang == "en" && desc.value.starts_with("CWE-") {
                        cwes.push(desc.value.clone());
                    }
                }
            }
        }

        cwes
    }

    /// Enrich a vulnerability with NVD data.
    pub async fn enrich_vulnerability(&self, vuln: &mut Vulnerability) -> Result<bool> {
        // Find a CVE ID in the vulnerability's ID or aliases
        let cve_id = if vuln.id.starts_with("CVE-") {
            Some(vuln.id.clone())
        } else {
            vuln.aliases.iter().find(|a| a.starts_with("CVE-")).cloned()
        };

        let cve_id = match cve_id {
            Some(id) => id,
            None => return Ok(false), // No CVE to look up
        };

        // Rate limit
        tokio::time::sleep(self.rate_limit_delay).await;

        // Fetch CVE data
        let cve = match self.get_cve(&cve_id).await? {
            Some(cve) => cve,
            None => return Ok(false),
        };

        let mut enriched = false;

        // Extract CVSS score if we don't have one or NVD has a more authoritative one
        if let Some(cvss) = self.extract_cvss_v3(&cve) {
            if vuln.cvss_score.is_none() || vuln.source != VulnerabilitySource::Nvd {
                vuln.cvss_score = Some(cvss.base_score);
                vuln.severity = Severity::from_cvss(cvss.base_score);
                enriched = true;
            }
        }

        // Add CWEs if we don't have them
        if vuln.cwes.is_empty() {
            let cwes = self.extract_cwes(&cve);
            if !cwes.is_empty() {
                vuln.cwes = cwes;
                enriched = true;
            }
        }

        // Add description if we don't have details
        if vuln.details.is_none() {
            if let Some(desc) = cve.descriptions.iter().find(|d| d.lang == "en") {
                vuln.details = Some(desc.value.clone());
                enriched = true;
            }
        }

        // Add NVD reference
        let nvd_url = format!("https://nvd.nist.gov/vuln/detail/{}", cve_id);
        if !vuln.references.iter().any(|r| r.url == nvd_url) {
            vuln.references.push(Reference {
                ref_type: ReferenceType::Advisory,
                url: nvd_url,
            });
            enriched = true;
        }

        Ok(enriched)
    }

    /// Batch enrich multiple vulnerabilities.
    pub async fn enrich_vulnerabilities(&self, vulns: &mut [Vulnerability]) -> Result<usize> {
        let mut enriched_count = 0;

        for vuln in vulns.iter_mut() {
            match self.enrich_vulnerability(vuln).await {
                Ok(true) => enriched_count += 1,
                Ok(false) => {}
                Err(e) => {
                    debug!("Failed to enrich {}: {}", vuln.id, e);
                }
            }
        }

        Ok(enriched_count)
    }
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracted CVSS v3 data.
#[derive(Debug, Clone)]
pub struct CvssV3Data {
    /// CVSS version (3.0 or 3.1).
    pub version: String,
    /// CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
    pub vector_string: String,
    /// Base score (0.0 - 10.0).
    pub base_score: f64,
    /// Base severity (NONE, LOW, MEDIUM, HIGH, CRITICAL).
    pub base_severity: String,
    /// Exploitability score (0.0 - 10.0).
    pub exploitability_score: Option<f64>,
    /// Impact score (0.0 - 10.0).
    pub impact_score: Option<f64>,
}

// NVD API response types

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdApiResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerabilityWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerabilityWrapper {
    cve: NvdCveData,
}

/// CVE data from NVD API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCveData {
    /// CVE ID.
    pub id: String,
    /// Source identifier.
    pub source_identifier: Option<String>,
    /// Publication date.
    pub published: Option<String>,
    /// Last modification date.
    pub last_modified: Option<String>,
    /// Vulnerability status.
    pub vuln_status: Option<String>,
    /// Descriptions in various languages.
    #[serde(default)]
    pub descriptions: Vec<NvdDescription>,
    /// CVSS metrics.
    pub metrics: Option<NvdMetrics>,
    /// Weakness enumeration (CWEs).
    pub weaknesses: Option<Vec<NvdWeakness>>,
    /// Configuration data.
    pub configurations: Option<serde_json::Value>,
    /// References.
    pub references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdMetrics {
    pub cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    pub cvss_metric_v2: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssMetric {
    pub source: String,
    #[serde(rename = "type")]
    pub metric_type: String,
    pub cvss_data: NvdCvssData,
    pub exploitability_score: Option<f64>,
    pub impact_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssData {
    pub version: String,
    pub vector_string: String,
    pub base_score: f64,
    pub base_severity: String,
}

#[derive(Debug, Deserialize)]
pub struct NvdWeakness {
    pub source: String,
    #[serde(rename = "type")]
    pub weakness_type: String,
    #[serde(default)]
    pub description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
pub struct NvdReference {
    pub url: String,
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// OSV API request/response types

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    published: Option<String>,
    modified: Option<String>,
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_osv_query() {
        let engine = ScaEngine::new();

        // Query for a known vulnerable package
        let result = engine.query_osv("lodash", "4.17.20", "npm").await;

        // This should succeed (though may or may not find vulnerabilities)
        assert!(result.is_ok());
    }

    #[test]
    fn test_purl_parse_cargo() {
        let purl = PackageUrl::parse("pkg:cargo/serde@1.0.193").unwrap();
        assert_eq!(purl.pkg_type, "cargo");
        assert_eq!(purl.name, "serde");
        assert_eq!(purl.version, Some("1.0.193".to_string()));
        assert!(purl.namespace.is_none());
    }

    #[test]
    fn test_purl_parse_npm_scoped() {
        let purl = PackageUrl::parse("pkg:npm/@types/node@20.10.0").unwrap();
        assert_eq!(purl.pkg_type, "npm");
        assert_eq!(purl.name, "node");
        assert_eq!(purl.namespace, Some("@types".to_string()));
        assert_eq!(purl.version, Some("20.10.0".to_string()));
    }

    #[test]
    fn test_purl_parse_npm_unscoped() {
        let purl = PackageUrl::parse("pkg:npm/lodash@4.17.21").unwrap();
        assert_eq!(purl.pkg_type, "npm");
        assert_eq!(purl.name, "lodash");
        assert!(purl.namespace.is_none());
        assert_eq!(purl.version, Some("4.17.21".to_string()));
    }

    #[test]
    fn test_purl_parse_pypi() {
        let purl = PackageUrl::parse("pkg:pypi/requests@2.31.0").unwrap();
        assert_eq!(purl.pkg_type, "pypi");
        assert_eq!(purl.name, "requests");
        assert_eq!(purl.version, Some("2.31.0".to_string()));
    }

    #[test]
    fn test_purl_parse_golang() {
        let purl = PackageUrl::parse("pkg:golang/github.com/gin-gonic/gin@1.9.1").unwrap();
        assert_eq!(purl.pkg_type, "golang");
        assert_eq!(purl.name, "github.com/gin-gonic/gin");
        assert_eq!(purl.version, Some("1.9.1".to_string()));
    }

    #[test]
    fn test_purl_parse_with_qualifiers() {
        let purl = PackageUrl::parse("pkg:npm/lodash@4.17.21?vcs_url=git://github.com").unwrap();
        assert_eq!(purl.qualifiers.get("vcs_url"), Some(&"git://github.com".to_string()));
    }

    #[test]
    fn test_purl_roundtrip_cargo() {
        let original = PackageUrl::from_cargo("serde", "1.0.193");
        let serialized = original.to_string();
        assert_eq!(serialized, "pkg:cargo/serde@1.0.193");
    }

    #[test]
    fn test_purl_roundtrip_npm_scoped() {
        let original = PackageUrl::from_npm("@types/node", "20.10.0");
        let serialized = original.to_string();
        assert_eq!(serialized, "pkg:npm/%40types/node@20.10.0");
    }

    #[test]
    fn test_purl_osv_ecosystem() {
        assert_eq!(PackageUrl::from_cargo("serde", "1.0").osv_ecosystem(), "crates.io");
        assert_eq!(PackageUrl::from_npm("lodash", "4.17").osv_ecosystem(), "npm");
        assert_eq!(PackageUrl::from_pypi("requests", "2.31").osv_ecosystem(), "PyPI");
        assert_eq!(PackageUrl::from_golang("github.com/gin-gonic/gin", "1.9").osv_ecosystem(), "Go");
    }

    #[test]
    fn test_purl_pypi_normalization() {
        // PyPI normalizes underscores to hyphens
        let purl = PackageUrl::from_pypi("my_package", "1.0.0");
        assert_eq!(purl.name, "my-package");
    }

    // Ecosystem-specific version parsing tests

    #[test]
    fn test_npm_version_in_range() {
        // Basic range check
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Npm,
            "1.5.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));

        // Below introduced
        assert!(!EcosystemVersionParser::version_in_range(
            Ecosystem::Npm,
            "0.9.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));

        // At or above fixed
        assert!(!EcosystemVersionParser::version_in_range(
            Ecosystem::Npm,
            "2.0.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));

        // Prerelease versions
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Npm,
            "1.0.0-beta.1",
            Some("1.0.0-alpha.1"),
            Some("1.0.0"),
            None
        ));
    }

    #[test]
    fn test_npm_satisfies_range() {
        // Caret range
        assert!(EcosystemVersionParser::npm_satisfies("1.2.3", "^1.0.0"));
        assert!(!EcosystemVersionParser::npm_satisfies("2.0.0", "^1.0.0"));

        // Tilde range
        assert!(EcosystemVersionParser::npm_satisfies("1.2.5", "~1.2.0"));
        assert!(!EcosystemVersionParser::npm_satisfies("1.3.0", "~1.2.0"));

        // Hyphen range
        assert!(EcosystemVersionParser::npm_satisfies("1.5.0", "1.0.0 - 2.0.0"));
    }

    #[test]
    fn test_pypi_version_in_range() {
        // Basic PEP 440 versions
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::PyPI,
            "2.0.0",
            Some("1.0.0"),
            Some("3.0.0"),
            None
        ));

        // Pre-release versions
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::PyPI,
            "1.0a1",
            Some("1.0a0"),
            Some("1.0"),
            None
        ));

        // Post release
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::PyPI,
            "1.0.post1",
            Some("1.0"),
            Some("1.1"),
            None
        ));
    }

    #[test]
    fn test_pypi_satisfies_specifier() {
        // Compatible release
        assert!(EcosystemVersionParser::pypi_satisfies("1.4.2", "~=1.4.0"));
        assert!(!EcosystemVersionParser::pypi_satisfies("1.5.0", "~=1.4.0"));

        // Version matching
        assert!(EcosystemVersionParser::pypi_satisfies("1.0", "==1.0"));
        assert!(EcosystemVersionParser::pypi_satisfies("1.0.0", "==1.0.*"));

        // Range specifiers
        assert!(EcosystemVersionParser::pypi_satisfies("1.5.0", ">=1.0,<2.0"));
        assert!(!EcosystemVersionParser::pypi_satisfies("2.0.0", ">=1.0,<2.0"));
    }

    #[test]
    fn test_cargo_version_in_range() {
        // Standard semver
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Cargo,
            "1.5.0",
            Some("1.0.0"),
            Some("2.0.0"),
            None
        ));

        // Pre-release
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Cargo,
            "1.0.0-alpha.2",
            Some("1.0.0-alpha.1"),
            Some("1.0.0"),
            None
        ));
    }

    #[test]
    fn test_cargo_satisfies_requirement() {
        // Caret (default)
        assert!(EcosystemVersionParser::cargo_satisfies("1.2.3", "^1.0"));
        assert!(!EcosystemVersionParser::cargo_satisfies("2.0.0", "^1.0"));

        // Exact
        assert!(EcosystemVersionParser::cargo_satisfies("1.0.0", "=1.0.0"));
        assert!(!EcosystemVersionParser::cargo_satisfies("1.0.1", "=1.0.0"));

        // Wildcard
        assert!(EcosystemVersionParser::cargo_satisfies("1.2.3", "1.*"));
        assert!(!EcosystemVersionParser::cargo_satisfies("2.0.0", "1.*"));
    }

    #[test]
    fn test_go_version_in_range() {
        // Go uses v prefix
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Go,
            "v1.5.0",
            Some("v1.0.0"),
            Some("v2.0.0"),
            None
        ));

        // Mixed v prefix
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Go,
            "1.5.0",
            Some("v1.0.0"),
            Some("2.0.0"),
            None
        ));
    }

    #[test]
    fn test_fallback_version_comparison() {
        // Non-standard versions fall back to numeric-aware comparison
        assert!(EcosystemVersionParser::version_in_range(
            Ecosystem::Unknown,
            "2.10.0",
            Some("2.9.0"),
            Some("2.11.0"),
            None
        ));

        // Should handle 2.10 > 2.9 correctly (not string comparison)
        assert!(!EcosystemVersionParser::version_in_range(
            Ecosystem::Unknown,
            "2.8.0",
            Some("2.9.0"),
            None,
            None
        ));
    }

    #[test]
    fn test_version_range_ext() {
        let range = VersionRange {
            introduced: Some("1.0.0".to_string()),
            fixed: Some("2.0.0".to_string()),
            last_affected: None,
        };

        assert!(range.contains_version("1.5.0", Ecosystem::Cargo));
        assert!(!range.contains_version("2.0.0", Ecosystem::Cargo));
        assert!(!range.contains_version("0.9.0", Ecosystem::Cargo));
    }

    #[test]
    fn test_ecosystem_detection() {
        assert_eq!(Ecosystem::from_purl_type("cargo"), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_purl_type("npm"), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_purl_type("pypi"), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_purl_type("golang"), Ecosystem::Go);
        assert_eq!(Ecosystem::from_purl_type("go"), Ecosystem::Go);
        assert_eq!(Ecosystem::from_purl_type("maven"), Ecosystem::Maven);
        assert_eq!(Ecosystem::from_purl_type("unknown"), Ecosystem::Unknown);
    }

    // NVD Client tests

    #[test]
    fn test_nvd_client_creation() {
        let client = NvdClient::new();
        assert!(client.api_key.is_none());

        let client_with_key = NvdClient::with_api_key("test-key".to_string());
        assert_eq!(client_with_key.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_nvd_cvss_extraction() {
        let client = NvdClient::new();

        // Create mock CVE data with CVSS v3.1
        let cve = NvdCveData {
            id: "CVE-2024-1234".to_string(),
            source_identifier: None,
            published: None,
            last_modified: None,
            vuln_status: None,
            descriptions: vec![NvdDescription {
                lang: "en".to_string(),
                value: "Test vulnerability description".to_string(),
            }],
            metrics: Some(NvdMetrics {
                cvss_metric_v31: Some(vec![NvdCvssMetric {
                    source: "nvd@nist.gov".to_string(),
                    metric_type: "Primary".to_string(),
                    cvss_data: NvdCvssData {
                        version: "3.1".to_string(),
                        vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                        base_score: 9.8,
                        base_severity: "CRITICAL".to_string(),
                    },
                    exploitability_score: Some(3.9),
                    impact_score: Some(5.9),
                }]),
                cvss_metric_v30: None,
                cvss_metric_v2: None,
            }),
            weaknesses: Some(vec![NvdWeakness {
                source: "nvd@nist.gov".to_string(),
                weakness_type: "Primary".to_string(),
                description: vec![NvdDescription {
                    lang: "en".to_string(),
                    value: "CWE-89".to_string(),
                }],
            }]),
            configurations: None,
            references: None,
        };

        // Test CVSS extraction
        let cvss = client.extract_cvss_v3(&cve).unwrap();
        assert_eq!(cvss.version, "3.1");
        assert_eq!(cvss.base_score, 9.8);
        assert_eq!(cvss.base_severity, "CRITICAL");
        assert_eq!(cvss.exploitability_score, Some(3.9));

        // Test CWE extraction
        let cwes = client.extract_cwes(&cve);
        assert_eq!(cwes, vec!["CWE-89"]);
    }

    #[test]
    fn test_nvd_cvss_v30_fallback() {
        let client = NvdClient::new();

        // Create CVE data with only CVSS v3.0 (no v3.1)
        let cve = NvdCveData {
            id: "CVE-2024-5678".to_string(),
            source_identifier: None,
            published: None,
            last_modified: None,
            vuln_status: None,
            descriptions: vec![],
            metrics: Some(NvdMetrics {
                cvss_metric_v31: None,
                cvss_metric_v30: Some(vec![NvdCvssMetric {
                    source: "nvd@nist.gov".to_string(),
                    metric_type: "Primary".to_string(),
                    cvss_data: NvdCvssData {
                        version: "3.0".to_string(),
                        vector_string: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
                        base_score: 6.1,
                        base_severity: "MEDIUM".to_string(),
                    },
                    exploitability_score: Some(2.8),
                    impact_score: Some(2.7),
                }]),
                cvss_metric_v2: None,
            }),
            weaknesses: None,
            configurations: None,
            references: None,
        };

        let cvss = client.extract_cvss_v3(&cve).unwrap();
        assert_eq!(cvss.version, "3.0");
        assert_eq!(cvss.base_score, 6.1);
    }

    #[test]
    fn test_nvd_no_metrics() {
        let client = NvdClient::new();

        let cve = NvdCveData {
            id: "CVE-2024-0000".to_string(),
            source_identifier: None,
            published: None,
            last_modified: None,
            vuln_status: None,
            descriptions: vec![],
            metrics: None,
            weaknesses: None,
            configurations: None,
            references: None,
        };

        assert!(client.extract_cvss_v3(&cve).is_none());
        assert!(client.extract_cwes(&cve).is_empty());
    }
}
