//! Configuration management for the security auditor.

use crate::models::Severity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for the security auditor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// GitHub configuration
    pub github: GitHubConfig,

    /// Analysis configuration
    pub analysis: AnalysisConfig,

    /// Output configuration
    pub output: OutputConfig,

    /// Concurrency settings
    pub concurrency: ConcurrencyConfig,
}

/// GitHub API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub personal access token or app token
    pub token: Option<String>,

    /// GitHub API base URL (for GitHub Enterprise)
    #[serde(default = "default_github_api_url")]
    pub api_url: String,

    /// Rate limit handling: delay in milliseconds between requests
    #[serde(default = "default_rate_limit_delay")]
    pub rate_limit_delay_ms: u64,

    /// Maximum repositories to scan in a single run
    #[serde(default = "default_max_repos")]
    pub max_repos: usize,
}

/// Analysis configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Enable SAST (Static Application Security Testing)
    #[serde(default = "default_true")]
    pub enable_sast: bool,

    /// Enable SCA (Software Composition Analysis)
    #[serde(default = "default_true")]
    pub enable_sca: bool,

    /// Enable secret detection
    #[serde(default = "default_true")]
    pub enable_secrets: bool,

    /// Enable provenance verification (SLSA/Sigstore)
    #[serde(default)]
    pub enable_provenance: bool,

    /// Enable AI-driven analysis
    #[serde(default)]
    pub enable_ai: bool,

    /// Languages to analyze
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,

    /// File patterns to ignore
    #[serde(default = "default_ignore_patterns")]
    pub ignore_patterns: Vec<String>,

    /// Maximum file size to analyze (in bytes)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,

    /// Minimum entropy threshold for secret detection
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Minimum severity level to report
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,

    /// Temporary directory for cloning repositories
    pub temp_dir: Option<PathBuf>,
}

/// Output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    #[serde(default)]
    pub format: OutputFormat,

    /// Output file path (stdout if not specified)
    pub output_path: Option<PathBuf>,

    /// Include source code snippets in findings
    #[serde(default = "default_true")]
    pub include_snippets: bool,

    /// Maximum snippet lines
    #[serde(default = "default_snippet_lines")]
    pub snippet_lines: usize,
}

/// Concurrency configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyConfig {
    /// Number of tokio worker threads (0 = auto)
    #[serde(default)]
    pub tokio_workers: usize,

    /// Number of rayon threads for CPU-bound work (0 = auto)
    #[serde(default)]
    pub rayon_threads: usize,

    /// Maximum concurrent repository clones
    #[serde(default = "default_concurrent_clones")]
    pub concurrent_clones: usize,

    /// Channel buffer size for pipeline
    #[serde(default = "default_channel_buffer")]
    pub channel_buffer: usize,

    /// Maximum files to process in a single parallel batch
    /// (helps control memory usage for large repositories)
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

/// Output format enumeration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// SARIF (Static Analysis Results Interchange Format)
    #[default]
    Sarif,
    /// JSON format
    Json,
    /// Human-readable text
    Text,
}

// Default value functions
fn default_github_api_url() -> String {
    "https://api.github.com".to_string()
}

fn default_rate_limit_delay() -> u64 {
    100
}

fn default_max_repos() -> usize {
    100
}

fn default_true() -> bool {
    true
}

fn default_languages() -> Vec<String> {
    vec![
        "rust".to_string(),
        "python".to_string(),
        "javascript".to_string(),
        "go".to_string(),
    ]
}

fn default_ignore_patterns() -> Vec<String> {
    vec![
        "**/target/**".to_string(),
        "**/node_modules/**".to_string(),
        "**/vendor/**".to_string(),
        "**/.git/**".to_string(),
        "**/dist/**".to_string(),
        "**/build/**".to_string(),
    ]
}

fn default_max_file_size() -> usize {
    1024 * 1024 // 1 MB
}

fn default_entropy_threshold() -> f64 {
    4.5
}

fn default_min_severity() -> Severity {
    Severity::Low
}

fn default_snippet_lines() -> usize {
    5
}

fn default_concurrent_clones() -> usize {
    4
}

fn default_channel_buffer() -> usize {
    100
}

fn default_batch_size() -> usize {
    500 // Process files in batches to control memory
}

impl Default for Config {
    fn default() -> Self {
        Self {
            github: GitHubConfig::default(),
            analysis: AnalysisConfig::default(),
            output: OutputConfig::default(),
            concurrency: ConcurrencyConfig::default(),
        }
    }
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            token: std::env::var("GITHUB_TOKEN").ok(),
            api_url: default_github_api_url(),
            rate_limit_delay_ms: default_rate_limit_delay(),
            max_repos: default_max_repos(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_sast: true,
            enable_sca: true,
            enable_secrets: true,
            enable_provenance: false,
            enable_ai: false,
            languages: default_languages(),
            ignore_patterns: default_ignore_patterns(),
            max_file_size: default_max_file_size(),
            entropy_threshold: default_entropy_threshold(),
            min_severity: default_min_severity(),
            temp_dir: None,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::default(),
            output_path: None,
            include_snippets: true,
            snippet_lines: default_snippet_lines(),
        }
    }
}

impl Default for ConcurrencyConfig {
    fn default() -> Self {
        Self {
            tokio_workers: 0,
            rayon_threads: 0,
            concurrent_clones: default_concurrent_clones(),
            channel_buffer: default_channel_buffer(),
            batch_size: default_batch_size(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Create a configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder for creating configurations programmatically.
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn github_token(mut self, token: impl Into<String>) -> Self {
        self.config.github.token = Some(token.into());
        self
    }

    pub fn enable_sast(mut self, enable: bool) -> Self {
        self.config.analysis.enable_sast = enable;
        self
    }

    pub fn enable_sca(mut self, enable: bool) -> Self {
        self.config.analysis.enable_sca = enable;
        self
    }

    pub fn enable_secrets(mut self, enable: bool) -> Self {
        self.config.analysis.enable_secrets = enable;
        self
    }

    pub fn enable_provenance(mut self, enable: bool) -> Self {
        self.config.analysis.enable_provenance = enable;
        self
    }

    pub fn enable_ai(mut self, enable: bool) -> Self {
        self.config.analysis.enable_ai = enable;
        self
    }

    pub fn min_severity(mut self, severity: Severity) -> Self {
        self.config.analysis.min_severity = severity;
        self
    }

    pub fn output_format(mut self, format: OutputFormat) -> Self {
        self.config.output.format = format;
        self
    }

    pub fn output_path(mut self, path: PathBuf) -> Self {
        self.config.output.output_path = Some(path);
        self
    }

    pub fn temp_dir(mut self, path: PathBuf) -> Self {
        self.config.analysis.temp_dir = Some(path);
        self
    }

    pub fn languages(mut self, languages: Vec<String>) -> Self {
        self.config.analysis.languages = languages;
        self
    }

    pub fn max_repos(mut self, max: usize) -> Self {
        self.config.github.max_repos = max;
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}
