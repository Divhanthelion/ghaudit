//! Configuration: built-in defaults, optionally overridden by a TOML file, then by CLI flags.
//!
//! Unknown keys are rejected so a typo in a config file is an error rather than a
//! silently ignored setting.

use crate::error::{Error, Result};
use crate::model::Severity;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Languages the SAST engine has rules for.
pub const SUPPORTED_LANGUAGES: &[&str] = &["rust", "python", "javascript", "typescript", "go"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub github: GitHubConfig,
    pub analysis: AnalysisConfig,
    pub sca: ScaConfig,
    pub ai: AiConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GitHubConfig {
    /// Personal access token. Prefer the GITHUB_TOKEN environment variable.
    #[serde(skip_serializing)]
    pub token: Option<String>,
    /// REST API base URL; change for GitHub Enterprise Server.
    pub api_url: String,
    /// Upper bound on repositories scanned by `org`, `user` and `search`.
    pub max_repos: usize,
    pub include_forks: bool,
    pub include_archived: bool,
    /// Repositories cloned and scanned at the same time in multi-repo scans.
    pub concurrency: usize,
    /// Give up on one repository (clone and analysis) after this many seconds.
    pub repo_timeout_secs: u64,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            token: None,
            api_url: "https://api.github.com".into(),
            max_repos: 100,
            include_forks: false,
            include_archived: false,
            concurrency: 4,
            repo_timeout_secs: 1800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    pub sast: bool,
    pub secrets: bool,
    pub sca: bool,
    /// GitHub Actions workflow checks.
    pub workflows: bool,
    /// Committed AI-agent and editor configuration (MCP servers, auto-approval, ...).
    pub agents: bool,
    /// Repository and organization security settings, read from the GitHub API.
    /// Needs a token; most checks need admin access to be assessable.
    pub settings: bool,
    /// Also search every commit for credentials that were removed from the current
    /// files. Repositories are then cloned with full history.
    pub history: bool,
    pub ai: bool,
    /// Languages the SAST engine analyzes. Secrets are searched in every text file.
    pub languages: Vec<String>,
    /// Extra gitignore-style patterns to skip, relative to the scan root.
    pub exclude: Vec<String>,
    /// Files larger than this many bytes are skipped (and listed in the report).
    pub max_file_size: u64,
    /// Whether the scanned repository's own controls are honored: its `.gitignore` and
    /// `.ignore` files, `ghaudit:ignore` comments and `osv-scanner.toml` files.
    /// `auto` honors them for local directories and not for cloned repositories, whose
    /// author could use them to hide findings.
    pub trust_repo: TrustRepo,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustRepo {
    #[default]
    Auto,
    Always,
    Never,
}

impl TrustRepo {
    /// Resolve `auto` for a local directory (`true`) or a cloned repository (`false`).
    pub fn resolve(self, local: bool) -> bool {
        match self {
            TrustRepo::Auto => local,
            TrustRepo::Always => true,
            TrustRepo::Never => false,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            sast: true,
            secrets: true,
            sca: true,
            workflows: true,
            agents: true,
            settings: true,
            history: false,
            ai: false,
            languages: SUPPORTED_LANGUAGES.iter().map(|s| s.to_string()).collect(),
            exclude: Vec::new(),
            max_file_size: 1024 * 1024,
            trust_repo: TrustRepo::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScaConfig {
    /// osv-scanner executable name or path.
    pub osv_scanner: String,
    /// Extra arguments passed to `osv-scanner scan source`,
    /// e.g. `["--offline-vulnerabilities", "--download-offline-databases"]`.
    pub extra_args: Vec<String>,
    pub timeout_secs: u64,
}

impl Default for ScaConfig {
    fn default() -> Self {
        Self {
            osv_scanner: "osv-scanner".into(),
            extra_args: Vec::new(),
            timeout_secs: 600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    /// OpenAI-compatible chat completions endpoint (LM Studio, Ollama, llama.cpp server, ...).
    pub url: String,
    pub model: String,
    pub timeout_secs: u64,
    /// Stop after this many files; local models are slow.
    pub max_files: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:1234/v1/chat/completions".into(),
            model: "local-model".into(),
            timeout_secs: 120,
            max_files: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    /// Findings below this severity are left out of the report.
    pub min_severity: Severity,
    /// Exit with status 1 when any reported finding is at or above this severity.
    pub fail_on: FailOn,
    /// A previous JSON report: findings already in it are left out of this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<std::path::PathBuf>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Low,
            fail_on: FailOn(Some(Severity::High)),
            baseline: None,
        }
    }
}

/// A severity threshold, or `never` to always exit 0 when the scan completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FailOn(pub Option<Severity>);

impl std::str::FromStr for FailOn {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.trim().eq_ignore_ascii_case("never") {
            Ok(FailOn(None))
        } else {
            s.parse::<Severity>().map(|sev| FailOn(Some(sev)))
        }
    }
}

impl TryFrom<String> for FailOn {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<FailOn> for String {
    fn from(f: FailOn) -> String {
        f.0.map_or("never".into(), |s| s.as_str().into())
    }
}

impl Config {
    /// Load a TOML config file. Missing sections and keys fall back to defaults.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    /// Check values that serde cannot.
    pub fn validate(&self) -> Result<()> {
        for lang in &self.analysis.languages {
            if !SUPPORTED_LANGUAGES.contains(&lang.as_str()) {
                return Err(Error::Config(format!(
                    "unsupported language '{lang}' (supported: {})",
                    SUPPORTED_LANGUAGES.join(", ")
                )));
            }
        }
        if self.analysis.history && !self.analysis.secrets {
            return Err(Error::Config(
                "history searches for credentials: it needs the secrets analyzer".into(),
            ));
        }
        if self.analysis.max_file_size == 0 {
            return Err(Error::Config("max_file_size must be greater than 0".into()));
        }
        if self.github.max_repos == 0 {
            return Err(Error::Config("max_repos must be greater than 0".into()));
        }
        if self.github.concurrency == 0 {
            return Err(Error::Config("concurrency must be greater than 0".into()));
        }
        if self.github.repo_timeout_secs == 0 {
            return Err(Error::Config(
                "repo_timeout_secs must be greater than 0".into(),
            ));
        }
        Ok(())
    }

    /// Environment variables override the AI defaults so existing LM Studio setups keep working.
    pub fn apply_env(&mut self) {
        let var = |names: &[&str]| names.iter().find_map(|n| std::env::var(n).ok());
        if let Some(url) = var(&["GHAUDIT_AI_URL", "LMSTUDIO_URL"]) {
            self.ai.url = url;
        }
        if let Some(model) = var(&["GHAUDIT_AI_MODEL", "LMSTUDIO_MODEL"]) {
            self.ai.model = model;
        }
        if let Some(t) = var(&["GHAUDIT_AI_TIMEOUT_SECS", "LMSTUDIO_TIMEOUT_SECS"])
            && let Ok(t) = t.parse()
        {
            self.ai.timeout_secs = t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_file_uses_defaults() {
        let c: Config = toml::from_str("[analysis]\nsca = false\n").unwrap();
        assert!(!c.analysis.sca);
        assert!(c.analysis.sast);
        assert_eq!(c.report.fail_on, FailOn(Some(Severity::High)));
        assert_eq!(c.github.api_url, "https://api.github.com");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>("[analysis]\nenable_sast = false\n").unwrap_err();
        assert!(err.to_string().contains("enable_sast"));
        assert!(toml::from_str::<Config>("[concurrency]\nrayon_threads = 4\n").is_err());
    }

    #[test]
    fn severities_parse_from_toml() {
        let c: Config =
            toml::from_str("[report]\nmin_severity = \"medium\"\nfail_on = \"critical\"\n")
                .unwrap();
        assert_eq!(c.report.min_severity, Severity::Medium);
        assert_eq!(c.report.fail_on, FailOn(Some(Severity::Critical)));
        let c: Config = toml::from_str("[report]\nfail_on = \"never\"\n").unwrap();
        assert_eq!(c.report.fail_on, FailOn(None));
    }

    #[test]
    fn example_config_is_valid_and_documents_the_defaults() {
        let example: Config = toml::from_str(include_str!("../ghaudit.example.toml")).unwrap();
        example.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&example).unwrap(),
            serde_json::to_value(Config::default()).unwrap(),
            "ghaudit.example.toml must show the real defaults"
        );
    }

    #[test]
    fn trust_resolution() {
        let c: Config = toml::from_str("[analysis]\ntrust_repo = \"never\"\n").unwrap();
        assert!(!c.analysis.trust_repo.resolve(true));
        assert!(TrustRepo::Auto.resolve(true));
        assert!(!TrustRepo::Auto.resolve(false));
        assert!(TrustRepo::Always.resolve(false));
        assert!(toml::from_str::<Config>("[analysis]\ntrust_repo = \"yes\"\n").is_err());
    }

    #[test]
    fn unsupported_language_is_an_error() {
        let mut c = Config::default();
        c.analysis.languages = vec!["cobol".into()];
        assert!(c.validate().is_err());
    }
}
