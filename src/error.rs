//! Error types for the security auditor application.

use thiserror::Error;

/// Main error type for the security auditor.
#[derive(Error, Debug)]
pub enum AuditorError {
    #[error("GitHub API error: {0}")]
    GitHub(String),

    #[error("Git operation failed: {0}")]
    Git(#[from] git2::Error),

    #[error("Failed to clone repository: {0}")]
    Clone(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Tree-sitter parsing error: {0}")]
    Parse(String),

    #[error("OSV query failed: {0}")]
    Osv(String),

    #[error("Sigstore verification failed: {0}")]
    Sigstore(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Rate limited: retry after {0} seconds")]
    RateLimited(u64),

    #[error("Repository not found: {0}")]
    NotFound(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Invalid Cargo.lock format: {0}")]
    CargoLock(String),

    #[error("Channel send error")]
    ChannelSend,

    #[error("Channel receive error")]
    ChannelRecv,
}

/// Result type alias for auditor operations.
pub type Result<T> = std::result::Result<T, AuditorError>;

impl From<octocrab::Error> for AuditorError {
    fn from(err: octocrab::Error) -> Self {
        AuditorError::GitHub(err.to_string())
    }
}

impl From<cargo_lock::Error> for AuditorError {
    fn from(err: cargo_lock::Error) -> Self {
        AuditorError::CargoLock(err.to_string())
    }
}

impl<T> From<async_channel::SendError<T>> for AuditorError {
    fn from(_: async_channel::SendError<T>) -> Self {
        AuditorError::ChannelSend
    }
}

impl From<async_channel::RecvError> for AuditorError {
    fn from(_: async_channel::RecvError) -> Self {
        AuditorError::ChannelRecv
    }
}
