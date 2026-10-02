//! Error type for the library.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid target '{0}': expected a local path, owner/repo, or a github.com URL")]
    InvalidTarget(String),

    #[error("a GitHub token is required for {0} (set GITHUB_TOKEN or pass --token)")]
    TokenRequired(&'static str),

    #[error("GitHub API: {0}")]
    GitHub(String),

    #[error("git: {0}")]
    Git(String),

    #[error("configuration: {0}")]
    Config(String),

    #[error("{0}")]
    Timeout(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
