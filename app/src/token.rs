//! The GitHub token for scans. It stays in this process: the page learns only where it
//! came from and whose it is, and it is never logged.
//!
//! Sources, in order: the `GITHUB_TOKEN` environment variable, the GitHub CLI's login
//! (`gh auth token`), then a token the user saved in the system keychain.

use crate::{keychain, tools};
use ghaudit::github::GitHub;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Environment,
    GithubCli,
    Keychain,
}

pub struct Token {
    pub source: Source,
    secret: String,
}

impl Token {
    pub fn secret(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("source", &self.source)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// A plausible token: printable ASCII without spaces, of sane length.
pub fn plausible(token: &str) -> bool {
    (20..=1024).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The token to scan with, from the first source that has one.
pub async fn resolve() -> Option<Token> {
    if let Some(secret) = std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| plausible(t))
    {
        return Some(Token {
            source: Source::Environment,
            secret,
        });
    }
    if let Some(secret) = from_github_cli().await {
        return Some(Token {
            source: Source::GithubCli,
            secret,
        });
    }
    let secret = keychain::get().ok().flatten()?;
    Some(Token {
        source: Source::Keychain,
        secret,
    })
}

/// `gh auth token`: the token of the GitHub CLI's login on github.com.
async fn from_github_cli() -> Option<String> {
    let gh = tools::find_gh()?;
    let out = tools::output(&gh, &["auth", "token", "--hostname", "github.com"]).await?;
    let token = out.trim();
    plausible(token).then(|| token.to_string())
}

/// The login of the token's user, or `None` if GitHub doesn't accept it.
pub async fn login(token: &str) -> Option<String> {
    GitHub::new(
        &ghaudit::Config::default().github.api_url,
        Some(token.to_string()),
    )
    .ok()?
    .authenticated_login()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_the_token() {
        let secret = ["gho_", "Zq8Wn3Lk5Rt7Vb2Xy4Pm6Hd9Js1Fc0Ga"].concat();
        let token = Token {
            source: Source::GithubCli,
            secret: secret.clone(),
        };
        let shown = format!("{token:?}");
        assert!(!shown.contains(&secret), "{shown}");
        assert!(shown.contains("GithubCli"));
    }

    #[test]
    fn implausible_tokens_are_ignored() {
        assert!(plausible(
            &["ghp_", "Zq8Wn3Lk5Rt7Vb2Xy4Pm6Hd9Js1Fc0GaQw"].concat()
        ));
        for bad in [
            "",
            "short",
            "has space in the middle of it ok",
            "line\nbreak-token-value-here",
        ] {
            assert!(!plausible(bad), "{bad:?}");
        }
    }
}
