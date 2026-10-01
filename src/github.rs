//! Minimal GitHub REST API client: just the endpoints ghaudit needs.

use crate::error::{Error, Result};
use reqwest::{Client, Response, StatusCode, header};
use serde::Deserialize;
use std::time::Duration;

/// Repository metadata needed to decide whether and how to clone.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RepoInfo {
    pub full_name: String,
    pub clone_url: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub fork: bool,
    #[serde(default)]
    pub private: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimit {
    pub limit: u64,
    pub remaining: u64,
    /// Unix timestamp when the window resets.
    pub reset: u64,
}

pub struct GitHub {
    client: Client,
    api_url: String,
    token: Option<String>,
}

impl GitHub {
    pub fn new(api_url: &str, token: Option<String>) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "X-GitHub-Api-Version",
            header::HeaderValue::from_static("2022-11-28"),
        );
        let client = Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            api_url: api_url.trim_end_matches('/').to_string(),
            token: token.filter(|t| !t.is_empty()),
        })
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Clone URL for `owner/name` on the configured GitHub host.
    pub fn clone_url(&self, owner: &str, name: &str) -> String {
        format!("{}/{owner}/{name}.git", web_url(&self.api_url))
    }

    pub async fn repo(&self, owner: &str, name: &str) -> Result<RepoInfo> {
        self.get(&format!("/repos/{owner}/{name}"), &[])
            .await?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn org_repos(&self, org: &str, limit: usize) -> Result<Vec<RepoInfo>> {
        self.paginate(
            &format!("/orgs/{org}/repos"),
            &[("type", "all"), ("sort", "pushed")],
            limit,
            false,
        )
        .await
    }

    pub async fn user_repos(&self, user: &str, limit: usize) -> Result<Vec<RepoInfo>> {
        self.paginate(
            &format!("/users/{user}/repos"),
            &[("type", "owner"), ("sort", "pushed")],
            limit,
            false,
        )
        .await
    }

    /// Repositories matching a search query (GitHub caps search at 1000 results).
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<RepoInfo>> {
        self.paginate(
            "/search/repositories",
            &[("q", query)],
            limit.min(1000),
            true,
        )
        .await
    }

    pub async fn rate_limit(&self) -> Result<RateLimit> {
        #[derive(Deserialize)]
        struct Resp {
            resources: Resources,
        }
        #[derive(Deserialize)]
        struct Resources {
            core: RateLimit,
        }
        let resp: Resp = self.get("/rate_limit", &[]).await?.json().await?;
        Ok(resp.resources.core)
    }

    async fn paginate(
        &self,
        path: &str,
        query: &[(&str, &str)],
        limit: usize,
        search: bool,
    ) -> Result<Vec<RepoInfo>> {
        #[derive(Deserialize)]
        struct SearchPage {
            items: Vec<RepoInfo>,
        }
        let mut repos = Vec::new();
        let mut page = 1u32;
        while repos.len() < limit {
            let page_str = page.to_string();
            let mut params = query.to_vec();
            params.push(("per_page", "100"));
            params.push(("page", &page_str));
            let resp = self.get(path, &params).await?;
            let items: Vec<RepoInfo> = if search {
                resp.json::<SearchPage>().await?.items
            } else {
                resp.json().await?
            };
            let n = items.len();
            repos.extend(items);
            if n < 100 {
                break;
            }
            page += 1;
        }
        repos.truncate(limit);
        Ok(repos)
    }

    async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Response> {
        let mut req = self
            .client
            .get(format!("{}{path}", self.api_url))
            .query(query);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(api_error(resp).await)
    }
}

async fn api_error(resp: Response) -> Error {
    let status = resp.status();
    let remaining = resp
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let reset = resp
        .headers()
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());
    #[derive(Deserialize)]
    struct Body {
        message: Option<String>,
    }
    let message = resp
        .json::<Body>()
        .await
        .ok()
        .and_then(|b| b.message)
        .unwrap_or_default();

    if matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) && remaining.as_deref() == Some("0")
    {
        let when = reset
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|t| t.format("%H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "later".into());
        return Error::GitHub(format!(
            "rate limit exhausted; resets at {when}. Authenticated requests get a higher limit (set GITHUB_TOKEN)"
        ));
    }
    if status == StatusCode::NOT_FOUND {
        return Error::GitHub("not found (private repositories need a token with access)".into());
    }
    Error::GitHub(format!("{status}: {message}"))
}

/// Web base URL for an API base URL: `https://api.github.com` -> `https://github.com`,
/// `https://ghe.example.com/api/v3` -> `https://ghe.example.com`.
pub fn web_url(api_url: &str) -> String {
    let api = api_url.trim_end_matches('/');
    if let Some(rest) = api.strip_prefix("https://api.") {
        return format!("https://{rest}");
    }
    api.strip_suffix("/api/v3").unwrap_or(api).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal HTTP server: `route` maps a request line ("GET /path?query") to
    /// (status, extra headers, body). Returns the base URL and a log of requests.
    async fn mock<F>(route: F) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>)
    where
        F: Fn(&str) -> (u16, Vec<(&'static str, String)>, String) + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log2 = log.clone();
        let route = std::sync::Arc::new(route);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let route = route.clone();
                let log = log2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let line = req
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .rsplit_once(' ')
                        .map(|(a, _)| a.to_string())
                        .unwrap_or_default();
                    let auth = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                        .map(|l| l.to_string());
                    log.lock()
                        .unwrap()
                        .push(format!("{line} auth={}", auth.is_some()));
                    let (status, headers, body) = route(&line);
                    let mut resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                        body.len()
                    );
                    for (k, v) in headers {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str("\r\n");
                    resp.push_str(&body);
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://{addr}"), log)
    }

    fn repos_json(start: usize, n: usize) -> String {
        let items: Vec<String> = (start..start + n)
            .map(|i| format!(r#"{{"full_name":"o/r{i}","clone_url":"https://github.com/o/r{i}.git","fork":{},"archived":false}}"#, i % 2 == 1))
            .collect();
        format!("[{}]", items.join(","))
    }

    #[tokio::test]
    async fn org_listing_paginates_until_the_limit() {
        let (url, log) = mock(|line| {
            let page = line
                .split(['?', '&'])
                .find_map(|kv| kv.strip_prefix("page="))
                .unwrap_or("1")
                .to_string();
            match page.as_str() {
                "1" => (200, vec![], repos_json(0, 100)),
                "2" => (200, vec![], repos_json(100, 100)),
                _ => (200, vec![], repos_json(200, 7)),
            }
        })
        .await;
        let gh = GitHub::new(&url, Some("t0ken".into())).unwrap();
        let repos = gh.org_repos("acme", 150).await.unwrap();
        assert_eq!(repos.len(), 150);
        assert_eq!(repos[149].full_name, "o/r149");
        let log = log.lock().unwrap().clone();
        assert_eq!(log.len(), 2, "stops once the limit is reached: {log:?}");
        assert!(
            log[0].starts_with("GET /orgs/acme/repos?") && log[0].ends_with("auth=true"),
            "{log:?}"
        );

        let all = gh.org_repos("acme", 1000).await.unwrap();
        assert_eq!(all.len(), 207, "stops at a short page");
    }

    #[tokio::test]
    async fn search_reads_items_and_rate_limit_errors_are_explained() {
        let (url, _) = mock(|line| {
            if line.starts_with("GET /search/repositories") {
                (
                    200,
                    vec![],
                    format!(r#"{{"total_count":2,"items":{}}}"#, repos_json(0, 2)),
                )
            } else {
                (
                    403,
                    vec![
                        ("x-ratelimit-remaining", "0".into()),
                        ("x-ratelimit-reset", "1700000000".into()),
                    ],
                    r#"{"message":"API rate limit exceeded"}"#.into(),
                )
            }
        })
        .await;
        let gh = GitHub::new(&url, None).unwrap();
        assert_eq!(gh.search("topic:cli", 10).await.unwrap().len(), 2);
        let err = gh.user_repos("someone", 10).await.unwrap_err().to_string();
        assert!(
            err.contains("rate limit exhausted") && err.contains("GITHUB_TOKEN"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn not_found_mentions_private_repositories() {
        let (url, _) = mock(|_| (404, vec![], r#"{"message":"Not Found"}"#.into())).await;
        let err = GitHub::new(&url, None)
            .unwrap()
            .repo("o", "missing")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("private"), "{err}");
    }

    #[test]
    fn web_urls() {
        assert_eq!(web_url("https://api.github.com"), "https://github.com");
        assert_eq!(web_url("https://api.github.com/"), "https://github.com");
        assert_eq!(web_url("https://ghe.corp/api/v3"), "https://ghe.corp");
    }

    #[test]
    fn clone_urls_follow_the_configured_host() {
        let gh = GitHub::new("https://ghe.corp/api/v3", None).unwrap();
        assert_eq!(gh.clone_url("o", "r"), "https://ghe.corp/o/r.git");
        assert!(!gh.has_token());
        assert!(
            !GitHub::new("https://api.github.com", Some(String::new()))
                .unwrap()
                .has_token()
        );
    }

    #[test]
    fn repo_info_deserializes_from_api_shape() {
        let json = r#"{"full_name":"o/r","clone_url":"https://github.com/o/r.git","archived":true,"fork":false,"private":false,"stargazers_count":3}"#;
        let r: RepoInfo = serde_json::from_str(json).unwrap();
        assert!(r.archived);
        assert_eq!(r.full_name, "o/r");
    }
}
