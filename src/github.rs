//! Minimal GitHub REST API client: just the endpoints ghaudit needs.
//!
//! Besides listing repositories and reading settings, it can fetch a commit's files
//! without git: [`GitHub::download_archive`] (the tarball), [`GitHub::tree`] (the list
//! of files to check it against) and [`GitHub::blob_raw`] (one file).

use crate::error::{Error, Result};
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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
    /// Absent from some listings; `None` then.
    #[serde(default)]
    pub default_branch: Option<String>,
}

/// A commit's files, from `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Tree {
    #[serde(rename = "tree")]
    pub entries: Vec<TreeEntry>,
    /// GitHub lists at most 100,000 entries (7 MB); beyond that the list is cut short.
    #[serde(default)]
    pub truncated: bool,
}

/// One entry of a [`Tree`].
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TreeEntry {
    /// Relative to the repository root, `/`-separated.
    pub path: String,
    /// `100644` or `100755` (file), `120000` (symbolic link: the blob is its target),
    /// `040000` (directory), `160000` (submodule).
    pub mode: String,
    /// `blob`, `tree` or `commit` (a submodule).
    #[serde(rename = "type")]
    pub kind: String,
    /// The git object id: for a blob, the SHA-1 of `blob <size>\0<content>`.
    pub sha: String,
    /// Bytes, for blobs.
    #[serde(default)]
    pub size: Option<u64>,
}

/// Redirects a download may follow (GitHub answers with one, to codeload).
const MAX_REDIRECTS: usize = 3;
/// Waits before retrying a download that got a 5xx or 429 response.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(4)];

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimit {
    pub limit: u64,
    pub remaining: u64,
    /// Unix timestamp when the window resets.
    pub reset: u64,
}

pub struct GitHub {
    client: Client,
    /// For archive downloads: follows no redirects itself, and has no total timeout.
    download: Client,
    api_url: String,
    token: Option<String>,
    /// Origins (`https://host[:port]`) a download may be redirected to.
    download_origins: Vec<String>,
}

/// Response of an endpoint whose failure statuses carry meaning: on settings
/// endpoints, 404 can mean "disabled" and 403 "this token may not look".
#[derive(Debug, Clone)]
pub struct Probe {
    pub status: u16,
    /// JSON body; `Null` for an empty body (e.g. 204).
    pub body: serde_json::Value,
}

impl Probe {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// GitHub's `message`, for 4xx responses.
    pub fn message(&self) -> &str {
        self.body
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or_default()
    }
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
        const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()?;
        // An archive can take minutes; a stalled connection still fails within a minute.
        let download = Client::builder()
            .user_agent(USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(60))
            .build()?;
        let api_url = api_url.trim_end_matches('/').to_string();
        Ok(Self {
            client,
            download,
            download_origins: download_origins(&api_url),
            api_url,
            token: token.filter(|t| !t.is_empty()),
        })
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Web base URL of the configured host (`https://github.com`).
    pub fn web_url(&self) -> String {
        web_url(&self.api_url)
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

    /// The commit at the tip of the default branch, or `None` for an empty repository.
    /// `branch` saves a request when the caller knows the default branch already.
    pub async fn default_branch_head(
        &self,
        owner: &str,
        name: &str,
        branch: Option<&str>,
    ) -> Result<Option<String>> {
        let branch = match branch {
            Some(b) => b.to_string(),
            None => self
                .repo(owner, name)
                .await?
                .default_branch
                .ok_or_else(|| Error::GitHub(format!("{owner}/{name} has no default branch")))?,
        };
        self.branch_head(owner, name, &branch).await
    }

    /// The commit at the tip of `branch`, or `None` for an empty repository (GitHub
    /// answers 409).
    pub async fn branch_head(
        &self,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> Result<Option<String>> {
        let path = format!(
            "/repos/{owner}/{name}/commits/heads/{}",
            path_segment(branch)
        );
        let resp = self
            .request(&path, &[], Some("application/vnd.github.sha"))
            .await?;
        if resp.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(api_error(resp).await);
        }
        let sha = resp.text().await.map_err(http)?.trim().to_ascii_lowercase();
        if !is_object_id(&sha) {
            return Err(Error::GitHub(format!(
                "GitHub did not return a commit id for {owner}/{name}"
            )));
        }
        Ok(Some(sha))
    }

    /// Every file of commit `sha` (`sha` must be a commit or tree id).
    pub async fn tree(&self, owner: &str, name: &str, sha: &str) -> Result<Tree> {
        self.get(
            &format!("/repos/{owner}/{name}/git/trees/{sha}"),
            &[("recursive", "1")],
        )
        .await?
        .json()
        .await
        .map_err(http)
    }

    /// The content of blob `sha`, refused when it is larger than `max` bytes.
    pub async fn blob_raw(&self, owner: &str, name: &str, sha: &str, max: u64) -> Result<Vec<u8>> {
        let path = format!("/repos/{owner}/{name}/git/blobs/{sha}");
        let mut resp = self
            .request(&path, &[], Some("application/vnd.github.raw+json"))
            .await?;
        if !resp.status().is_success() {
            return Err(api_error(resp).await);
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(http)? {
            if (body.len() + chunk.len()) as u64 > max {
                return Err(Error::GitHub(format!(
                    "blob {sha} is larger than {max} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Download the gzip-compressed tarball of commit `sha` (GitHub's `git archive` of
    /// it) to `out`, and return its size in bytes.
    ///
    /// GitHub redirects the request to codeload, with a short-lived token for private
    /// repositories in the URL. The redirects are followed here, not by reqwest: at
    /// most [`MAX_REDIRECTS`], over https only, to the API host, the web host or
    /// `codeload.<web host>`. The GitHub token is sent only to the API host. No error
    /// carries a URL, so codeload's token cannot reach a report or a log. A download
    /// over `max_bytes` is stopped, and a 5xx or 429 response is retried twice.
    pub async fn download_archive(
        &self,
        owner: &str,
        name: &str,
        sha: &str,
        out: &Path,
        max_bytes: u64,
    ) -> Result<u64> {
        let mut url = Url::parse(&format!(
            "{}/repos/{owner}/{name}/tarball/{sha}",
            self.api_url
        ))
        .map_err(|e| Error::Config(format!("invalid github.api_url: {e}")))?;
        let mut redirects = 0;
        let mut resp = loop {
            let resp = self.download_request(&url).await?;
            if !resp.status().is_redirection() {
                break resp;
            }
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(Error::GitHub(
                    "the archive download was redirected too many times".into(),
                ));
            }
            let next = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .ok_or_else(|| {
                    Error::GitHub("the archive download was redirected to an invalid URL".into())
                })?;
            redirect_allowed(&next, &self.download_origins, &self.api_url).map_err(|why| {
                Error::GitHub(format!("refused to follow the archive download to {why}"))
            })?;
            url = next;
        };
        if !resp.status().is_success() {
            return Err(api_error(resp).await);
        }
        let mut file = tokio::fs::File::create(out).await?;
        let mut written = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(http)? {
            written += chunk.len() as u64;
            if written > max_bytes {
                return Err(Error::GitHub(format!(
                    "the archive is larger than {} MiB",
                    max_bytes >> 20
                )));
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        Ok(written)
    }

    /// One request of a download, retried on 5xx and 429. Authorization and the API's
    /// headers go to the API host only.
    async fn download_request(&self, url: &Url) -> Result<Response> {
        let to_api = Url::parse(&self.api_url).is_ok_and(|api| api.origin() == url.origin());
        let mut attempt = 0;
        loop {
            let mut req = self.download.get(url.clone());
            if to_api {
                req = req
                    .header(header::ACCEPT, "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28");
                if let Some(token) = &self.token {
                    req = req.bearer_auth(token);
                }
            }
            let resp = req.send().await.map_err(http)?;
            match retry_delay(&resp, attempt) {
                Some(delay) => {
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                None => return Ok(resp),
            }
        }
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

    /// Repositories owned by `user`. GitHub lists only public repositories for
    /// `/users/{name}/repos`, so when the token belongs to `user` their own listing is
    /// used instead, which includes private repositories.
    pub async fn user_repos(&self, user: &str, limit: usize) -> Result<Vec<RepoInfo>> {
        if self
            .authenticated_login()
            .await
            .is_some_and(|me| me.eq_ignore_ascii_case(user))
        {
            return self
                .paginate(
                    "/user/repos",
                    &[("affiliation", "owner"), ("sort", "pushed")],
                    limit,
                    false,
                )
                .await;
        }
        self.paginate(
            &format!("/users/{user}/repos"),
            &[("type", "owner"), ("sort", "pushed")],
            limit,
            false,
        )
        .await
    }

    /// Login of the token's user. `None` without a token, for a token GitHub does not
    /// accept, or for tokens that are not a user's (e.g. GitHub App installation tokens).
    pub async fn authenticated_login(&self) -> Option<String> {
        #[derive(Deserialize)]
        struct Me {
            login: String,
        }
        self.token.as_ref()?;
        let resp = self.send("/user", &[]).await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<Me>().await.ok().map(|m| m.login)
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
        let resp = self.send(path, query).await?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(api_error(resp).await)
    }

    async fn send(&self, path: &str, query: &[(&str, &str)]) -> Result<Response> {
        self.request(path, query, None).await
    }

    /// GET an API path, with `accept` in place of the JSON media type when given.
    async fn request(
        &self,
        path: &str,
        query: &[(&str, &str)],
        accept: Option<&'static str>,
    ) -> Result<Response> {
        let mut req = self
            .client
            .get(format!("{}{path}", self.api_url))
            .query(query);
        if let Some(accept) = accept {
            req = req.header(header::ACCEPT, accept);
        }
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        Ok(req.send().await?)
    }

    /// GET that returns 4xx responses instead of failing on them. Rate limiting, server
    /// errors and network failures are still errors: they say nothing about the setting.
    pub async fn probe(&self, path: impl AsRef<str>, query: &[(&str, &str)]) -> Result<Probe> {
        let resp = self.send(path.as_ref(), query).await?;
        let status = resp.status();
        let limited = resp
            .headers()
            .get("x-ratelimit-remaining")
            .is_some_and(|v| v.as_bytes() == b"0");
        if status.is_server_error()
            || status == StatusCode::TOO_MANY_REQUESTS
            || (status == StatusCode::FORBIDDEN && limited)
        {
            return Err(api_error(resp).await);
        }
        let text = resp.text().await?;
        let body = if text.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
        };
        Ok(Probe {
            status: status.as_u16(),
            body,
        })
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

/// A reqwest error without its URL, which may hold a download token.
fn http(e: reqwest::Error) -> Error {
    Error::Http(e.without_url())
}

/// A full, lower-case git object id (SHA-1, or SHA-256 for such repositories).
pub(crate) fn is_object_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// How long to wait before retrying `resp`, or `None` to use it as it is: only server
/// errors and 429s are retried, never an exhausted rate limit or a long `Retry-After`.
fn retry_delay(resp: &Response, attempt: usize) -> Option<Duration> {
    let status = resp.status();
    if !(status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS) {
        return None;
    }
    let headers = resp.headers();
    if headers
        .get("x-ratelimit-remaining")
        .is_some_and(|v| v.as_bytes() == b"0")
    {
        return None;
    }
    let delay = *RETRY_DELAYS.get(attempt)?;
    match headers
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().parse::<u64>())
    {
        Some(Ok(secs)) if secs <= 60 => Some(Duration::from_secs(secs)),
        Some(_) => None,
        None => Some(delay),
    }
}

/// Origins an archive download may be redirected to: the API's, the web host's and
/// `codeload.<web host>` (GitHub Enterprise without subdomain isolation serves codeload
/// under the web host).
fn download_origins(api_url: &str) -> Vec<String> {
    let mut origins: Vec<String> = [api_url.to_string(), web_url(api_url)]
        .iter()
        .filter_map(|u| Url::parse(u).ok())
        .map(|u| u.origin().ascii_serialization())
        .collect();
    if let Ok(mut web) = Url::parse(&web_url(api_url))
        && let Some(host) = web.host_str().map(|h| format!("codeload.{h}"))
        && web.set_host(Some(&host)).is_ok()
    {
        origins.push(web.origin().ascii_serialization());
    }
    origins.dedup();
    origins
}

/// Whether a download may follow a redirect to `next`; `Err` describes it without its
/// path or query (where codeload's token is).
fn redirect_allowed(
    next: &Url,
    origins: &[String],
    api_url: &str,
) -> std::result::Result<(), String> {
    let host = next.host_str().unwrap_or_default();
    if !next.username().is_empty() || next.password().is_some() {
        return Err(format!("a URL with credentials ({host})"));
    }
    // Plain http only when the API itself is plain http (a test server).
    let http_api = api_url.starts_with("http://");
    match next.scheme() {
        "https" => {}
        "http" if http_api => {}
        scheme => return Err(format!("a {scheme} URL ({host})")),
    }
    if !origins.contains(&next.origin().ascii_serialization()) {
        return Err(format!("another host ({host})"));
    }
    Ok(())
}

/// Escape characters a branch name may contain that are special in a URL path.
pub(crate) fn path_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '%' => "%25".into(),
            '#' => "%23".into(),
            '?' => "%3F".into(),
            ' ' => "%20".into(),
            c => c.to_string(),
        })
        .collect()
}

/// Host of the configured GitHub web UI (`github.com`, or a GitHub Enterprise host).
pub fn web_host(api_url: &str) -> String {
    let web = web_url(api_url);
    let rest = web.split_once("://").map_or(web.as_str(), |(_, r)| r);
    rest.split('/').next().unwrap_or(rest).to_ascii_lowercase()
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
pub(crate) mod mock {
    //! A minimal HTTP server for tests of code that talks to the GitHub API.

    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Requests received, as `"GET /path?query auth=true"`.
    pub type Log = Arc<Mutex<Vec<String>>>;

    /// A response: status, extra headers and body.
    pub type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);

    /// Serve text bodies: `route` maps a request line (`"GET /path?query"`) to
    /// (status, extra headers, body). Returns the base URL and a log of requests.
    pub async fn serve<F>(route: F) -> (String, Log)
    where
        F: Fn(&str) -> (u16, Vec<(&'static str, String)>, String) + Send + Sync + 'static,
    {
        serve_bytes(move |line| {
            let (status, headers, body) = route(line);
            (status, headers, body.into_bytes())
        })
        .await
    }

    /// Like [`serve`], with byte bodies. A `x-mock-length` header replaces the real
    /// `content-length`, so a response can promise more bytes than it sends.
    pub async fn serve_bytes<F>(route: F) -> (String, Log)
    where
        F: Fn(&str) -> Reply + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        let route = Arc::new(route);
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
                    let length = headers
                        .iter()
                        .find(|(k, _)| *k == "x-mock-length")
                        .map_or(body.len().to_string(), |(_, v)| v.clone());
                    let mut resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {length}\r\nconnection: close\r\n"
                    );
                    for (k, v) in headers.iter().filter(|(k, _)| *k != "x-mock-length") {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str("\r\n");
                    let mut bytes = resp.into_bytes();
                    bytes.extend_from_slice(&body);
                    let _ = sock.write_all(&bytes).await;
                });
            }
        });
        (format!("http://{addr}"), log)
    }
}

#[cfg(test)]
mod tests {
    use super::mock::serve as mock;
    use super::*;

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
    async fn your_own_user_listing_includes_private_repositories() {
        let (url, log) = mock(|line| {
            if line.starts_with("GET /user/repos?") {
                (200, vec![], repos_json(0, 3))
            } else if line.starts_with("GET /user ") || line == "GET /user" {
                (200, vec![], r#"{"login":"Me"}"#.into())
            } else if line.starts_with("GET /users/") {
                (200, vec![], repos_json(0, 1))
            } else {
                (404, vec![], "{}".into())
            }
        })
        .await;
        let gh = GitHub::new(&url, Some("t0ken".into())).unwrap();
        assert_eq!(gh.user_repos("me", 10).await.unwrap().len(), 3);
        assert_eq!(gh.user_repos("someone-else", 10).await.unwrap().len(), 1);
        let log = log.lock().unwrap().clone();
        assert!(
            log.iter()
                .any(|l| l.contains("/user/repos?") && l.contains("affiliation=owner")),
            "{log:?}"
        );
        // Without a token, no /user call is made.
        let gh = GitHub::new(&url, None).unwrap();
        assert_eq!(gh.user_repos("me", 10).await.unwrap().len(), 1);
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

    /// A secret-looking query parameter, built at runtime like codeload's.
    fn codeload_query() -> String {
        ["?to", "ken=", "AB7QX2LMZP9VKW4RT"].concat()
    }

    /// The API on one mock server redirects the tarball to "codeload" on a second one.
    async fn redirected_download(
        codeload: impl Fn(&str) -> mock::Reply + Send + Sync + 'static,
        allow_codeload: bool,
    ) -> (GitHub, mock::Log, mock::Log) {
        let (codeload_url, codeload_log) = mock::serve_bytes(codeload).await;
        let target = format!(
            "{codeload_url}/o/r/legacy.tar.gz/{}{}",
            "a".repeat(40),
            codeload_query()
        );
        let (api, api_log) = mock(move |line| {
            if line.starts_with("GET /repos/o/r/tarball/") {
                (302, vec![("location", target.clone())], String::new())
            } else {
                (404, vec![], r#"{"message":"Not Found"}"#.into())
            }
        })
        .await;
        let mut gh = GitHub::new(&api, Some("t0ken".into())).unwrap();
        if allow_codeload {
            gh.download_origins.push(codeload_url);
        }
        (gh, api_log, codeload_log)
    }

    #[tokio::test]
    async fn archives_follow_the_redirect_without_the_token() {
        let (gh, api_log, codeload_log) =
            redirected_download(|_| (200, vec![], b"archive bytes".to_vec()), true).await;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a.tar.gz");
        let sha = "a".repeat(40);
        let n = gh
            .download_archive("o", "r", &sha, &out, 1 << 20)
            .await
            .unwrap();
        assert_eq!(n, 13);
        assert_eq!(std::fs::read(&out).unwrap(), b"archive bytes");
        let api_log = api_log.lock().unwrap().clone();
        let codeload_log = codeload_log.lock().unwrap().clone();
        assert_eq!(
            api_log,
            vec![format!("GET /repos/o/r/tarball/{sha} auth=true")]
        );
        assert_eq!(codeload_log.len(), 1, "{codeload_log:?}");
        assert!(
            codeload_log[0].ends_with("auth=false"),
            "the token stays with the API host: {codeload_log:?}"
        );
    }

    #[tokio::test]
    async fn download_errors_never_show_the_codeload_token() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a.tar.gz");
        let sha = "a".repeat(40);
        let check = |err: Error, expect: &str| {
            let text = format!("{err} {err:?}");
            assert!(!text.contains("ken="), "{text}");
            assert!(!text.contains("AB7QX2LMZP9VKW4RT"), "{text}");
            assert!(text.contains(expect), "{text}");
        };

        // A host that is not GitHub's.
        let (gh, _, log) = redirected_download(|_| (200, vec![], Vec::new()), false).await;
        let err = gh.download_archive("o", "r", &sha, &out, 1 << 20).await;
        check(err.unwrap_err(), "another host");
        assert!(log.lock().unwrap().is_empty(), "nothing was sent there");

        // The connection drops before the promised body arrives.
        let truncated = |_: &str| (200, vec![("x-mock-length", "1000".into())], vec![0u8; 10]);
        let (gh, _, _) = redirected_download(truncated, true).await;
        let err = gh.download_archive("o", "r", &sha, &out, 1 << 20).await;
        check(err.unwrap_err(), "");

        // The archive is over the size limit.
        let (gh, _, _) = redirected_download(|_| (200, vec![], vec![7u8; 4096]), true).await;
        let err = gh.download_archive("o", "r", &sha, &out, 1000).await;
        check(err.unwrap_err(), "larger than");

        // codeload keeps failing (it is retried first).
        let (gh, _, log) = redirected_download(|_| (503, vec![], Vec::new()), true).await;
        let err = gh.download_archive("o", "r", &sha, &out, 1 << 20).await;
        check(err.unwrap_err(), "503");
        assert_eq!(log.lock().unwrap().len(), 3, "two retries");
    }

    #[tokio::test]
    async fn downloads_retry_server_errors() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let (url, _) = mock(move |_| {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                (502, vec![], String::new())
            } else {
                (200, vec![], "ok".into())
            }
        })
        .await;
        let gh = GitHub::new(&url, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("a.tar.gz");
        assert_eq!(
            gh.download_archive("o", "r", &"b".repeat(40), &out, 100)
                .await
                .unwrap(),
            2
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn too_many_redirects_are_refused() {
        let (url, log) = mock(|line| {
            let n: usize = line.rsplit('/').next().unwrap().parse().unwrap_or(0);
            (
                302,
                vec![("location", format!("/loop/{}", n + 1))],
                String::new(),
            )
        })
        .await;
        let gh = GitHub::new(&url, None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = gh
            .download_archive("o", "r", &"c".repeat(40), &dir.path().join("x"), 100)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too many"), "{err}");
        assert_eq!(log.lock().unwrap().len(), MAX_REDIRECTS + 1);
    }

    #[test]
    fn redirects_stay_on_https_and_github_hosts() {
        let api = "https://api.github.com";
        let origins = download_origins(api);
        assert_eq!(
            origins,
            vec![
                "https://api.github.com",
                "https://github.com",
                "https://codeload.github.com"
            ]
        );
        let ok = |u: &str| redirect_allowed(&Url::parse(u).unwrap(), &origins, api);
        ok("https://codeload.github.com/o/r/legacy.tar.gz/abc?token=x").unwrap();
        ok("https://api.github.com/repositories/1/tarball/abc").unwrap();
        assert!(
            ok("http://codeload.github.com/o/r")
                .unwrap_err()
                .contains("http URL")
        );
        assert!(
            ok("https://evil.example/o/r")
                .unwrap_err()
                .contains("another host")
        );
        assert!(ok("https://codeload.github.com:8443/o/r").is_err());
        assert!(ok("https://user:pw@codeload.github.com/o/r").is_err());
        assert!(ok("ftp://codeload.github.com/o/r").is_err());
        let err = ok("https://evil.example/o/r?token=secret").unwrap_err();
        assert!(!err.contains("secret"), "{err}");

        let ghe = download_origins("https://ghe.corp/api/v3");
        assert_eq!(ghe, vec!["https://ghe.corp", "https://codeload.ghe.corp"]);
    }

    #[tokio::test]
    async fn commits_trees_and_blobs() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let (url, log) = mock(move |line| match line {
            "GET /repos/o/r" => (200, vec![], r#"{"full_name":"o/r","clone_url":"x","default_branch":"dev/next"}"#.into()),
            "GET /repos/o/r/commits/heads/dev/next" => (200, vec![], format!("{}\n", sha.to_uppercase())),
            "GET /repos/o/empty/commits/heads/main" => (409, vec![], r#"{"message":"Git Repository is empty."}"#.into()),
            "GET /repos/o/odd/commits/heads/main" => (200, vec![], "<html>".into()),
            "GET /repos/o/r/git/trees/abc?recursive=1" => (200, vec![], r#"{"sha":"abc","tree":[{"path":"a.txt","mode":"100644","type":"blob","sha":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","size":0},{"path":"d","mode":"040000","type":"tree","sha":"x"}],"truncated":true}"#.into()),
            "GET /repos/o/r/git/blobs/b1" => (200, vec![], "hello\n".into()),
            _ => (404, vec![], r#"{"message":"Not Found"}"#.into()),
        })
        .await;
        let gh = GitHub::new(&url, None).unwrap();
        assert_eq!(
            gh.default_branch_head("o", "r", None)
                .await
                .unwrap()
                .as_deref(),
            Some(sha)
        );
        assert_eq!(gh.branch_head("o", "empty", "main").await.unwrap(), None);
        assert!(gh.branch_head("o", "odd", "main").await.is_err());
        let err = gh
            .default_branch_head("o", "private", None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("private repositories need a token"),
            "{err}"
        );

        let tree = gh.tree("o", "r", "abc").await.unwrap();
        assert!(tree.truncated);
        assert_eq!(tree.entries.len(), 2);
        assert_eq!(tree.entries[0].size, Some(0));
        assert_eq!(tree.entries[1].kind, "tree");

        assert_eq!(gh.blob_raw("o", "r", "b1", 6).await.unwrap(), b"hello\n");
        assert!(
            gh.blob_raw("o", "r", "b1", 5).await.is_err(),
            "over the cap"
        );
        let log = log.lock().unwrap().clone();
        assert!(log.iter().all(|l| l.ends_with("auth=false")), "{log:?}");
    }

    #[test]
    fn web_urls() {
        assert_eq!(web_url("https://api.github.com"), "https://github.com");
        assert_eq!(web_url("https://api.github.com/"), "https://github.com");
        assert_eq!(web_url("https://ghe.corp/api/v3"), "https://ghe.corp");
        assert_eq!(web_host("https://api.github.com"), "github.com");
        assert_eq!(web_host("https://GHE.corp:8443/api/v3"), "ghe.corp:8443");
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
