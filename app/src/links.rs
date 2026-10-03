//! Links the page may open in the browser. Report content comes from the scanned
//! repositories, so any link in it is untrusted: only https links to GitHub and to the
//! OSV vulnerability database are opened, and nothing else.

use tauri::Url;

const ALLOWED_HOSTS: [&str; 2] = ["github.com", "osv.dev"];

/// The link, normalized, if the page may open it.
pub fn check(link: &str) -> Result<Url, String> {
    let refused = || format!("Only links to github.com and osv.dev can be opened: {link}");
    let url = Url::parse(link).map_err(|_| refused())?;
    let allowed = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.host_str().is_some_and(|h| ALLOWED_HOSTS.contains(&h));
    if allowed { Ok(url) } else { Err(refused()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_and_osv_links_open() {
        for link in [
            "https://github.com/Divhanthelion/ghaudit",
            "https://github.com/acme/app/blob/0a1b2c/src/db.py#L12",
            "https://github.com/acme/app/settings/rules",
            "https://osv.dev/vulnerability/GHSA-8c75-8mhr-p7r9",
            "https://GitHub.com/acme/app",
        ] {
            assert!(check(link).is_ok(), "{link}");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for link in [
            "http://github.com/acme/app",
            "https://github.com.evil.example/acme/app",
            "https://evil.example/https://github.com/",
            "https://github.com@evil.example/",
            "https://user:pass@github.com/acme/app",
            "https://github.com:8443/acme/app",
            "https://gist.github.com/acme/1",
            "https://ghe.corp.example/acme/app",
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "ms-settings:privacy",
            "github.com/acme/app",
            "",
        ] {
            assert!(check(link).is_err(), "{link}");
        }
    }
}
