//! Guards for the app's security posture, so a later change can't quietly weaken it.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn app_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// Report content comes from scanned repositories. It must only ever reach the page as
/// text, so no script may parse a string as HTML or code.
#[test]
fn the_page_never_parses_strings_as_html_or_code() {
    let ui = app_dir().join("../ui");
    let mut scripts = Vec::new();
    files(&ui, "js", &mut scripts);
    assert!(scripts.len() >= 5, "found the UI scripts: {scripts:?}");
    let sinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "createContextualFragment",
        "DOMParser",
        "srcdoc",
        "eval(",
        "new Function",
    ];
    for script in scripts {
        let text = std::fs::read_to_string(&script).unwrap();
        for sink in sinks {
            assert!(
                !text.contains(sink),
                "{} uses {sink}: build elements with h() and text nodes instead",
                script.display()
            );
        }
    }
}

/// Everything the page loads ships with the app: no remote scripts, styles or fonts.
#[test]
fn the_page_loads_nothing_remote() {
    let ui = app_dir().join("../ui");
    let mut pages = Vec::new();
    files(&ui, "html", &mut pages);
    files(&ui, "css", &mut pages);
    for page in pages {
        let text = std::fs::read_to_string(&page).unwrap();
        for remote in ["http://", "https://", "//cdn", "@import"] {
            assert!(!text.contains(remote), "{} loads {remote}", page.display());
        }
    }
}

#[test]
fn content_security_policy_stays_strict() {
    let config = read_json(&app_dir().join("tauri.conf.json"));
    let security = &config["app"]["security"];
    assert_eq!(security["freezePrototype"], true);
    let csp = security["csp"].as_str().unwrap();
    for directive in [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src ipc: http://ipc.localhost",
        "object-src 'none'",
    ] {
        assert!(
            csp.split(';').any(|d| d.trim() == directive),
            "CSP lacks `{directive}`: {csp}"
        );
    }
    for loose in ["unsafe-inline", "unsafe-eval", "*", "http:", "https:"] {
        assert!(
            !csp.split_whitespace()
                .any(|t| t.trim_end_matches(';') == loose),
            "CSP allows {loose}: {csp}"
        );
    }
    assert_eq!(security.get("dangerousDisableAssetCspModification"), None);
}

/// The window may call the app's own commands (each listed in build.rs) and nothing
/// else: no plugin permissions, so no file-system, shell, dialog or opener access.
#[test]
fn the_window_gets_only_the_apps_own_commands() {
    let dir = app_dir().join("capabilities");
    let mut capabilities = Vec::new();
    files(&dir, "json", &mut capabilities);
    assert_eq!(capabilities.len(), 1, "{capabilities:?}");
    let capability = read_json(&capabilities[0]);
    assert_eq!(capability["windows"], serde_json::json!(["main"]));
    assert!(capability.get("remote").is_none(), "no remote URLs");
    let build = std::fs::read_to_string(app_dir().join("build.rs")).unwrap();
    for permission in capability["permissions"].as_array().unwrap() {
        let permission = permission.as_str().expect("plain permission names only");
        let command = permission
            .strip_prefix("allow-")
            .unwrap_or_else(|| panic!("{permission} is not one of the app's own commands"));
        assert!(
            build.contains(&format!("\"{}\"", command.replace('-', "_"))),
            "{permission} is not listed in build.rs"
        );
    }
}
