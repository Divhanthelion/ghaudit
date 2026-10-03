//! ghaudit desktop app: serves the web UI in `../ui` and answers its commands.
//!
//! The page is treated as untrusted display code. It renders report content (paths,
//! messages, snippets from scanned repositories) and can only call the commands below:
//! it has no file-system, shell, dialog or opener access of its own. File dialogs and
//! file reads happen here, and links open only to GitHub and OSV (see [`links`]).

mod links;
mod reports;

use ghaudit::Severity;
use ghaudit::analyzer::{agents, rules, settings, workflows};
use ghaudit::model::ScanReport;
use serde::Serialize;
use std::path::PathBuf;
use tauri::{AppHandle, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

/// A rule the page can describe: names and default severities for every check.
#[derive(Serialize)]
struct RuleInfo {
    id: &'static str,
    /// `code`, `workflow`, `agent` or `settings`.
    kind: &'static str,
    name: &'static str,
    severity: Severity,
}

#[derive(Serialize)]
struct Catalog {
    app_version: &'static str,
    scanner_version: &'static str,
    rules: Vec<RuleInfo>,
}

/// Versions, and the name of every rule (settings checks are named only here).
#[tauri::command]
fn catalog() -> Catalog {
    let code = rules::all().map(|r| RuleInfo {
        id: r.id,
        kind: "code",
        name: r.name,
        severity: r.severity,
    });
    let workflow = workflows::RULES.iter().map(|r| RuleInfo {
        id: r.id,
        kind: "workflow",
        name: r.name,
        severity: r.severity,
    });
    let agent = agents::RULES.iter().map(|r| RuleInfo {
        id: r.id,
        kind: "agent",
        name: r.name,
        severity: r.severity,
    });
    let setting = settings::RULES.iter().map(|r| RuleInfo {
        id: r.id,
        kind: "settings",
        name: r.name,
        severity: r.severity,
    });
    Catalog {
        app_version: env!("CARGO_PKG_VERSION"),
        scanner_version: ghaudit::VERSION,
        rules: code.chain(workflow).chain(agent).chain(setting).collect(),
    }
}

/// A report the user opened, with its file name (not its path).
#[derive(Serialize)]
struct Opened {
    name: String,
    report: ScanReport,
}

/// Ask for a report file and read it. `None` when the dialog is cancelled.
#[tauri::command]
async fn open_report(window: WebviewWindow) -> Result<Option<Opened>, String> {
    let Some(path) = pick_report(&window, "Open a ghaudit report").await else {
        return Ok(None);
    };
    let name = reports::display_name(&path);
    let report = tauri::async_runtime::spawn_blocking(move || reports::load(&path))
        .await
        .map_err(|e| e.to_string())??;
    Ok(Some(Opened { name, report }))
}

/// The system's open-file dialog, for JSON reports.
async fn pick_report(window: &WebviewWindow, title: &str) -> Option<PathBuf> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .add_filter("ghaudit report (JSON)", &["json"])
        .pick_file(move |file| {
            let _ = tx.send(file);
        });
    rx.await.ok().flatten()?.into_path().ok()
}

/// Open a GitHub or OSV link in the system browser.
#[tauri::command]
fn open_link(app: AppHandle, url: String) -> Result<(), String> {
    let url = links::check(&url)?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|e| format!("Couldn't open the browser: {e}"))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![catalog, open_report, open_link])
        .run(tauri::generate_context!())
        .expect("error while running ghaudit");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_every_settings_check() {
        let catalog = catalog();
        assert_eq!(catalog.scanner_version, ghaudit::VERSION);
        for rule in settings::RULES {
            assert!(
                catalog
                    .rules
                    .iter()
                    .any(|r| r.id == rule.id && r.kind == "settings")
            );
        }
        let mut ids: Vec<&str> = catalog.rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), catalog.rules.len(), "rule IDs are unique");
    }
}
