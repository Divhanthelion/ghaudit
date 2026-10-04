//! ghaudit desktop app: serves the web UI in `../ui` and answers its commands.
//!
//! The page is treated as untrusted display code. It renders report content (paths,
//! messages, snippets from scanned repositories) and can only call the commands below:
//! it has no file-system, shell, dialog or opener access of its own. File dialogs and
//! file reads happen here, and links open only to GitHub and OSV (see [`links`]). The
//! GitHub token stays here too (see [`token`]): the page never receives it.

mod keychain;
mod links;
mod reports;
mod scan;
mod token;
mod tools;

use ghaudit::analyzer::{agents, rules, settings, workflows};
use ghaudit::model::ScanReport;
use ghaudit::{Progress, ProgressSink, Severity};
use scan::{Context, ScanOptions, TargetSpec};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State, WebviewWindow, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use token::Token;
use tokio::sync::Notify;

#[derive(Default)]
struct AppState {
    /// The folder last chosen in the folder dialog: the only folder the page can scan.
    folder: Mutex<Option<PathBuf>>,
    /// Set while a scan runs; notifying it stops the scan.
    scan: Mutex<Option<Arc<Notify>>>,
    /// The report on screen, kept here so exports and comparisons work on the scanner's
    /// own data rather than on anything the page sends back.
    current: Mutex<Option<Current>>,
}

struct Current {
    report: ScanReport,
    /// An earlier report to compare with.
    baseline: Option<ScanReport>,
}

impl AppState {
    fn show(&self, report: &ScanReport) {
        *self.current.lock().unwrap() = Some(Current {
            report: report.clone(),
            baseline: None,
        });
    }
}

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
async fn open_report(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<Opened>, String> {
    let Some(path) = pick_report(&window, "Open a ghaudit report").await else {
        return Ok(None);
    };
    let name = reports::display_name(&path);
    let report = tauri::async_runtime::spawn_blocking(move || reports::load(&path))
        .await
        .map_err(|e| e.to_string())??;
    state.show(&report);
    Ok(Some(Opened { name, report }))
}

/// The report on screen compared with an earlier one.
#[derive(Serialize)]
struct Compared {
    /// The earlier report's file name and when it was scanned.
    name: String,
    scanned: chrono::DateTime<chrono::Utc>,
    /// The report on screen without the findings the earlier one already had
    /// (`ScanReport::apply_baseline`, as `--baseline` in the CLI).
    report: ScanReport,
}

/// Ask for an earlier report and compare the one on screen with it.
#[tauri::command]
async fn compare_with(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<Compared>, String> {
    if state.current.lock().unwrap().is_none() {
        return Err("Open or run a scan first.".into());
    }
    let Some(path) = pick_report(&window, "Compare with an earlier report").await else {
        return Ok(None);
    };
    let name = reports::display_name(&path);
    let baseline = tauri::async_runtime::spawn_blocking(move || reports::load(&path))
        .await
        .map_err(|e| e.to_string())??;
    let mut current = state.current.lock().unwrap();
    let current = current.as_mut().ok_or("Open or run a scan first.")?;
    let report = reports::compare(&current.report, &baseline)?;
    let scanned = baseline.started_at;
    current.baseline = Some(baseline);
    Ok(Some(Compared {
        name,
        scanned,
        report,
    }))
}

/// Stop comparing with an earlier report.
#[tauri::command]
fn clear_comparison(state: State<'_, AppState>) {
    if let Some(current) = state.current.lock().unwrap().as_mut() {
        current.baseline = None;
    }
}

/// Save the report on screen as JSON, SARIF or text, through the save dialog. With
/// `only_new`, findings the compared report already had are left out, as on screen.
/// Returns the saved file's name, or `None` if the dialog is cancelled.
#[tauri::command]
async fn export_report(
    window: WebviewWindow,
    state: State<'_, AppState>,
    format: ghaudit::report::Format,
    only_new: bool,
) -> Result<Option<String>, String> {
    let report = {
        let current = state.current.lock().unwrap();
        let current = current.as_ref().ok_or("There is no report to export.")?;
        let mut report = current.report.clone();
        if let (true, Some(baseline)) = (only_new, &current.baseline) {
            report.apply_baseline(baseline);
        }
        report
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let (label, ext) = match format {
        ghaudit::report::Format::Json => ("ghaudit report (JSON)", "json"),
        ghaudit::report::Format::Sarif => ("SARIF log", "sarif"),
        ghaudit::report::Format::Text => ("Text", "txt"),
    };
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Export the report")
        .set_file_name(reports::export_name(&report, format))
        .add_filter(label, &[ext])
        .save_file(move |file| {
            let _ = tx.send(file);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|f| f.into_path().ok()) else {
        return Ok(None);
    };
    let name = reports::display_name(&path);
    tauri::async_runtime::spawn_blocking(move || reports::export(&report, format, &path))
        .await
        .map_err(|e| e.to_string())??;
    Ok(Some(name))
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

// ---------------------------------------------------------------- what this computer has

#[derive(Serialize)]
struct GithubAccess {
    /// Where the token comes from; `None` without one.
    source: Option<token::Source>,
    /// Whose it is; `None` if GitHub doesn't accept it.
    login: Option<String>,
}

#[derive(Serialize)]
struct Keychain {
    available: bool,
    /// A token is saved there (used only when there is no other source).
    saved: bool,
}

#[derive(Serialize)]
struct Environment {
    github: GithubAccess,
    keychain: Keychain,
    /// The GitHub CLI is installed.
    github_cli: bool,
    osv_scanner: Option<tools::Program>,
    git: Option<tools::Program>,
}

async fn probe(path: Option<PathBuf>) -> Option<tools::Program> {
    tools::probe(path?).await
}

/// GitHub access, osv-scanner and git: what scans can use, without the token itself.
#[tauri::command]
async fn environment() -> Environment {
    let token = token::resolve().await;
    let login = match &token {
        Some(t) => token::login(t.secret()).await,
        None => None,
    };
    let (osv_scanner, git) = tokio::join!(
        probe(tools::find_osv_scanner()),
        probe(tools::find_program("git"))
    );
    Environment {
        github: GithubAccess {
            source: token.as_ref().map(|t| t.source),
            login,
        },
        keychain: Keychain {
            available: keychain::available(),
            saved: keychain::get().ok().flatten().is_some(),
        },
        github_cli: tools::find_gh().is_some(),
        osv_scanner,
        git,
    }
}

/// Check a token with GitHub and keep it in the system keychain. Returns its login.
#[tauri::command]
async fn save_token(token: String) -> Result<String, String> {
    let token = token.trim().to_string();
    if !token::plausible(&token) {
        return Err("That doesn't look like a GitHub token. Copy the whole token: it starts with ghp_ or github_pat_.".into());
    }
    if !keychain::available() {
        return Err("This computer has no system keychain to keep a token in. Sign in with the GitHub CLI (gh auth login) or set GITHUB_TOKEN instead.".into());
    }
    let login = token::login(&token).await.ok_or(
        "GitHub didn't accept this token. Check that it's complete and hasn't expired or been revoked.",
    )?;
    keychain::set(&token)?;
    Ok(login)
}

/// Remove the saved token from the system keychain.
#[tauri::command]
fn forget_token() -> Result<(), String> {
    keychain::delete()
}

// ---------------------------------------------------------------- scanning

/// Ask for a folder to scan. Returns its path for display, or `None` if cancelled.
#[tauri::command]
async fn pick_folder(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose a folder to scan")
        .pick_folder(move |folder| {
            let _ = tx.send(folder);
        });
    let Some(path) = rx.await.ok().flatten().and_then(|f| f.into_path().ok()) else {
        return Ok(None);
    };
    let shown = path.display().to_string();
    *state.folder.lock().unwrap() = Some(path);
    Ok(Some(shown))
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum ScanResult {
    Finished { report: Box<ScanReport> },
    Cancelled,
}

/// Clears the running scan when the command ends, however it ends.
struct Running<'a>(&'a Mutex<Option<Arc<Notify>>>);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

/// Run a scan, sending progress events to `on_progress`. Resolves with the report, or
/// as cancelled when `cancel_scan` is called.
#[tauri::command]
async fn start_scan(
    state: State<'_, AppState>,
    options: ScanOptions,
    on_progress: Channel<Progress>,
) -> Result<ScanResult, String> {
    let stop = Arc::new(Notify::new());
    {
        let mut running = state.scan.lock().unwrap();
        if running.is_some() {
            return Err("A scan is already running.".into());
        }
        *running = Some(Arc::clone(&stop));
    }
    let _running = Running(&state.scan);
    let work = async {
        let token = token::resolve().await;
        let login = match (&options.target, &token) {
            (TargetSpec::Mine, Some(t)) => token::login(t.secret()).await,
            _ => None,
        };
        let osv_scanner = if options.sca {
            tools::find_osv_scanner()
        } else {
            None
        };
        let folder = state.folder.lock().unwrap().clone();
        let (config, target) = scan::prepare(
            &options,
            &Context {
                token: token.as_ref().map(Token::secret),
                login: login.as_deref(),
                osv_scanner: osv_scanner.as_deref(),
                folder: folder.as_deref(),
            },
        )?;
        let sink: ProgressSink = Arc::new(move |event| {
            let _ = on_progress.send(event);
        });
        scan::run(config, target, sink).await
    };
    // Dropping `work` stops the scan: clones are deleted and child processes killed.
    let report = tokio::select! {
        result = work => result?,
        () = stop.notified() => return Ok(ScanResult::Cancelled),
    };
    state.show(&report);
    Ok(ScanResult::Finished {
        report: Box::new(report),
    })
}

/// Stop the running scan, if any.
#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) {
    if let Some(stop) = state.scan.lock().unwrap().as_ref() {
        stop.notify_one();
    }
}

/// Closing the window during a scan stops the scan first, so its temporary clones are
/// removed rather than left behind.
fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    let WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    let Some(stop) = window.state::<AppState>().scan.lock().unwrap().clone() else {
        return;
    };
    api.prevent_close();
    stop.notify_one();
    let window = window.clone();
    tauri::async_runtime::spawn(async move {
        for _ in 0..100 {
            if window.state::<AppState>().scan.lock().unwrap().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = window.destroy();
    });
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
        .manage(AppState::default())
        .on_window_event(on_window_event)
        .invoke_handler(tauri::generate_handler![
            catalog,
            open_report,
            open_link,
            environment,
            save_token,
            forget_token,
            pick_folder,
            start_scan,
            cancel_scan,
            compare_with,
            clear_comparison,
            export_report
        ])
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
