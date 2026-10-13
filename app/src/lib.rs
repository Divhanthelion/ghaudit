//! ghaudit desktop app: serves the web UI in `../ui` and answers its commands.
//!
//! The page is treated as untrusted display code. It renders report content (paths,
//! messages, snippets from scanned repositories) and can only call the commands below:
//! it has no file-system, shell, dialog or opener access of its own. File dialogs and
//! file reads happen here, and links open only to GitHub and OSV (see [`links`]). The
//! GitHub token stays here too (see [`token`]): the page never receives it.

mod keychain;
mod links;
mod picked;
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
use tauri_plugin_dialog::{DialogExt, FilePath};
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
    let Some(file) = pick_report(&window, "Open a ghaudit report").await else {
        return Ok(None);
    };
    let (name, report) = load_report(window.app_handle().clone(), file).await?;
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
    let Some(file) = pick_report(&window, "Compare with an earlier report").await else {
        return Ok(None);
    };
    let (name, baseline) = load_report(window.app_handle().clone(), file).await?;
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
    // Android's save dialog takes MIME types; a bare extension it doesn't know (such as
    // "sarif") maps to none at all.
    let android = cfg!(target_os = "android");
    let (label, ext) = match format {
        ghaudit::report::Format::Json => (
            "ghaudit report (JSON)",
            if android { "application/json" } else { "json" },
        ),
        ghaudit::report::Format::Sarif => (
            "SARIF log",
            if android {
                "application/octet-stream"
            } else {
                "sarif"
            },
        ),
        ghaudit::report::Format::Text => ("Text", if android { "text/plain" } else { "txt" }),
    };
    let suggested = reports::export_name(&report, format);
    let dialog = window.dialog().file();
    #[cfg(desktop)]
    let dialog = dialog.set_parent(&window);
    dialog
        .set_title("Export the report")
        .set_file_name(&suggested)
        .add_filter(label, &[ext])
        .save_file(move |file| {
            let _ = tx.send(file);
        });
    let Some(file) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let app = window.app_handle().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        let name = picked::name(&file);
        #[cfg(target_os = "android")]
        {
            // Android doesn't say what the user named the file; the suggestion is the
            // best guess when the URI doesn't show it.
            let name = if name == picked::UNNAMED {
                suggested
            } else {
                name
            };
            let out = picked::open(&app, file, true)?;
            reports::export_to(&report, format, out, &name)?;
            Ok(name)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (&app, suggested);
            let path = file.into_path().map_err(|e| e.to_string())?;
            reports::export(&report, format, &path)?;
            Ok(name)
        }
    })
    .await
    .map_err(|e| e.to_string())?
    .map(Some)
}

/// The system's open-file dialog, for JSON reports.
async fn pick_report(window: &WebviewWindow, title: &str) -> Option<FilePath> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let dialog = window.dialog().file();
    // Android: no filter. Content providers label .json files inconsistently, and the
    // file is checked when it is read.
    #[cfg(desktop)]
    let dialog = dialog
        .set_parent(window)
        .add_filter("ghaudit report (JSON)", &["json"]);
    dialog.set_title(title).pick_file(move |file| {
        let _ = tx.send(file);
    });
    rx.await.ok().flatten()
}

/// Read a report the user chose, with its name for display.
async fn load_report(app: AppHandle, file: FilePath) -> Result<(String, ScanReport), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let name = picked::name(&file);
        #[cfg(target_os = "android")]
        let report = reports::load_from(
            picked::open(&app, file, false)?,
            &name,
            reports::MAX_REPORT_BYTES,
        )?;
        #[cfg(not(target_os = "android"))]
        let report = {
            let _ = &app;
            reports::load(&file.into_path().map_err(|e| e.to_string())?)?
        };
        Ok((name, report))
    })
    .await
    .map_err(|e| e.to_string())?
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
    /// `windows`, `macos`, `linux` or `android`: for install hints.
    platform: &'static str,
    /// A phone: the page uses its phone layout and token flow.
    mobile: bool,
    capabilities: Capabilities,
}

/// What this device can do, so the page offers only that.
#[derive(Serialize)]
struct Capabilities {
    /// A local folder can be chosen and scanned (desktop only).
    folders: bool,
    /// git history can be searched (needs git, so desktop only).
    history: bool,
    /// Dependency checks can run here at all (osv-scanner runs only on a computer).
    dependencies: bool,
    /// How repositories are fetched: `git` or `archive`.
    download: &'static str,
    /// The token is pasted from the clipboard by the backend (phones).
    paste_token: bool,
}

const CAPABILITIES: Capabilities = Capabilities {
    folders: cfg!(desktop),
    history: cfg!(desktop),
    dependencies: cfg!(desktop),
    download: if cfg!(desktop) { "git" } else { "archive" },
    paste_token: cfg!(mobile),
};

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
        platform: std::env::consts::OS,
        mobile: cfg!(mobile),
        capabilities: CAPABILITIES,
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

/// Open GitHub's page for a new fine-grained token, filled in with the read-only
/// permissions ghaudit needs, in the browser.
#[tauri::command]
fn open_token_page(app: AppHandle) -> Result<(), String> {
    let url = links::check(token::NEW_TOKEN_PAGE)?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|e| format!("Couldn't open the browser: {e}"))
}

/// Take the token from the clipboard, check it with GitHub, keep it in the keystore
/// and clear the clipboard. Returns its login. The token never passes through the page.
#[tauri::command]
async fn paste_token(app: AppHandle) -> Result<String, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let copied = app.clipboard().read_text().unwrap_or_default();
    let token = copied.trim().to_string();
    if !token::plausible(&token) {
        return Err("The clipboard doesn't hold a GitHub token. Copy the token on GitHub, then tap Paste token again.".into());
    }
    if !keychain::available() {
        return Err("This device has no keystore to keep a token in.".into());
    }
    let login = token::login(&token).await.ok_or(
        "GitHub didn't accept this token. Check that it's complete and hasn't expired or been revoked.",
    )?;
    keychain::set(&token)?;
    // A token left on the clipboard could be pasted anywhere later.
    let _ = app.clipboard().clear();
    Ok(login)
}

// ---------------------------------------------------------------- scanning

/// Ask for a folder to scan. Returns its path for display, or `None` if cancelled.
#[tauri::command]
async fn pick_folder(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    #[cfg(mobile)]
    {
        // Android's folder picker gives a document-tree URI, not a folder the scanner
        // can walk.
        let _ = (window, state);
        Err("Folders can't be scanned on this device. Scan a GitHub repository instead.".into())
    }
    #[cfg(desktop)]
    {
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
                phone: cfg!(mobile),
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
    if let WindowEvent::Destroyed = event {
        // Android sends no CloseRequested: the activity is simply destroyed.
        if let Some(stop) = window.state::<AppState>().scan.lock().unwrap().as_ref() {
            stop.notify_one();
        }
        return;
    }
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    // Rust-only use: opening the content:// files Android's dialogs return. The page
    // has no fs permission (capabilities/default.json), so it can't call the plugin.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_fs::init());
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // Before Android 13 there is no per-app temporary folder (temp_dir() gives
            // /data/local/tmp, which apps can't write): use the app's cache instead.
            #[cfg(target_os = "android")]
            if let Ok(dir) = app.path().app_cache_dir() {
                let _ = std::fs::create_dir_all(&dir);
                let _ = tempfile::env::override_temp_dir(&dir);
                // Android may kill the app mid-scan, before its downloads are deleted;
                // nothing is scanning yet, so every leftover can go.
                ghaudit::git::remove_stale_work_dirs(&dir, Duration::ZERO);
            }
            // A phone has a few fast cores and a few slow ones, and the page must stay
            // responsive while files are analyzed: four analysis threads, not one per core.
            #[cfg(mobile)]
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .build_global();
            let _ = app;
            Ok(())
        })
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
            export_report,
            open_token_page,
            paste_token
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
