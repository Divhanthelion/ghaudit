//! Generates the app's permissions. Every command the page may call is listed here and
//! granted by name in capabilities/default.json; anything not listed cannot be invoked.

const COMMANDS: &[&str] = &[
    "catalog",
    "open_report",
    "open_link",
    "environment",
    "save_token",
    "forget_token",
    "pick_folder",
    "start_scan",
    "cancel_scan",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri-build failed");
}
