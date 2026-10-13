//! Files the user chose in the system's file dialogs. On desktop they are paths. On
//! Android they are content:// URIs that only the system's content resolver can open,
//! so they are opened here, in Rust, through tauri-plugin-fs's Rust API: the page still
//! has no file-system permission.

use tauri_plugin_dialog::FilePath;

/// The name used when a content URI does not show the file name.
pub const UNNAMED: &str = "the chosen file";

/// A name for messages: the file name, or on Android the last part of the URI when it
/// looks like a file name ("primary:Download/report.json" gives "report.json").
pub fn name(file: &FilePath) -> String {
    match file {
        FilePath::Path(p) => crate::reports::display_name(p),
        FilePath::Url(u) => {
            if let Ok(p) = u.to_file_path() {
                return crate::reports::display_name(&p);
            }
            let last = u
                .path_segments()
                .and_then(|mut s| s.next_back())
                .map(percent_decode)
                .unwrap_or_default();
            let tail = last.rsplit(['/', ':']).next().unwrap_or_default();
            if tail.contains('.') && !tail.chars().any(char::is_control) {
                tail.to_string()
            } else {
                UNNAMED.to_string()
            }
        }
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Open a chosen file for reading, or (`write`) for writing from the start.
/// Blocking: call it from `spawn_blocking`, never on the main thread.
#[cfg(target_os = "android")]
pub fn open<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    file: FilePath,
    write: bool,
) -> Result<std::fs::File, String> {
    use tauri_plugin_fs::{FsExt, OpenOptions};
    let name = name(&file);
    let mut options = OpenOptions::new();
    if write {
        // "wt": truncate, so a shorter export never leaves the end of an older file behind
        options.write(true).truncate(true);
    } else {
        options.read(true);
    }
    app.fs()
        .open(file, options)
        .map_err(|e| format!("Couldn't open {name}: {e}"))
}
