//! The programs a scan relies on: git (to clone), osv-scanner (dependency checks) and,
//! for the token, the GitHub CLI. Each is looked up by absolute path, so the current
//! directory is never searched.

use serde::Serialize;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Where winget installs osv-scanner (`winget install --id Google.OSVScanner`). winget
/// adds it to the user's PATH, but a running app keeps the PATH it started with.
#[cfg(windows)]
const WINGET_OSV_SCANNER: &str = r"Microsoft\WinGet\Packages\Google.OSVScanner_Microsoft.Winget.Source_8wekyb3d8bbwe\osv-scanner.exe";

/// A program found on this computer.
#[derive(Debug, Clone, Serialize)]
pub struct Program {
    pub path: PathBuf,
    /// First line of `--version`, e.g. `osv-scanner version: 2.6.0`.
    pub version: Option<String>,
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// `name` in the directories of a PATH-style list.
pub fn find_in(paths: &OsStr, name: &str) -> Option<PathBuf> {
    let file = executable_name(name);
    std::env::split_paths(paths)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(&file))
        .find(|p| p.is_file())
}

/// `name` on this process's PATH.
pub fn find_program(name: &str) -> Option<PathBuf> {
    find_in(&std::env::var_os("PATH")?, name)
}

/// osv-scanner on the PATH, or where winget puts it.
pub fn find_osv_scanner() -> Option<PathBuf> {
    find_program("osv-scanner").or_else(winget_osv_scanner)
}

#[cfg(windows)]
fn winget_osv_scanner() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join(WINGET_OSV_SCANNER);
    path.is_file().then_some(path)
}

#[cfg(not(windows))]
fn winget_osv_scanner() -> Option<PathBuf> {
    None
}

/// The GitHub CLI on the PATH, or in its installers' default folders on Windows.
pub fn find_gh() -> Option<PathBuf> {
    find_program("gh").or_else(|| {
        if !cfg!(windows) {
            return None;
        }
        ["ProgramFiles", "LOCALAPPDATA"]
            .iter()
            .filter_map(std::env::var_os)
            .flat_map(|base| {
                let base = PathBuf::from(base);
                [
                    base.join(r"GitHub CLI\gh.exe"),
                    base.join(r"Programs\GitHub CLI\gh.exe"),
                ]
            })
            .find(|p| p.is_file())
    })
}

/// A command for a helper program: no console window, no input, killed if dropped.
pub fn command(program: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.stdin(Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    cmd
}

/// Run `program args` and return its standard output, or `None` if it fails or takes
/// longer than ten seconds.
pub async fn output(program: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = command(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    let out = tokio::time::timeout(Duration::from_secs(10), cmd.output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// The program with its version, if it runs.
pub async fn probe(path: PathBuf) -> Option<Program> {
    let version = output(&path, &["--version"]).await?;
    let version = version
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string);
    Some(Program { path, version })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_programs_only_in_absolute_path_entries() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(executable_name("osv-scanner"));
        std::fs::write(&exe, b"").unwrap();
        let paths =
            std::env::join_paths([PathBuf::from("relative"), dir.path().to_path_buf()]).unwrap();
        assert_eq!(find_in(&paths, "osv-scanner"), Some(exe));
        assert_eq!(find_in(&paths, "gh"), None);
        // A relative entry such as "." would search the current directory.
        let relative = std::env::join_paths([PathBuf::from(".")]).unwrap();
        assert_eq!(find_in(&relative, "osv-scanner"), None);
    }

    #[tokio::test]
    async fn missing_programs_have_no_version() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe(dir.path().join("nothing-here")).await.is_none());
    }
}
