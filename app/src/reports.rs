//! Reading ghaudit JSON reports the user picked: to browse them, or as a baseline.

use ghaudit::ScanReport;
use std::path::Path;

/// Larger files are refused rather than read into memory. A scan of 100 repositories
/// with a few thousand findings is a few megabytes.
pub const MAX_REPORT_BYTES: u64 = 200 * 1024 * 1024;

/// Read and check a report. Errors are sentences for the page to show.
pub fn load(path: &Path) -> Result<ScanReport, String> {
    load_limited(path, MAX_REPORT_BYTES)
}

fn load_limited(path: &Path, max_bytes: u64) -> Result<ScanReport, String> {
    let name = display_name(path);
    let size = std::fs::metadata(path)
        .map_err(|e| format!("Couldn't open {name}: {e}"))?
        .len();
    if size > max_bytes {
        return Err(format!(
            "{name} is {} MB, more than a ghaudit report should be ({} MB at most).",
            size / (1024 * 1024),
            max_bytes / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Couldn't read {name}: {e}"))?;
    let not_a_report = || {
        format!(
            "{name} isn't a ghaudit report. Open a report saved by this app, or one made with \
             ghaudit's -f json option."
        )
    };
    let text = decode(&bytes).ok_or_else(not_a_report)?;
    let report: ScanReport = serde_json::from_str(&text).map_err(|_| not_a_report())?;
    if report.tool != "ghaudit" {
        return Err(not_a_report());
    }
    Ok(report)
}

/// UTF-8, with or without a byte-order mark, or UTF-16 with one: Windows PowerShell 5's
/// `>` writes UTF-16, so `ghaudit ... -f json > report.json` gives UTF-16 there.
fn decode(bytes: &[u8]) -> Option<String> {
    let utf16 = |rest: &[u8], from: fn([u8; 2]) -> u16| {
        let (units, tail) = rest.as_chunks::<2>();
        if !tail.is_empty() {
            return None;
        }
        String::from_utf16(&units.iter().map(|u| from(*u)).collect::<Vec<_>>()).ok()
    };
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8(bytes.to_vec()).ok(),
    }
}

/// The file's name, for messages; the page never sees full paths it did not need.
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_json() -> String {
        let report = ScanReport::new("user:acme");
        ghaudit::report::render(&report, ghaudit::report::Format::Json, false)
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn reads_reports_in_any_encoding_windows_writes() {
        let dir = tempfile::tempdir().unwrap();
        let json = report_json();
        let utf16 = |bom: [u8; 2], to: fn(u16) -> [u8; 2]| {
            let mut bytes = bom.to_vec();
            bytes.extend(json.encode_utf16().flat_map(to));
            bytes
        };
        for (name, bytes) in [
            ("plain.json", json.as_bytes().to_vec()),
            (
                "bom.json",
                [&[0xEF, 0xBB, 0xBF][..], json.as_bytes()].concat(),
            ),
            ("le.json", utf16([0xFF, 0xFE], u16::to_le_bytes)),
            ("be.json", utf16([0xFE, 0xFF], u16::to_be_bytes)),
        ] {
            let report = load(&write(dir.path(), name, &bytes)).unwrap();
            assert_eq!(report.target, "user:acme", "{name}");
        }
    }

    #[test]
    fn other_files_are_refused_with_a_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let sarif = r#"{"version":"2.1.0","runs":[]}"#;
        let other_tool = report_json().replace("\"tool\": \"ghaudit\"", "\"tool\": \"other\"");
        assert_ne!(other_tool, report_json());
        for (name, bytes) in [
            ("scan.sarif", sarif.as_bytes()),
            ("notes.json", b"[1, 2, 3]".as_slice()),
            ("other.json", other_tool.as_bytes()),
            ("binary.json", &[0xFF, 0x00, 0xC3][..]),
        ] {
            let err = load(&write(dir.path(), name, bytes)).unwrap_err();
            assert!(
                err.starts_with(&format!("{name} isn't a ghaudit report")),
                "{err}"
            );
        }
        let missing = load(&dir.path().join("gone.json")).unwrap_err();
        assert!(missing.starts_with("Couldn't open gone.json"), "{missing}");
    }

    #[test]
    fn oversized_files_are_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "big.json", &vec![b' '; 3 * 1024 * 1024]);
        let err = load_limited(&path, 2 * 1024 * 1024).unwrap_err();
        assert!(err.contains("big.json is 3 MB"), "{err}");
    }
}
