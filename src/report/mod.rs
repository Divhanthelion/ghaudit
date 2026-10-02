//! Report writers.

mod sarif;
mod text;

use crate::model::ScanReport;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub use sarif::to_sarif;
pub use text::TextOptions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Human-readable, for terminals.
    Text,
    /// The full report as JSON (stable field names; see docs/ARCHITECTURE.md).
    Json,
    /// SARIF 2.1.0, for GitHub code scanning and other SARIF viewers.
    Sarif,
}

/// Render a report. `color` only affects the text format.
pub fn render(report: &ScanReport, format: Format, color: bool) -> String {
    match format {
        Format::Text => text::render(report, &TextOptions { color }),
        Format::Json => serde_json::to_string_pretty(report).expect("report serializes") + "\n",
        Format::Sarif => {
            serde_json::to_string_pretty(&to_sarif(report)).expect("SARIF serializes") + "\n"
        }
    }
}

/// Make untrusted text (paths, code, messages, error output) safe to print on a
/// terminal. Control characters could move the cursor, rewrite earlier output or set
/// the window title; invisible and direction-changing characters could disguise what
/// is shown. Both are replaced with a visible `<U+XXXX>`.
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    fn unsafe_char(c: char) -> bool {
        (c.is_control() && c != '\t')
            || matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{061C}'
                    | '\u{FEFF}'
                    | '\u{E0000}'..='\u{E007F}'
            )
    }
    if !s.chars().any(unsafe_char) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| {
                if unsafe_char(c) {
                    format!("<U+{:04X}>", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_escapes_are_neutralized() {
        assert_eq!(terminal_safe("plain\ttext"), "plain\ttext");
        assert_eq!(
            terminal_safe("a\x1b]0;pwned\x07b\u{202E}c"),
            "a<U+001B>]0;pwned<U+0007>b<U+202E>c"
        );
        assert_eq!(terminal_safe("x\ry\u{9b}2J"), "x<U+000D>y<U+009B>2J");
    }
}
