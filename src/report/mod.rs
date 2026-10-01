//! Report writers.

mod sarif;
mod text;

use crate::model::ScanReport;
use serde::{Deserialize, Serialize};

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
