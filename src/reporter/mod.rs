//! Reporting module for outputting scan results.

mod sarif;
mod text;

pub use sarif::*;
pub use text::*;

use crate::config::OutputFormat;
use crate::models::ScanResult;

/// Report generator trait.
pub trait Reporter {
    /// Generate a report from scan results.
    fn generate(&self, result: &ScanResult) -> String;
}

/// Create a reporter based on output format.
pub fn create_reporter(format: OutputFormat) -> Box<dyn Reporter> {
    match format {
        OutputFormat::Sarif => Box::new(SarifReporter::new()),
        OutputFormat::Json => Box::new(JsonReporter::new()),
        OutputFormat::Text => Box::new(TextReporter::new()),
    }
}

/// JSON reporter for simple JSON output.
pub struct JsonReporter;

impl JsonReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JsonReporter {
    fn generate(&self, result: &ScanResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}
