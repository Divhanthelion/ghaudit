//! ghaudit: a security scanner for GitHub repositories.
//!
//! The library is organized as a pipeline:
//!
//! - [`target`]: what to scan (a directory, `owner/repo`, an org, a search query)
//! - [`github`] and [`git`]: list repositories and shallow-clone them
//! - [`discovery`]: choose the files to analyze
//! - [`analyzer`]: the analyzers (code rules, secrets, dependencies via osv-scanner, optional LLM)
//! - [`scanner`]: runs the analyzers and assembles a [`model::ScanReport`], reporting
//!   [`progress`] events along the way if asked
//! - [`report`]: renders the report as text, JSON or SARIF
//!
//! The `ghaudit` binary (src/main.rs) is a thin command-line layer over [`scanner::Scanner`].

pub mod analyzer;
pub mod config;
pub mod discovery;
pub mod error;
pub mod git;
pub mod github;
pub mod model;
pub mod progress;
pub mod report;
pub mod scanner;
pub mod target;

pub use config::Config;
pub use error::{Error, Result};
pub use model::{Finding, ScanReport, Severity};
pub use progress::{Progress, ProgressSink};
pub use scanner::Scanner;

/// This library's version, which reports carry as `version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
