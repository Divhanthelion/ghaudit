//! Live progress of a scan, for progress displays: the CLI's line per repository on
//! stderr, or the desktop app's progress view.
//!
//! Give a [`Scanner`](crate::Scanner) a sink with
//! [`Scanner::with_progress_sink`](crate::Scanner::with_progress_sink) and it calls the
//! sink as the scan goes. Events come from the scan's tasks, several at a time in
//! multi-repository scans, so a sink must be quick and must not block: print a line or
//! hand the event to a channel.
//!
//! Strings in events (repository names, error messages, analyzer details) can come from
//! GitHub or from the scanned repositories. Treat them as untrusted text: [`line`] makes
//! them safe for a terminal; a web view must insert them as text, never as markup.

use crate::model::AnalyzerStatus;
use crate::report::terminal_safe;
use serde::Serialize;
use std::sync::Arc;

/// Receives [`Progress`] events.
pub type ProgressSink = Arc<dyn Fn(Progress) + Send + Sync>;

/// One step of a scan. Serialized with a `type` tag (`repository_finished`, ...), for
/// front ends that receive events as JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Progress {
    /// A multi-repository scan (organization, user or search) listed its repositories.
    /// `repositories` are the ones it will scan, in report order: forks and archived
    /// repositories are left out unless the configuration asks for them.
    RepositoriesListed {
        /// How many GitHub returned, before leaving out forks and archived ones.
        listed: usize,
        repositories: Vec<String>,
    },
    /// A repository of a multi-repository scan started: its clone begins.
    RepositoryStarted {
        /// Position in [`Progress::RepositoriesListed`]'s `repositories`.
        index: usize,
        total: usize,
        name: String,
    },
    /// A repository of a multi-repository scan finished, or could not be scanned.
    RepositoryFinished {
        /// Position in [`Progress::RepositoriesListed`]'s `repositories`.
        index: usize,
        /// Repositories finished so far, this one included.
        done: usize,
        total: usize,
        name: String,
        /// Findings at or above the minimum severity.
        findings: usize,
        duration_ms: u64,
        /// Why the repository could not be cloned or scanned.
        error: Option<String>,
    },
    /// The files of a directory or cloned repository were listed; analysis begins.
    FilesDiscovered {
        /// `owner/name` of a cloned repository; `None` for a local directory.
        repository: Option<String>,
        files: usize,
    },
    /// One analyzer finished on a directory or repository: completed, skipped (with
    /// the reason) or failed (with the error). Every analyzer reports once per
    /// directory or repository, with the status the report will carry.
    AnalyzerFinished {
        /// `owner/name` of a cloned repository; `None` for a local directory.
        repository: Option<String>,
        status: AnalyzerStatus,
    },
}

/// The CLI's progress line for an event, or `None` for events it does not print: one
/// line per finished repository of a multi-repository scan, such as
/// `[3/12] acme/app: 4 findings (2.1s)`. Untrusted text is made safe for a terminal.
pub fn line(event: &Progress) -> Option<String> {
    let Progress::RepositoryFinished {
        done,
        total,
        name,
        findings,
        duration_ms,
        error,
        ..
    } = event
    else {
        return None;
    };
    let outcome = match error {
        None => format!("{findings} findings"),
        Some(e) => format!("failed: {e}"),
    };
    Some(format!(
        "[{done}/{total}] {}: {} ({:.1}s)",
        terminal_safe(name),
        terminal_safe(&outcome),
        *duration_ms as f64 / 1000.0
    ))
}

/// A sink that prints [`line`]s to stderr.
pub fn stderr() -> ProgressSink {
    Arc::new(|event| {
        if let Some(line) = line(&event) {
            eprintln!("{line}");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finished(error: Option<&str>) -> Progress {
        Progress::RepositoryFinished {
            index: 4,
            done: 2,
            total: 12,
            name: "acme/app".into(),
            findings: 4,
            duration_ms: 2149,
            error: error.map(Into::into),
        }
    }

    #[test]
    fn finished_repositories_get_a_line() {
        assert_eq!(
            line(&finished(None)).unwrap(),
            "[2/12] acme/app: 4 findings (2.1s)"
        );
        assert_eq!(
            line(&finished(Some("git: clone failed"))).unwrap(),
            "[2/12] acme/app: failed: git: clone failed (2.1s)"
        );
    }

    #[test]
    fn lines_are_safe_for_a_terminal() {
        let event = Progress::RepositoryFinished {
            index: 0,
            done: 1,
            total: 1,
            name: "acme/app".into(),
            findings: 0,
            duration_ms: 0,
            error: Some("bad\x1b[2Jname\nnext".into()),
        };
        assert_eq!(
            line(&event).unwrap(),
            "[1/1] acme/app: failed: bad<U+001B>[2Jname<U+000A>next (0.0s)"
        );
    }

    #[test]
    fn other_events_print_nothing() {
        for event in [
            Progress::RepositoriesListed {
                listed: 3,
                repositories: vec!["acme/app".into()],
            },
            Progress::RepositoryStarted {
                index: 0,
                total: 1,
                name: "acme/app".into(),
            },
            Progress::FilesDiscovered {
                repository: None,
                files: 3,
            },
            Progress::AnalyzerFinished {
                repository: None,
                status: AnalyzerStatus::completed("sast"),
            },
        ] {
            assert_eq!(line(&event), None, "{event:?}");
        }
    }

    #[test]
    fn events_serialize_with_a_type_tag() {
        let json = serde_json::to_value(finished(None)).unwrap();
        assert_eq!(json["type"], "repository_finished");
        assert_eq!(json["duration_ms"], 2149);
        assert!(json["error"].is_null());
        let json = serde_json::to_value(Progress::AnalyzerFinished {
            repository: Some("acme/app".into()),
            status: AnalyzerStatus::failed("sca", "osv-scanner not found"),
        })
        .unwrap();
        assert_eq!(json["type"], "analyzer_finished");
        assert_eq!(json["status"]["analyzer"], "sca");
        assert_eq!(json["status"]["state"], "failed");
    }
}
