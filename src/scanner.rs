//! Orchestration: turns a [`Target`] into a [`ScanReport`].
//!
//! For one directory the pipeline is:
//! 1. discover files (gitignore-aware, dependency dirs skipped);
//! 2. in parallel: per-file analysis on a rayon pool (each file is read once and fed
//!    to the SAST engine and the secret detector) and osv-scanner as a subprocess;
//! 3. optionally, LLM review of source files;
//! 4. inline suppressions (`ghaudit:ignore`) are applied and the report is finalized.
//!
//! Remote targets are shallow-cloned into a temporary directory first; org/user/search
//! targets list repositories through the GitHub API and scan several at a time.

use crate::analyzer::ai::AiAnalyzer;
use crate::analyzer::sast::SastEngine;
use crate::analyzer::sca::OsvScanner;
use crate::analyzer::secrets::{SecretDetector, redact_snippets};
use crate::analyzer::{unicode, workflows};
use crate::config::Config;
use crate::discovery::{self, DiscoveryOptions, SourceFile};
use crate::error::{Error, Result};
use crate::git;
use crate::github::{GitHub, RepoInfo};
use crate::model::{AnalyzerState, AnalyzerStatus, Finding, RepositorySummary, ScanReport};
use crate::target::Target;
use futures::StreamExt;
use rayon::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub const ANALYZERS: [&str; 5] = ["sast", "secrets", "sca", "workflows", "ai"];

/// Per-file analyzers, shared with blocking worker threads.
struct LocalEngines {
    sast: Option<SastEngine>,
    secrets: Option<SecretDetector>,
    workflows: bool,
}

pub struct Scanner {
    config: Config,
    local: Arc<LocalEngines>,
    sca: Option<OsvScanner>,
    ai: Option<AiAnalyzer>,
    github: GitHub,
}

/// A cloned repository's HEAD commit and scan results.
type RemoteScan = Result<(Option<String>, DirScan)>;

/// Results of scanning one directory.
#[derive(Debug, Default)]
struct DirScan {
    findings: Vec<Finding>,
    analyzers: Vec<AnalyzerStatus>,
    files: usize,
    lines: usize,
    packages: usize,
}

impl Scanner {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let a = &config.analysis;
        let sast = if a.sast {
            Some(SastEngine::new(&a.languages).map_err(Error::Config)?)
        } else {
            None
        };
        let secrets = a.secrets.then(SecretDetector::new);
        let sca = a.sca.then(|| {
            OsvScanner::new(
                config.sca.osv_scanner.clone(),
                config.sca.extra_args.clone(),
                &config.analysis.exclude,
                Duration::from_secs(config.sca.timeout_secs),
            )
        });
        let ai = if a.ai {
            Some(AiAnalyzer::new(&config.ai).map_err(Error::Config)?)
        } else {
            None
        };
        let github = GitHub::new(&config.github.api_url, config.github.token.clone())?;
        Ok(Self {
            local: Arc::new(LocalEngines {
                sast,
                secrets,
                workflows: a.workflows,
            }),
            sca,
            ai,
            github,
            config,
        })
    }

    pub fn github(&self) -> &GitHub {
        &self.github
    }

    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let started = Instant::now();
        let mut report = ScanReport::new(target.label());

        match target {
            Target::Local(path) => {
                report.commit = git::head_commit(path).await;
                let dir = self.scan_dir(path).await?;
                apply(&mut report, dir);
            }
            Target::Repo { owner, name } => {
                let url = self.github.clone_url(owner, name);
                let checkout = git::clone(&url, self.config.github.token.as_deref()).await?;
                report.commit = checkout.commit.clone();
                let dir = self.scan_dir(&checkout.path).await?;
                apply(&mut report, dir);
            }
            Target::Org(org) => {
                let repos = self
                    .github
                    .org_repos(org, self.config.github.max_repos)
                    .await?;
                self.scan_many(&mut report, repos).await;
            }
            Target::User(user) => {
                let repos = self
                    .github
                    .user_repos(user, self.config.github.max_repos)
                    .await?;
                self.scan_many(&mut report, repos).await;
            }
            Target::Search(query) => {
                if !self.github.has_token() {
                    return Err(Error::TokenRequired("search"));
                }
                let repos = self
                    .github
                    .search(query, self.config.github.max_repos)
                    .await?;
                self.scan_many(&mut report, repos).await;
            }
        }

        report.finished_at = chrono::Utc::now();
        report.stats.duration_ms = started.elapsed().as_millis() as u64;
        report.finalize(self.config.report.min_severity);
        Ok(report)
    }

    async fn scan_many(&self, report: &mut ScanReport, repos: Vec<RepoInfo>) {
        let total = repos.len();
        let selected: Vec<RepoInfo> = repos
            .into_iter()
            .filter(|r| self.config.github.include_forks || !r.fork)
            .filter(|r| self.config.github.include_archived || !r.archived)
            .collect();
        info!(
            "scanning {} of {total} repositories (forks/archived filtered by config)",
            selected.len()
        );

        let results: Vec<(RepoInfo, RemoteScan)> = futures::stream::iter(selected)
            .map(|repo| async move {
                let result = self.scan_remote(&repo).await;
                (repo, result)
            })
            .buffered(self.config.github.concurrency)
            .collect()
            .await;

        for (repo, result) in results {
            match result {
                Ok((commit, mut dir)) => {
                    for f in &mut dir.findings {
                        f.repository = Some(repo.full_name.clone());
                    }
                    report.stats.files_scanned += dir.files;
                    report.stats.lines_scanned += dir.lines;
                    report.stats.dependencies_scanned += dir.packages;
                    report.repositories.push(RepositorySummary {
                        name: repo.full_name.clone(),
                        commit,
                        findings: 0, // filled in below, after severity filtering
                        error: None,
                        analyzers: dir.analyzers,
                    });
                    report.findings.extend(dir.findings);
                }
                Err(e) => {
                    warn!("{}: {e}", repo.full_name);
                    report.repositories.push(RepositorySummary {
                        name: repo.full_name,
                        commit: None,
                        findings: 0,
                        error: Some(e.to_string()),
                        analyzers: Vec::new(),
                    });
                }
            }
        }

        report.analyzers = ANALYZERS
            .iter()
            .map(|name| summarize_analyzer(name, &report.repositories, self.enabled(name)))
            .collect();
        let min = self.config.report.min_severity;
        for summary in &mut report.repositories {
            summary.findings = report
                .findings
                .iter()
                .filter(|f| {
                    f.repository.as_deref() == Some(&summary.name) && f.severity.at_least(min)
                })
                .count();
        }
    }

    async fn scan_remote(&self, repo: &RepoInfo) -> RemoteScan {
        let checkout = git::clone(&repo.clone_url, self.config.github.token.as_deref()).await?;
        let dir = self.scan_dir(&checkout.path).await?;
        Ok((checkout.commit.clone(), dir))
    }

    fn enabled(&self, analyzer: &str) -> bool {
        let a = &self.config.analysis;
        match analyzer {
            "sast" => a.sast,
            "secrets" => a.secrets,
            "sca" => a.sca,
            "workflows" => a.workflows,
            "ai" => a.ai,
            _ => false,
        }
    }

    /// Scan one directory with every enabled analyzer.
    async fn scan_dir(&self, root: &Path) -> Result<DirScan> {
        let opts = DiscoveryOptions {
            max_file_size: self.config.analysis.max_file_size,
            exclude: self.config.analysis.exclude.clone(),
        };
        let root_owned = root.to_path_buf();
        let files = tokio::task::spawn_blocking(move || discovery::discover(&root_owned, &opts))
            .await
            .map_err(|e| Error::Config(format!("file discovery crashed: {e}")))??;
        let files = Arc::new(files);

        let local = {
            let engines = Arc::clone(&self.local);
            let files = Arc::clone(&files);
            tokio::task::spawn_blocking(move || analyze_files(&engines, &files))
        };
        let sca = async {
            match &self.sca {
                Some(s) => Some(s.scan(root).await),
                None => None,
            }
        };
        let (local, sca) = tokio::join!(local, sca);
        let local = local.map_err(|e| Error::Config(format!("analysis crashed: {e}")))?;

        let mut dir = DirScan {
            findings: local.findings,
            files: local.files,
            lines: local.lines,
            ..Default::default()
        };
        dir.analyzers
            .push(status("sast", self.local.sast.is_some()));
        dir.analyzers
            .push(status("secrets", self.local.secrets.is_some()));

        dir.analyzers.push(match sca {
            None => AnalyzerStatus::skipped("sca", "disabled"),
            Some(Ok(outcome)) => {
                dir.packages = outcome.packages;
                dir.findings.extend(outcome.findings);
                let detail = (!outcome.warnings.is_empty())
                    .then(|| format!("osv-scanner warnings: {}", outcome.warnings.join("; ")));
                AnalyzerStatus::completed("sca").with_detail(detail)
            }
            Some(Err(e)) => {
                warn!("dependency scan failed: {e}");
                AnalyzerStatus::failed("sca", e)
            }
        });

        dir.analyzers
            .push(status("workflows", self.local.workflows));
        dir.analyzers.push(match &self.ai {
            None => AnalyzerStatus::skipped("ai", "disabled (enable with --ai)"),
            Some(ai) => self.run_ai(ai, &files, &mut dir.findings).await,
        });

        Ok(dir)
    }

    async fn run_ai(
        &self,
        ai: &AiAnalyzer,
        files: &[SourceFile],
        findings: &mut Vec<Finding>,
    ) -> AnalyzerStatus {
        if let Err(e) = ai.check().await {
            return AnalyzerStatus::failed("ai", e);
        }
        let candidates: Vec<&SourceFile> = files
            .iter()
            .filter(|f| f.language.is_some() && f.size <= 100 * 1024)
            .collect();
        let limit = self.config.ai.max_files;
        let mut errors = 0;
        for file in candidates.iter().take(limit) {
            let (Some(lang), Some(source)) = (file.language, discovery::read_text(&file.abs_path))
            else {
                continue;
            };
            info!("AI review: {}", file.rel_path);
            match ai.analyze(&file.rel_path, lang, &source).await {
                Ok(found) => findings.extend(found.into_iter().filter(|f| !suppressed(&source, f))),
                Err(e) => {
                    errors += 1;
                    warn!("AI review of {} failed: {e}", file.rel_path);
                }
            }
        }
        let reviewed = candidates.len().min(limit);
        let mut detail = format!("reviewed {reviewed} of {} source files", candidates.len());
        if candidates.len() > limit {
            detail.push_str(&format!(" (limit ai.max_files = {limit})"));
        }
        if errors > 0 {
            detail.push_str(&format!("; {errors} requests failed"));
        }
        AnalyzerStatus::completed("ai").with_detail(Some(detail))
    }
}

fn status(name: &str, enabled: bool) -> AnalyzerStatus {
    if enabled {
        AnalyzerStatus::completed(name)
    } else {
        AnalyzerStatus::skipped(name, "disabled")
    }
}

fn apply(report: &mut ScanReport, dir: DirScan) {
    report.stats.files_scanned = dir.files;
    report.stats.lines_scanned = dir.lines;
    report.stats.dependencies_scanned = dir.packages;
    report.analyzers = dir.analyzers;
    report.findings = dir.findings;
}

/// Roll per-repository statuses up into one status per analyzer.
fn summarize_analyzer(name: &str, repos: &[RepositorySummary], enabled: bool) -> AnalyzerStatus {
    if !enabled {
        return AnalyzerStatus::skipped(name, "disabled");
    }
    let failed = repos
        .iter()
        .filter(|r| {
            r.analyzers
                .iter()
                .any(|a| a.analyzer == name && a.state == AnalyzerState::Failed)
        })
        .count();
    if failed > 0 {
        AnalyzerStatus::failed(
            name,
            format!("failed in {failed} of {} repositories", repos.len()),
        )
    } else {
        AnalyzerStatus::completed(name)
    }
}

struct LocalResults {
    findings: Vec<Finding>,
    files: usize,
    lines: usize,
}

/// Read each file once and run the per-file analyzers on it, in parallel.
fn analyze_files(engines: &LocalEngines, files: &[SourceFile]) -> LocalResults {
    let per_file: Vec<(Vec<Finding>, usize, usize)> = files
        .par_iter()
        .filter_map(|file| {
            let wants_sast =
                matches!((&engines.sast, file.language), (Some(e), Some(l)) if e.handles(l));
            let wants_secrets =
                engines.secrets.is_some() && SecretDetector::should_scan(&file.rel_path);
            let wants_workflow = engines.workflows && workflows::is_workflow(&file.rel_path);
            // Hidden-Unicode checks ride along with code analysis.
            let wants_unicode =
                engines.sast.is_some() && unicode::applies_to(&file.rel_path, file.language);
            if !(wants_sast || wants_secrets || wants_workflow || wants_unicode) {
                return None;
            }
            let content = discovery::read_text(&file.abs_path)?;
            let mut found = Vec::new();
            if let (true, Some(engine), Some(lang)) = (wants_sast, &engines.sast, file.language) {
                found.extend(engine.analyze(&file.rel_path, lang, &content));
            }
            if wants_unicode {
                found.extend(unicode::detect(&file.rel_path, &content));
            }
            if wants_workflow {
                found.extend(workflows::analyze(&file.rel_path, &content));
            }
            if let (true, Some(detector)) = (wants_secrets, &engines.secrets) {
                let secrets = detector.detect(&file.rel_path, &content);
                found.extend(secrets.findings);
                // Code findings near a credential must not display it in their context lines.
                redact_snippets(&mut found, &secrets.values);
            }
            found.retain(|f| !suppressed(&content, f));
            Some((found, 1, content.lines().count()))
        })
        .collect();

    let mut out = LocalResults {
        findings: Vec::new(),
        files: 0,
        lines: 0,
    };
    for (findings, files, lines) in per_file {
        out.findings.extend(findings);
        out.files += files;
        out.lines += lines;
    }
    out
}

/// Inline suppression: a `ghaudit:ignore` comment on the finding's line or the line
/// above silences it. `ghaudit:ignore[rule/id, other/]` limits it to those rule IDs
/// (an entry ending in `/` matches a whole family, e.g. `secret/`).
pub fn suppressed(content: &str, finding: &Finding) -> bool {
    let line = finding.location.start_line;
    let mut lines = content.lines().skip(line.saturating_sub(2));
    let candidates: Vec<&str> = if line >= 2 {
        lines.by_ref().take(2).collect()
    } else {
        lines.take(1).collect()
    };
    candidates
        .iter()
        .any(|l| marker_applies(l, &finding.rule_id))
}

fn marker_applies(line: &str, rule_id: &str) -> bool {
    const MARKER: &str = "ghaudit:ignore";
    let Some(pos) = line.find(MARKER) else {
        return false;
    };
    let rest = &line[pos + MARKER.len()..];
    let Some(list) = rest.strip_prefix('[') else {
        return true;
    };
    let Some(end) = list.find(']') else {
        return true;
    };
    list[..end]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|entry| {
            if entry.ends_with('/') {
                rule_id.starts_with(entry)
            } else {
                rule_id == entry
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Confidence, Location, Severity};

    fn finding(rule: &str, line: usize) -> Finding {
        Finding::new(
            rule,
            Category::Sast,
            Severity::High,
            Confidence::High,
            "t",
            "m",
            Location::new("a.py", line, 1),
            "x",
        )
    }

    #[test]
    fn suppression_markers() {
        let src = "a = eval(x)  # ghaudit:ignore\n# ghaudit:ignore[python/eval]\nb = eval(y)\nc = eval(z)  # ghaudit:ignore[secret/]\nd = eval(w)\n";
        assert!(suppressed(src, &finding("python/eval", 1)), "same line");
        assert!(
            suppressed(src, &finding("python/eval", 3)),
            "line above, matching rule"
        );
        assert!(
            !suppressed(src, &finding("python/os-command", 3)),
            "line above, other rule"
        );
        assert!(
            !suppressed(src, &finding("python/eval", 4)),
            "family marker for another family"
        );
        assert!(
            suppressed(src, &finding("secret/github-token", 4)),
            "family marker"
        );
        assert!(
            !suppressed(src, &finding("python/eval", 5)),
            "line above names another family"
        );
    }

    #[test]
    fn line_above_only_counts_for_the_next_line() {
        let src = "x = 1  # ghaudit:ignore\ny = eval(a)\nz = eval(b)\n";
        assert!(!suppressed(src, &finding("python/eval", 3)));
    }

    #[test]
    fn rollup_reports_failures() {
        let repo = |state| RepositorySummary {
            name: "o/r".into(),
            commit: None,
            findings: 0,
            error: None,
            analyzers: vec![AnalyzerStatus {
                analyzer: "sca".into(),
                state,
                detail: None,
            }],
        };
        let repos = vec![repo(AnalyzerState::Completed), repo(AnalyzerState::Failed)];
        assert_eq!(
            summarize_analyzer("sca", &repos, true).state,
            AnalyzerState::Failed
        );
        assert_eq!(
            summarize_analyzer("sca", &repos, false).state,
            AnalyzerState::Skipped
        );
        assert_eq!(
            summarize_analyzer("sast", &repos, true).state,
            AnalyzerState::Completed
        );
    }
}
