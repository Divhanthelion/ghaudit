//! Orchestration: turns a [`Target`] into a [`ScanReport`].
//!
//! For one directory the pipeline is:
//! 1. discover files (dependency dirs skipped, oversized files recorded);
//! 2. in parallel: per-file analysis on a rayon pool (each file is read once and fed
//!    to the secret detector, the code rules, the hidden-Unicode check and the
//!    workflow audit) and osv-scanner as a subprocess;
//! 3. optionally, a search of git history for removed credentials (alongside step 2),
//!    and LLM review of source files;
//! 4. per file: findings in tests and docs are downgraded, secret values are masked
//!    everywhere (snippets, messages, fingerprints), inline suppressions are applied
//!    (trusted trees only), and repeats of one rule in one file are capped.
//!
//! Remote targets are shallow-cloned (full history with `--history`) into a temporary
//! directory first; org/user/search
//! targets list repositories through the GitHub API and scan several at a time.
//! A cloned repository is untrusted by default: its ignore files, suppression
//! comments and osv-scanner configuration are not honored (see
//! [`crate::config::TrustRepo`]).

use crate::analyzer::ai::AiAnalyzer;
use crate::analyzer::sast::{FILE_BUDGET, SastEngine};
use crate::analyzer::sca::OsvScanner;
use crate::analyzer::secrets::{self, Masker, SecretDetector};
use crate::analyzer::settings::{self, Audit};
use crate::analyzer::{agents, history, unicode, workflows};
use crate::config::Config;
use crate::discovery::{self, DiscoveryOptions, FileText, PathFilter, SourceFile};
use crate::error::{Error, Result};
use crate::git;
use crate::github::{GitHub, RepoInfo};
use crate::model::{
    AnalyzerState, AnalyzerStatus, Category, Finding, LineIndex, Omitted, RepositorySummary,
    ScanReport, SettingsCheck, Severity, SkippedFile,
};
use crate::report::terminal_safe;
use crate::target::{self, Target};
use futures::StreamExt;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub const ANALYZERS: [&str; 8] = [
    "sast",
    "secrets",
    "history",
    "sca",
    "workflows",
    "agents",
    "settings",
    "ai",
];

/// Findings of one rule kept per file; the rest are counted in the report's `omitted`.
pub const MAX_PER_RULE_AND_FILE: usize = 25;

/// Per-file analyzers, shared with blocking worker threads.
struct LocalEngines {
    sast: Option<SastEngine>,
    secrets: Option<SecretDetector>,
    workflows: bool,
    agents: bool,
    history: bool,
}

pub struct Scanner {
    config: Config,
    local: Arc<LocalEngines>,
    sca: Option<OsvScanner>,
    ai: Option<AiAnalyzer>,
    github: GitHub,
    progress: bool,
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
    suppressed: usize,
    skipped: Vec<SkippedFile>,
    omitted: Vec<Omitted>,
    settings: Vec<SettingsCheck>,
}

impl DirScan {
    /// Add a settings audit's outcome.
    fn add_settings(&mut self, status: AnalyzerStatus, audit: Audit) {
        self.analyzers.push(status);
        self.analyzers.sort_by_key(|a| {
            ANALYZERS
                .iter()
                .position(|n| *n == a.analyzer)
                .unwrap_or(usize::MAX)
        });
        self.findings.extend(audit.findings);
        self.settings.extend(audit.checks);
    }
}

/// Sets the flag when dropped: a scan future that is dropped (Ctrl-C, timeout) tells
/// its blocking analysis threads to stop.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
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
                agents: a.agents,
                history: a.history,
            }),
            sca,
            ai,
            github,
            config,
            progress: false,
        })
    }

    /// Print one line per finished repository to stderr during multi-repo scans.
    pub fn with_progress(mut self, progress: bool) -> Self {
        self.progress = progress;
        self
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
                let trusted = self.config.analysis.trust_repo.resolve(true);
                let repo = self.github_repo_of(path).await;
                let (dir, (status, audit)) = tokio::join!(
                    self.scan_dir(path, trusted),
                    self.audit_settings(
                        repo.as_deref(),
                        "this directory has no origin remote on the configured GitHub host"
                    )
                );
                let mut dir = dir?;
                dir.add_settings(status, audit);
                apply(&mut report, dir);
            }
            Target::Repo { owner, name } => {
                let url = self.github.clone_url(owner, name);
                let (commit, dir) = self.scan_remote(&url, &format!("{owner}/{name}")).await?;
                report.commit = commit;
                apply(&mut report, dir);
            }
            Target::Org(org) => {
                let repos = self
                    .github
                    .org_repos(org, self.config.github.max_repos)
                    .await?;
                let ((), org_audit) =
                    tokio::join!(self.scan_many(&mut report, repos), self.audit_org(org));
                match org_audit {
                    Ok(Some(audit)) => {
                        report.findings.extend(audit.findings);
                        report.settings.extend(audit.checks);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!("organization settings: {}", terminal_safe(&e.to_string()));
                        if let Some(status) = report
                            .analyzers
                            .iter_mut()
                            .find(|a| a.analyzer == "settings")
                        {
                            *status = AnalyzerStatus::failed(
                                "settings",
                                format!("organization {org}: {e}"),
                            );
                        }
                    }
                }
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
        report.stats.files_skipped = report.skipped.len();
        report.stats.findings_omitted = report.omitted.iter().map(|o| o.count).sum();
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
        let count = selected.len();
        let done = &AtomicUsize::new(0);
        let min = self.config.report.min_severity;

        // Unordered, so one slow repository does not hold up the others; the original
        // order is restored afterwards.
        let mut results: Vec<(usize, RepoInfo, RemoteScan)> =
            futures::stream::iter(selected.into_iter().enumerate())
                .map(|(i, repo)| async move {
                    let started = Instant::now();
                    let result = self.scan_remote(&repo.clone_url, &repo.full_name).await;
                    if self.progress {
                        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                        let outcome = match &result {
                            Ok((_, dir)) => format!(
                                "{} findings",
                                dir.findings
                                    .iter()
                                    .filter(|f| f.severity.at_least(min))
                                    .count()
                            ),
                            Err(e) => format!("failed: {e}"),
                        };
                        eprintln!(
                            "[{n}/{count}] {}: {} ({:.1}s)",
                            terminal_safe(&repo.full_name),
                            terminal_safe(&outcome),
                            started.elapsed().as_secs_f64()
                        );
                    }
                    (i, repo, result)
                })
                .buffer_unordered(self.config.github.concurrency)
                .collect()
                .await;
        results.sort_by_key(|(i, _, _)| *i);

        for (_, repo, result) in results {
            match result {
                Ok((commit, mut dir)) => {
                    for f in &mut dir.findings {
                        f.repository = Some(repo.full_name.clone());
                    }
                    for s in &mut dir.skipped {
                        s.repository = Some(repo.full_name.clone());
                    }
                    for o in &mut dir.omitted {
                        o.repository = Some(repo.full_name.clone());
                    }
                    report.stats.files_scanned += dir.files;
                    report.stats.lines_scanned += dir.lines;
                    report.stats.dependencies_scanned += dir.packages;
                    report.stats.findings_suppressed += dir.suppressed;
                    report.repositories.push(RepositorySummary {
                        name: repo.full_name.clone(),
                        commit,
                        findings: 0, // filled in below, after severity filtering
                        error: None,
                        analyzers: dir.analyzers,
                    });
                    report.findings.extend(dir.findings);
                    report.skipped.extend(dir.skipped);
                    report.omitted.extend(dir.omitted);
                    report.settings.extend(dir.settings);
                }
                Err(e) => {
                    warn!(
                        "{}: {}",
                        terminal_safe(&repo.full_name),
                        terminal_safe(&e.to_string())
                    );
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

    /// Clone, scan and audit the settings of one repository (`full_name` is
    /// `owner/name`), within `github.repo_timeout_secs`.
    async fn scan_remote(&self, clone_url: &str, full_name: &str) -> RemoteScan {
        let limit = Duration::from_secs(self.config.github.repo_timeout_secs);
        let trusted = self.config.analysis.trust_repo.resolve(false);
        let work = async {
            let scan = async {
                let checkout = git::clone(
                    clone_url,
                    self.config.github.token.as_deref(),
                    self.config.analysis.history,
                )
                .await?;
                let dir = self.scan_dir(&checkout.path, trusted).await?;
                Ok::<_, Error>((checkout.commit.clone(), dir))
            };
            let (scan, (status, audit)) =
                tokio::join!(scan, self.audit_settings(Some(full_name), ""));
            let (commit, mut dir) = scan?;
            dir.add_settings(status, audit);
            Ok((commit, dir))
        };
        tokio::time::timeout(limit, work).await.unwrap_or_else(|_| {
            Err(Error::Timeout(format!(
                "gave up after {}s (github.repo_timeout_secs)",
                limit.as_secs()
            )))
        })
    }

    fn enabled(&self, analyzer: &str) -> bool {
        let a = &self.config.analysis;
        match analyzer {
            "sast" => a.sast,
            "secrets" => a.secrets,
            "history" => a.history,
            "sca" => a.sca,
            "workflows" => a.workflows,
            "agents" => a.agents,
            "settings" => a.settings,
            "ai" => a.ai,
            _ => false,
        }
    }

    /// `owner/name` of the GitHub repository a local directory was cloned from.
    async fn github_repo_of(&self, path: &Path) -> Option<String> {
        let url = git::origin_url(path).await?;
        let host = crate::github::web_host(&self.config.github.api_url);
        match target::parse_scan_target(&url, &host) {
            Ok(Target::Repo { owner, name }) => Some(format!("{owner}/{name}")),
            _ => None,
        }
    }

    /// Audit one repository's settings. `missing` explains a `None` repository.
    async fn audit_settings(&self, repo: Option<&str>, missing: &str) -> (AnalyzerStatus, Audit) {
        let skipped = |why: &str| (AnalyzerStatus::skipped("settings", why), Audit::default());
        if !self.config.analysis.settings {
            return skipped("disabled");
        }
        let Some((owner, name)) = repo.and_then(|r| r.split_once('/')) else {
            return skipped(missing);
        };
        if !self.github.has_token() {
            return skipped("needs a GitHub token (set GITHUB_TOKEN); admin access shows the most");
        }
        match settings::audit_repo(&self.github, owner, name).await {
            Ok(audit) => (settings_status(&audit), audit),
            Err(e) => {
                warn!(
                    "settings of {owner}/{name}: {}",
                    terminal_safe(&e.to_string())
                );
                (
                    AnalyzerStatus::failed("settings", e.to_string()),
                    Audit::default(),
                )
            }
        }
    }

    /// Audit an organization's own settings; `None` when settings are off or there is
    /// no token.
    async fn audit_org(&self, org: &str) -> Result<Option<Audit>> {
        if !(self.config.analysis.settings && self.github.has_token()) {
            return Ok(None);
        }
        settings::audit_org(&self.github, org).await.map(Some)
    }

    /// Scan one directory with every enabled analyzer. `trusted` decides whether the
    /// tree's own ignore files, suppressions and osv-scanner config are honored.
    async fn scan_dir(&self, root: &Path, trusted: bool) -> Result<DirScan> {
        let cancel = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
        let max_file_size = self.config.analysis.max_file_size;
        let opts = DiscoveryOptions {
            max_file_size,
            exclude: self.config.analysis.exclude.clone(),
            honor_ignore_files: trusted,
        };
        let root_owned = root.to_path_buf();
        let discovered =
            tokio::task::spawn_blocking(move || discovery::discover(&root_owned, &opts))
                .await
                .map_err(|e| Error::Config(format!("file discovery crashed: {e}")))??;
        let files = Arc::new(discovered.files);

        let local = {
            let engines = Arc::clone(&self.local);
            let files = Arc::clone(&files);
            let cancel = Arc::clone(&cancel);
            tokio::task::spawn_blocking(move || analyze_files(&engines, &files, trusted, &cancel))
        };
        let sca = async {
            match &self.sca {
                Some(s) => Some(s.scan(root, trusted).await),
                None => None,
            }
        };
        let history = {
            let engines = Arc::clone(&self.local);
            let cancel = Arc::clone(&cancel);
            let root = root.to_path_buf();
            let exclude = self.config.analysis.exclude.clone();
            async move {
                if !engines.history {
                    return None;
                }
                let task = tokio::task::spawn_blocking(move || {
                    let detector = engines
                        .secrets
                        .as_ref()
                        .ok_or("needs the secrets analyzer")?;
                    let filter = PathFilter::new(&root, &exclude).map_err(|e| e.to_string())?;
                    history::scan_history(
                        &root,
                        detector,
                        &filter,
                        history::Limits::default(),
                        &cancel,
                    )
                });
                Some(task.await.unwrap_or_else(|e| Err(format!("crashed: {e}"))))
            }
        };
        let (local, sca, history) = tokio::join!(local, sca, history);
        let local = local.map_err(|e| Error::Config(format!("analysis crashed: {e}")))?;

        let mut dir = DirScan {
            findings: local.findings,
            files: local.files,
            lines: local.lines,
            suppressed: local.suppressed,
            skipped: local.skipped,
            omitted: local.omitted,
            ..Default::default()
        };
        dir.skipped.extend(
            discovered
                .too_large
                .into_iter()
                .map(|(path, size)| SkippedFile {
                    repository: None,
                    path,
                    reason: format!("{size} bytes, over max_file_size ({max_file_size})"),
                }),
        );
        dir.skipped.sort_by(|a, b| a.path.cmp(&b.path));
        dir.analyzers
            .push(status("sast", self.local.sast.is_some()));
        dir.analyzers
            .push(status("secrets", self.local.secrets.is_some()));
        dir.analyzers.push(match history {
            None => AnalyzerStatus::skipped("history", "disabled (enable with --history)"),
            Some(Ok(mut outcome)) => {
                outcome.drop_current(&local.secret_values);
                dir.findings.append(&mut outcome.findings);
                AnalyzerStatus::completed("history").with_detail(Some(outcome.summary()))
            }
            Some(Err(e)) => {
                warn!("git history search failed: {}", terminal_safe(&e));
                AnalyzerStatus::failed("history", e)
            }
        });

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
                warn!("dependency scan failed: {}", terminal_safe(&e));
                AnalyzerStatus::failed("sca", e)
            }
        });

        dir.analyzers
            .push(status("workflows", self.local.workflows));
        dir.analyzers.push(status("agents", self.local.agents));
        let ai = match &self.ai {
            None => AnalyzerStatus::skipped("ai", "disabled (enable with --ai)"),
            Some(ai) => self.run_ai(ai, &files, trusted, &mut dir).await,
        };
        dir.analyzers.push(ai);

        Ok(dir)
    }

    async fn run_ai(
        &self,
        ai: &AiAnalyzer,
        files: &[SourceFile],
        trusted: bool,
        dir: &mut DirScan,
    ) -> AnalyzerStatus {
        if let Err(e) = ai.check().await {
            return AnalyzerStatus::failed("ai", e);
        }
        let candidates: Vec<&SourceFile> = files
            .iter()
            .filter(|f| f.language.is_some() && f.size <= 100 * 1024)
            .collect();
        let limit = self.config.ai.max_files;
        let detector = SecretDetector::new();
        let mut errors = 0;
        for file in candidates.iter().take(limit) {
            let (Some(lang), Some(source)) = (file.language, discovery::read_text(&file.abs_path))
            else {
                continue;
            };
            info!("AI review: {}", terminal_safe(&file.rel_path));
            // The model gets no credentials, even a local one: its requests and replies
            // may be logged.
            let values = detector.detect(&file.rel_path, &source).values;
            let masked = Masker::new(&values).mask(&source).into_owned();
            match ai.analyze(&file.rel_path, lang, &masked).await {
                Ok(mut found) => {
                    let index = LineIndex::new(&source);
                    let outcome = finish(&mut found, &file.rel_path, &index, &values, trusted);
                    dir.suppressed += outcome.suppressed;
                    dir.omitted.extend(outcome.omitted);
                    dir.findings.extend(found);
                }
                Err(e) => {
                    errors += 1;
                    warn!(
                        "AI review of {} failed: {}",
                        terminal_safe(&file.rel_path),
                        terminal_safe(&e)
                    );
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

/// Completed; the per-check outcomes are in the report's `settings` section.
fn settings_status(_audit: &Audit) -> AnalyzerStatus {
    AnalyzerStatus::completed("settings")
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
    report.stats.findings_suppressed = dir.suppressed;
    report.analyzers = dir.analyzers;
    report.findings = dir.findings;
    report.skipped = dir.skipped;
    report.omitted = dir.omitted;
    report.settings = dir.settings;
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
        return AnalyzerStatus::failed(
            name,
            format!("failed in {failed} of {} repositories", repos.len()),
        );
    }
    // Skipped everywhere (e.g. settings without a token): say so, with the reason.
    let statuses: Vec<&AnalyzerStatus> = repos
        .iter()
        .filter_map(|r| r.analyzers.iter().find(|a| a.analyzer == name))
        .collect();
    if !statuses.is_empty() && statuses.iter().all(|a| a.state == AnalyzerState::Skipped) {
        return AnalyzerStatus::skipped(name, statuses[0].detail.clone().unwrap_or_default());
    }
    AnalyzerStatus::completed(name)
}

#[derive(Default)]
struct LocalResults {
    findings: Vec<Finding>,
    files: usize,
    lines: usize,
    suppressed: usize,
    skipped: Vec<SkippedFile>,
    omitted: Vec<Omitted>,
    /// Credentials found in the current files, so history does not report them again.
    secret_values: HashSet<String>,
}

#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    secret_values: Vec<String>,
    lines: usize,
    suppressed: usize,
    omitted: Vec<Omitted>,
    skipped: Option<SkippedFile>,
}

fn skipped(file: &SourceFile, reason: impl Into<String>) -> Option<SkippedFile> {
    Some(SkippedFile {
        repository: None,
        path: file.rel_path.clone(),
        reason: reason.into(),
    })
}

/// Read each file once and run the per-file analyzers on it, in parallel.
fn analyze_files(
    engines: &LocalEngines,
    files: &[SourceFile],
    trusted: bool,
    cancel: &AtomicBool,
) -> LocalResults {
    let per_file: Vec<FileResult> = files
        .par_iter()
        .filter_map(|file| {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            analyze_file(engines, file, trusted, cancel)
        })
        .collect();

    let mut out = LocalResults::default();
    for r in per_file {
        out.files += 1;
        out.lines += r.lines;
        out.suppressed += r.suppressed;
        out.findings.extend(r.findings);
        out.omitted.extend(r.omitted);
        out.skipped.extend(r.skipped);
        out.secret_values.extend(r.secret_values);
    }
    out
}

fn analyze_file(
    engines: &LocalEngines,
    file: &SourceFile,
    trusted: bool,
    cancel: &AtomicBool,
) -> Option<FileResult> {
    let path = file.rel_path.as_str();
    let wants_sast = matches!((&engines.sast, file.language), (Some(e), Some(l)) if e.handles(l));
    let wants_secrets = engines.secrets.is_some() && SecretDetector::should_scan(path);
    let wants_workflow = engines.workflows && workflows::applies_to(path);
    let wants_agents = engines.agents && agents::applies_to(path);
    // Hidden-Unicode checks ride along with code analysis.
    let wants_unicode = engines.sast.is_some() && unicode::applies_to(path, file.language);
    if !(wants_sast || wants_secrets || wants_workflow || wants_agents || wants_unicode) {
        return None;
    }
    let Some(text) = discovery::read_file(&file.abs_path) else {
        return Some(FileResult {
            skipped: skipped(file, "could not be read"),
            ..Default::default()
        });
    };
    let content = match text {
        FileText::Text(content) => content,
        FileText::Binary(content) => {
            let mut result = FileResult::default();
            if let (true, Some(detector)) = (wants_secrets, &engines.secrets) {
                let scan = detector.detect_binary(path, &content);
                let index = LineIndex::new(&content);
                let mut found = scan.findings;
                let outcome = finish(&mut found, path, &index, &scan.values, trusted);
                result.findings = found;
                result.suppressed = outcome.suppressed;
                result.omitted = outcome.omitted;
                result.secret_values = scan.values;
            }
            return Some(result);
        }
    };

    let index = LineIndex::new(&content);
    let mut result = FileResult {
        lines: index.len(),
        ..Default::default()
    };
    let mut found = Vec::new();
    let mut values = Vec::new();
    if let (true, Some(detector)) = (wants_secrets, &engines.secrets) {
        let scan = detector.detect(path, &content);
        found.extend(scan.findings);
        values = scan.values;
    }
    if let (true, Some(engine), Some(lang)) = (wants_sast, &engines.sast, file.language) {
        if is_minified(&content) {
            result.skipped = skipped(file, "minified or generated code: code rules not run");
        } else {
            let sast = engine.analyze_with(path, lang, &content, cancel);
            found.extend(sast.findings);
            if sast.incomplete {
                result.skipped = skipped(
                    file,
                    format!(
                        "code rules stopped after the {}s per-file time limit",
                        FILE_BUDGET.as_secs()
                    ),
                );
            }
        }
    }
    if wants_unicode {
        found.extend(unicode::detect(path, &content));
    }
    if wants_workflow {
        found.extend(workflows::analyze(path, &content));
    }
    if wants_agents {
        found.extend(agents::analyze(path, &content));
    }
    let outcome = finish(&mut found, path, &index, &values, trusted);
    result.findings = found;
    result.suppressed = outcome.suppressed;
    result.omitted = outcome.omitted;
    result.secret_values = values;
    Some(result)
}

/// Bundled or minified JavaScript and similar: long lines, few of them.
fn is_minified(content: &str) -> bool {
    let lines = content.lines().count().max(1);
    content.len() > 4096 && content.len() / lines > 500
}

struct Outcome {
    suppressed: usize,
    omitted: Vec<Omitted>,
}

/// Per-file post-processing shared by every analyzer's findings.
fn finish(
    found: &mut Vec<Finding>,
    path: &str,
    index: &LineIndex,
    values: &[String],
    trusted: bool,
) -> Outcome {
    // Findings in tests, examples and docs stay visible but stop failing builds.
    // (Secret findings get their own, gentler policy in the detector.) Agent
    // instruction files are Markdown too, but they are instructions, not docs.
    if secrets::is_test_path(path) && !unicode::is_agent_file(path) {
        for f in found.iter_mut().filter(|f| f.category != Category::Secret) {
            f.severity = Severity::Info;
            f.message
                .push_str(" (in test, example or documentation files, so reported as info)");
        }
    }

    // No secret value may appear anywhere in the report, or be guessable from a
    // fingerprint: findings on a line holding one get a fingerprint of the masked line.
    if !values.is_empty() {
        let masker = Masker::new(values);
        masker.redact_findings(found);
        let mut masked_lines: HashMap<usize, Option<String>> = HashMap::new();
        for f in found.iter_mut() {
            let n = f.location.start_line;
            let masked = masked_lines.entry(n).or_insert_with(|| {
                let line = index.line(n).unwrap_or_default();
                match masker.mask(line) {
                    std::borrow::Cow::Owned(m) => Some(m),
                    std::borrow::Cow::Borrowed(_) => None,
                }
            });
            if let Some(masked) = masked {
                f.refingerprint(masked);
            }
        }
    }

    let mut suppressed = 0;
    if trusted {
        let before = found.len();
        found.retain(|f| !is_suppressed(index, f));
        suppressed = before - found.len();
    }

    // A file can trigger one rule thousands of times (generated code, or on purpose
    // to bury real findings); keep the first few per rule and count the rest.
    found.sort_by_key(|f| (f.location.start_line, f.location.start_column));
    let mut per_rule: HashMap<String, usize> = HashMap::new();
    found.retain(|f| {
        let n = per_rule.entry(f.rule_id.clone()).or_insert(0);
        *n += 1;
        *n <= MAX_PER_RULE_AND_FILE
    });
    let mut omitted: Vec<Omitted> = per_rule
        .into_iter()
        .filter(|(_, n)| *n > MAX_PER_RULE_AND_FILE)
        .map(|(rule_id, n)| Omitted {
            repository: None,
            path: path.to_string(),
            rule_id,
            count: n - MAX_PER_RULE_AND_FILE,
        })
        .collect();
    omitted.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    for f in found.iter_mut() {
        if let Some(snippet) = &mut f.snippet {
            snippet.clip(f.location.start_line, f.location.start_column);
        }
    }
    Outcome {
        suppressed,
        omitted,
    }
}

/// Inline suppression: a `ghaudit:ignore` comment on the finding's line or the line
/// above silences it. `ghaudit:ignore[rule/id, other/]` limits it to those rule IDs
/// (an entry ending in `/` matches a whole family, e.g. `secret/`).
pub fn suppressed(content: &str, finding: &Finding) -> bool {
    is_suppressed(&LineIndex::new(content), finding)
}

fn is_suppressed(index: &LineIndex, finding: &Finding) -> bool {
    let line = finding.location.start_line;
    [line.checked_sub(1), Some(line)]
        .into_iter()
        .flatten()
        .filter_map(|n| index.line(n))
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
    use crate::model::{Confidence, Location, Snippet};

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
    fn suppressions_only_apply_to_trusted_trees() {
        let src = "a = eval(x)  # ghaudit:ignore\n";
        let index = LineIndex::new(src);
        let mut found = vec![finding("python/eval", 1)];
        assert_eq!(finish(&mut found, "a.py", &index, &[], true).suppressed, 1);
        assert!(found.is_empty());
        let mut found = vec![finding("python/eval", 1)];
        assert_eq!(finish(&mut found, "a.py", &index, &[], false).suppressed, 0);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn repeated_findings_are_capped_per_rule_and_file() {
        let src = "eval(x)\n".repeat(100);
        let index = LineIndex::new(&src);
        let mut found: Vec<Finding> = (1..=100).map(|l| finding("python/eval", l)).collect();
        found.push(finding("python/pickle", 50));
        let outcome = finish(&mut found, "a.py", &index, &[], false);
        assert_eq!(found.len(), MAX_PER_RULE_AND_FILE + 1);
        assert_eq!(
            found[0].location.start_line, 1,
            "the first occurrences are kept"
        );
        assert_eq!(outcome.omitted.len(), 1);
        assert_eq!(
            (
                outcome.omitted[0].rule_id.as_str(),
                outcome.omitted[0].count
            ),
            ("python/eval", 100 - MAX_PER_RULE_AND_FILE)
        );
    }

    #[test]
    fn secrets_never_leak_through_other_findings() {
        // Assembled at runtime so this file does not itself contain a credential.
        let secret = &["Hunter2", "Hunter2xyz"].concat();
        let src = format!("conn = connect(password=\"{secret}\"); eval(x)\n");
        let index = LineIndex::new(&src);
        let mut f = finding("python/eval", 1).with_snippet(Snippet::from_index(&index, 1, 1, 0));
        f.message = format!("model says {secret}");
        let before = f.fingerprint.clone();
        let mut found = vec![f];
        finish(
            &mut found,
            "a.py",
            &index,
            std::slice::from_ref(secret),
            false,
        );
        let json = serde_json::to_string(&found).unwrap();
        assert!(!json.contains(secret.as_str()), "{json}");
        assert_ne!(found[0].fingerprint, before);
        // The fingerprint is that of the masked line, whatever the secret was.
        let replacement = ["Zx9Qp2", "Lm7Kw4Rt8Vb"].concat();
        let other = src.replace(secret.as_str(), &replacement);
        let other_index = LineIndex::new(&other);
        let mut g = vec![finding("python/eval", 1)];
        finish(&mut g, "a.py", &other_index, &[replacement], false);
        assert_eq!(found[0].fingerprint, g[0].fingerprint);
    }

    #[test]
    fn test_code_is_downgraded_not_dropped() {
        let index = LineIndex::new("eval(x)\n");
        let mut found = vec![finding("python/eval", 1)];
        finish(&mut found, "tests/test_app.py", &index, &[], false);
        assert_eq!(found[0].severity, Severity::Info);
        assert!(found[0].message.contains("reported as info"));
    }

    #[test]
    fn agent_instructions_are_not_downgraded_as_docs() {
        let index = LineIndex::new("x\n");
        let mut found = vec![finding("unicode/invisible-text", 1)];
        finish(&mut found, "CLAUDE.md", &index, &[], false);
        assert_eq!(found[0].severity, Severity::High);
        let mut found = vec![finding("unicode/invisible-text", 1)];
        finish(&mut found, "docs/guide.md", &index, &[], false);
        assert_eq!(found[0].severity, Severity::Info);
    }

    #[test]
    fn minified_detection() {
        assert!(is_minified(&"var a=1;".repeat(1000)));
        assert!(!is_minified(&"var a = 1;\n".repeat(1000)));
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
