//! Turning the page's scan options into a ghaudit configuration and target, the same way
//! the CLI turns its flags into them (src/main.rs), so a scan here finds what
//! `ghaudit scan|user|org|search` with the same options finds.

use ghaudit::config::Config;
use ghaudit::target::{self, Target};
use ghaudit::{ProgressSink, ScanReport, Scanner, Severity};
use serde::Deserialize;
use std::path::Path;

/// What to scan.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetSpec {
    /// Every repository the token's user owns (`ghaudit user <login>`).
    Mine,
    /// The folder last chosen in the folder dialog.
    Folder,
    /// `owner/name` or a GitHub URL (`ghaudit scan owner/name`).
    Repo {
        repo: String,
    },
    User {
        name: String,
    },
    Org {
        name: String,
    },
    Search {
        query: String,
    },
}

/// The options of the scan setup page.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanOptions {
    pub target: TargetSpec,
    pub sast: bool,
    pub secrets: bool,
    pub sca: bool,
    pub workflows: bool,
    pub agents: bool,
    pub settings: bool,
    /// `--history`
    pub history: bool,
    /// `--include-archived`
    pub include_archived: bool,
    /// `--include-forks`
    pub include_forks: bool,
    /// `--min-severity`
    pub min_severity: Severity,
    /// `--max-repos`
    pub max_repos: usize,
}

/// What a scan has to work with, found by the app.
pub struct Context<'a> {
    pub token: Option<&'a str>,
    /// The token's user, for "my repositories".
    pub login: Option<&'a str>,
    pub osv_scanner: Option<&'a Path>,
    pub folder: Option<&'a Path>,
}

pub const NO_OSV_SCANNER: &str = "Dependency checks need osv-scanner, which isn't installed. Install it (on Windows: winget install --id Google.OSVScanner), or scan without dependency checks.";

/// The configuration and target for these options. Errors are sentences for the page.
pub fn prepare(options: &ScanOptions, cx: &Context) -> Result<(Config, Target), String> {
    let mut config = Config::default();
    config.github.token = cx.token.map(str::to_string);
    let a = &mut config.analysis;
    a.sast = options.sast;
    a.secrets = options.secrets;
    a.sca = options.sca;
    a.workflows = options.workflows;
    a.agents = options.agents;
    a.settings = options.settings;
    a.history = options.history;
    a.ai = false;
    if !(a.sast || a.secrets || a.sca || a.workflows || a.agents || a.settings) {
        return Err("Turn on at least one check.".into());
    }
    if a.history && !a.secrets {
        return Err(
            "Searching git history looks for secrets: turn on \u{201c}Secrets\u{201d} too.".into(),
        );
    }
    if a.sca {
        let osv = cx.osv_scanner.ok_or(NO_OSV_SCANNER)?;
        config.sca.osv_scanner = osv.to_string_lossy().into_owned();
    }
    config.report.min_severity = options.min_severity;
    if options.max_repos == 0 {
        return Err("Scan at least one repository.".into());
    }
    config.github.max_repos = options.max_repos;
    config.github.include_archived = options.include_archived;
    config.github.include_forks = options.include_forks;
    config
        .validate()
        .map_err(|e| format!("These options don't work together: {e}"))?;
    let target = target(&options.target, cx)?;
    Ok((config, target))
}

fn owner(name: &str, what: &str) -> Result<String, String> {
    let name = name.trim();
    if target::valid_owner(name) {
        Ok(name.to_string())
    } else {
        Err(format!(
            "\u{201c}{name}\u{201d} isn't a valid GitHub {what} name."
        ))
    }
}

fn target(spec: &TargetSpec, cx: &Context) -> Result<Target, String> {
    match spec {
        TargetSpec::Mine => cx
            .login
            .map(|l| Target::User(l.to_string()))
            .ok_or_else(|| {
                "Scanning your repositories needs GitHub access: sign in with the GitHub CLI \
             (gh auth login), or add a token."
                    .to_string()
            }),
        TargetSpec::Folder => cx
            .folder
            .map(|f| Target::Local(f.to_path_buf()))
            .ok_or_else(|| "Choose a folder to scan.".to_string()),
        TargetSpec::Repo { repo } => {
            let repo = repo.trim();
            let not_a_repo = || {
                format!(
                    "\u{201c}{repo}\u{201d} isn't a GitHub repository: enter owner/name or its github.com address."
                )
            };
            // parse_scan_target also accepts directories; folders come only from the
            // folder dialog.
            if repo.is_empty() || Path::new(repo).exists() {
                return Err(not_a_repo());
            }
            match target::parse_scan_target(repo, "github.com") {
                Ok(t @ Target::Repo { .. }) => Ok(t),
                _ => Err(not_a_repo()),
            }
        }
        TargetSpec::User { name } => Ok(Target::User(owner(name, "user")?)),
        TargetSpec::Org { name } => Ok(Target::Org(owner(name, "organization")?)),
        TargetSpec::Search { query } => {
            let query = query.trim();
            if query.is_empty() || query.len() > 256 {
                return Err("Enter a GitHub search query, such as topic:cli language:rust.".into());
            }
            if cx.token.is_none() {
                return Err("GitHub search needs GitHub access: sign in with the GitHub CLI (gh auth login), or add a token.".into());
            }
            Ok(Target::Search(query.to_string()))
        }
    }
}

/// Run a scan, reporting progress to `sink`. Dropping the future stops it: temporary
/// clones are removed and child processes killed.
pub async fn run(config: Config, target: Target, sink: ProgressSink) -> Result<ScanReport, String> {
    let scanner = Scanner::new(config)
        .map_err(|e| e.to_string())?
        .with_progress_sink(sink);
    scanner.scan(&target).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn options(target: TargetSpec) -> ScanOptions {
        ScanOptions {
            target,
            sast: true,
            secrets: true,
            sca: true,
            workflows: true,
            agents: true,
            settings: true,
            history: false,
            include_archived: false,
            include_forks: false,
            min_severity: Severity::Low,
            max_repos: 100,
        }
    }

    fn context<'a>(osv: &'a Path) -> Context<'a> {
        Context {
            token: Some("token-for-tests-only"),
            login: Some("octocat"),
            osv_scanner: Some(osv),
            folder: None,
        }
    }

    /// The same configuration as `ghaudit user octocat --history --include-archived`.
    #[test]
    fn options_build_the_configuration_the_cli_would() {
        let osv = PathBuf::from("osv-scanner");
        let mut opts = options(TargetSpec::Mine);
        opts.history = true;
        opts.include_archived = true;
        let (config, target) = prepare(&opts, &context(&osv)).unwrap();
        assert_eq!(target, Target::User("octocat".into()));
        let mut cli = Config::default();
        cli.github.token = Some("token-for-tests-only".into());
        cli.analysis.history = true;
        cli.github.include_archived = true;
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::to_value(&cli).unwrap()
        );
        assert_eq!(config.github.token, cli.github.token);
    }

    #[test]
    fn targets_are_checked() {
        let osv = PathBuf::from("osv-scanner");
        let cx = context(&osv);
        let target = |spec| prepare(&options(spec), &cx).map(|(_, t)| t);
        assert_eq!(
            target(TargetSpec::Repo {
                repo: " https://github.com/rust-lang/regex ".into()
            }),
            Ok(Target::Repo {
                owner: "rust-lang".into(),
                name: "regex".into()
            })
        );
        assert_eq!(
            target(TargetSpec::Org {
                name: "acme".into()
            }),
            Ok(Target::Org("acme".into()))
        );
        // Folders come only from the folder dialog, not from a text field.
        let dir = tempfile::tempdir().unwrap();
        let err = target(TargetSpec::Repo {
            repo: dir.path().display().to_string(),
        })
        .unwrap_err();
        assert!(err.contains("isn't a GitHub repository"), "{err}");
        assert!(
            target(TargetSpec::Repo {
                repo: "gitlab.com/a/b".into()
            })
            .is_err()
        );
        assert!(
            target(TargetSpec::User {
                name: "-bad".into()
            })
            .is_err()
        );
        assert_eq!(
            target(TargetSpec::Folder).unwrap_err(),
            "Choose a folder to scan."
        );
        let no_login = Context {
            login: None,
            token: None,
            ..context(&osv)
        };
        assert!(
            prepare(&options(TargetSpec::Mine), &no_login)
                .unwrap_err()
                .contains("needs GitHub access")
        );
        assert!(
            prepare(
                &options(TargetSpec::Search {
                    query: "topic:cli".into()
                }),
                &no_login
            )
            .is_err()
        );
    }

    #[test]
    fn impossible_options_are_explained() {
        let osv = PathBuf::from("osv-scanner");
        let cx = context(&osv);
        let mut none = options(TargetSpec::Mine);
        (
            none.sast,
            none.secrets,
            none.sca,
            none.workflows,
            none.agents,
            none.settings,
        ) = (false, false, false, false, false, false);
        assert_eq!(
            prepare(&none, &cx).unwrap_err(),
            "Turn on at least one check."
        );
        let mut history = options(TargetSpec::Mine);
        history.history = true;
        history.secrets = false;
        assert!(prepare(&history, &cx).unwrap_err().contains("Secrets"));
        let no_osv = Context {
            osv_scanner: None,
            ..context(&osv)
        };
        assert_eq!(
            prepare(&options(TargetSpec::Mine), &no_osv).unwrap_err(),
            NO_OSV_SCANNER
        );
        let mut without_sca = options(TargetSpec::Mine);
        without_sca.sca = false;
        assert!(prepare(&without_sca, &no_osv).is_ok());
    }

    #[test]
    fn options_from_the_page_parse() {
        let json = r#"{"target":{"kind":"repo","repo":"acme/app"},"sast":true,"secrets":true,"sca":false,
            "workflows":true,"agents":true,"settings":true,"history":true,"includeArchived":true,
            "includeForks":false,"minSeverity":"medium","maxRepos":100}"#;
        let opts: ScanOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.min_severity, Severity::Medium);
        assert!(matches!(opts.target, TargetSpec::Repo { .. }));
        assert!(
            serde_json::from_str::<ScanOptions>(
                &json.replace("\"sast\"", "\"unknown\":1,\"sast\"")
            )
            .is_err()
        );
    }
}
