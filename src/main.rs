//! ghaudit command-line interface.

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ghaudit::analyzer::{rules, workflows};
use ghaudit::config::{Config, FailOn, SUPPORTED_LANGUAGES};
use ghaudit::model::{ScanReport, Severity};
use ghaudit::report::{self, Format};
use ghaudit::scanner::Scanner;
use ghaudit::target::{self, Target};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

/// Exit status when findings meet the --fail-on threshold.
const EXIT_FINDINGS: u8 = 1;
/// Exit status for usage or runtime errors (clap also uses 2 for bad arguments).
const EXIT_ERROR: u8 = 2;
/// Exit status when the scan finished but part of it failed (e.g. osv-scanner missing).
const EXIT_INCOMPLETE: u8 = 3;
const EXIT_INTERRUPTED: u8 = 130;

#[derive(Parser)]
#[command(
    name = "ghaudit",
    version,
    about = "Security scanner for GitHub repositories: risky code patterns, leaked secrets and vulnerable dependencies.",
    after_help = "Exit status: 0 clean, 1 findings at or above --fail-on, 2 error, 3 scan incomplete.\nDocumentation: https://github.com/Divhanthelion/ghaudit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global: GlobalArgs,
}

#[derive(Args)]
struct GlobalArgs {
    /// Report format
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,

    /// Write the report to this file instead of stdout
    #[arg(short = 'o', long, value_name = "FILE", global = true)]
    output: Option<PathBuf>,

    /// TOML configuration file (see ghaudit.example.toml)
    #[arg(short = 'c', long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// GitHub token, for private repositories, org/user/search scans and higher rate limits
    #[arg(long, env = "GITHUB_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,

    /// When to color text output
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    color: ColorChoice,

    /// More log output on stderr (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Only log errors
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a local directory or one GitHub repository
    #[command(after_help = "TARGET may be a directory (., ../app), owner/repo, or a GitHub URL.")]
    Scan {
        target: String,
        #[command(flatten)]
        scan: ScanArgs,
    },
    /// Scan the repositories of a GitHub organization
    Org {
        name: String,
        #[command(flatten)]
        scan: ScanArgs,
        #[command(flatten)]
        multi: MultiArgs,
    },
    /// Scan the repositories owned by a GitHub user
    User {
        name: String,
        #[command(flatten)]
        scan: ScanArgs,
        #[command(flatten)]
        multi: MultiArgs,
    },
    /// Scan repositories matching a GitHub search query (requires a token)
    #[command(
        after_help = "Example: ghaudit search 'topic:cli language:rust stars:>100' --max-repos 20"
    )]
    Search {
        query: String,
        #[command(flatten)]
        scan: ScanArgs,
        #[command(flatten)]
        multi: MultiArgs,
    },
    /// List the built-in code rules
    Rules,
    /// Show the GitHub API rate limit for the current token
    RateLimit,
}

#[derive(Args, Default)]
struct ScanArgs {
    /// Skip code pattern analysis
    #[arg(long)]
    no_sast: bool,

    /// Skip secret detection
    #[arg(long)]
    no_secrets: bool,

    /// Skip dependency vulnerability scanning (osv-scanner)
    #[arg(long)]
    no_sca: bool,

    /// Skip GitHub Actions workflow checks
    #[arg(long)]
    no_workflows: bool,

    /// Also ask a local LLM to review source files (OpenAI-compatible endpoint, e.g. LM Studio)
    #[arg(long)]
    ai: bool,

    /// Languages for code analysis (comma-separated)
    #[arg(long, value_delimiter = ',', value_name = "LANG,...")]
    languages: Option<Vec<String>>,

    /// Skip paths matching this gitignore-style pattern (repeatable)
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Skip files larger than this many bytes
    #[arg(long, value_name = "BYTES")]
    max_file_size: Option<u64>,

    /// Leave findings below this severity out of the report [info, low, medium, high, critical]
    #[arg(long, value_name = "SEVERITY")]
    min_severity: Option<Severity>,

    /// Exit with status 1 if a finding is at or above this severity [default: high; or never]
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,
}

#[derive(Args, Default)]
struct MultiArgs {
    /// Maximum number of repositories to scan
    #[arg(long, value_name = "N")]
    max_repos: Option<usize>,

    /// Include forked repositories
    #[arg(long)]
    include_forks: bool,

    /// Include archived repositories
    #[arg(long)]
    include_archived: bool,

    /// Repositories to clone and scan at the same time
    #[arg(long, value_name = "N")]
    concurrency: Option<usize>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.global.verbose, cli.global.quiet);

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start async runtime: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let outcome = runtime.block_on(async {
        tokio::select! {
            result = run(cli) => Some(result),
            _ = tokio::signal::ctrl_c() => None,
        }
    });
    // Dropping the scan future above removed temporary clones and killed child
    // processes; don't wait for in-flight file analysis threads.
    runtime.shutdown_background();

    match outcome {
        None => {
            eprintln!("interrupted");
            ExitCode::from(EXIT_INTERRUPTED)
        }
        Some(Ok(code)) => ExitCode::from(code),
        Some(Err(e)) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<u8> {
    let g = &cli.global;
    let mut config = match &g.config {
        Some(path) => Config::from_file(path)?,
        None => Config::default(),
    };
    config.apply_env();
    if let Some(token) = g.token.clone().filter(|t| !t.is_empty()) {
        config.github.token = Some(token);
    }

    let (target, scan_args, multi) = match cli.command {
        Command::Rules => {
            print_rules(g.format)?;
            return Ok(0);
        }
        Command::RateLimit => {
            let scanner = Scanner::new(config)?;
            let rl = scanner.github().rate_limit().await?;
            let reset = chrono::DateTime::from_timestamp(rl.reset as i64, 0)
                .map(|t| t.format("%H:%M:%S UTC").to_string())
                .unwrap_or_default();
            let auth = if scanner.github().has_token() {
                "authenticated"
            } else {
                "unauthenticated"
            };
            println!(
                "{} of {} requests remaining ({auth}); resets at {reset}",
                rl.remaining, rl.limit
            );
            return Ok(0);
        }
        Command::Scan { target, scan } => (
            target::parse_scan_target(&target)?,
            scan,
            MultiArgs::default(),
        ),
        Command::Org { name, scan, multi } => (Target::Org(owner(&name)?), scan, multi),
        Command::User { name, scan, multi } => (Target::User(owner(&name)?), scan, multi),
        Command::Search { query, scan, multi } => (Target::Search(query), scan, multi),
    };
    apply_scan_args(&mut config, scan_args, multi)?;
    let fail_on = config.report.fail_on;

    // Fail on an unwritable output path now, not after a long scan.
    let output = g.output.as_deref().map(prepare_output).transpose()?;

    let scanner = Scanner::new(config)?;
    let report = scanner.scan(&target).await?;

    match output {
        Some((file, path)) => {
            let text = report::render(&report, g.format, false);
            write_output(file, &path, &text)?;
            tracing::info!("report written to {}", path.display());
        }
        None => write_stdout(&report, g.format, g.color)?,
    }

    Ok(exit_code(&report, fail_on))
}

fn exit_code(report: &ScanReport, fail_on: FailOn) -> u8 {
    if let FailOn(Some(threshold)) = fail_on
        && report.count_at_least(threshold) > 0
    {
        return EXIT_FINDINGS;
    }
    if report.is_complete() {
        0
    } else {
        EXIT_INCOMPLETE
    }
}

fn owner(name: &str) -> anyhow::Result<String> {
    if !target::valid_owner(name) {
        bail!("'{name}' is not a valid GitHub user or organization name");
    }
    Ok(name.to_string())
}

fn apply_scan_args(config: &mut Config, scan: ScanArgs, multi: MultiArgs) -> anyhow::Result<()> {
    let a = &mut config.analysis;
    a.sast &= !scan.no_sast;
    a.secrets &= !scan.no_secrets;
    a.sca &= !scan.no_sca;
    a.workflows &= !scan.no_workflows;
    a.ai |= scan.ai;
    if let Some(langs) = scan.languages {
        a.languages = langs
            .into_iter()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|l| !l.is_empty())
            .collect();
    }
    a.exclude.extend(scan.exclude);
    if let Some(size) = scan.max_file_size {
        a.max_file_size = size;
    }
    if let Some(sev) = scan.min_severity {
        config.report.min_severity = sev;
    }
    if let Some(f) = scan.fail_on {
        config.report.fail_on = f;
    }
    let gh = &mut config.github;
    if let Some(n) = multi.max_repos {
        gh.max_repos = n;
    }
    gh.include_forks |= multi.include_forks;
    gh.include_archived |= multi.include_archived;
    if let Some(n) = multi.concurrency {
        gh.concurrency = n;
    }
    if !(config.analysis.sast
        || config.analysis.secrets
        || config.analysis.sca
        || config.analysis.workflows
        || config.analysis.ai)
    {
        bail!("every analyzer is disabled; nothing to do");
    }
    config.validate().context("invalid options")?;
    Ok(())
}

/// Create a temporary file next to the destination; it is renamed into place once the
/// report is complete, so a failed scan never leaves a truncated report behind.
fn prepare_output(path: &Path) -> anyhow::Result<(tempfile::NamedTempFile, PathBuf)> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if path.is_dir() {
        bail!("output path {} is a directory", path.display());
    }
    let file = tempfile::NamedTempFile::new_in(&parent)
        .with_context(|| format!("cannot write to directory {}", parent.display()))?;
    Ok((file, path.to_path_buf()))
}

fn write_output(mut file: tempfile::NamedTempFile, path: &Path, text: &str) -> anyhow::Result<()> {
    file.write_all(text.as_bytes())?;
    file.persist(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

fn write_stdout(report: &ScanReport, format: Format, color: ColorChoice) -> anyhow::Result<()> {
    let text = report::render(report, format, format == Format::Text);
    let choice = match color {
        ColorChoice::Auto => anstream::ColorChoice::Auto,
        ColorChoice::Always => anstream::ColorChoice::Always,
        ColorChoice::Never => anstream::ColorChoice::Never,
    };
    // anstream strips the escape codes when stdout is not a terminal, NO_COLOR is
    // set, or --color never was given, and enables them on Windows consoles.
    let mut out = anstream::AutoStream::new(std::io::stdout().lock(), choice);
    match out.write_all(text.as_bytes()).and_then(|_| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()), // e.g. `| head`
        other => Ok(other?),
    }
}

fn print_rules(format: Format) -> anyhow::Result<()> {
    let code: Vec<&rules::Rule> = rules::all().collect();
    if format != Format::Text {
        let mut json: Vec<serde_json::Value> = code
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id, "kind": "code", "name": r.name, "severity": r.severity, "confidence": r.confidence,
                    "cwe": r.cwe, "description": r.message, "remediation": r.remediation,
                })
            })
            .collect();
        json.extend(workflows::RULES.iter().map(|r| {
            serde_json::json!({ "id": r.id, "kind": "workflow", "name": r.name, "severity": r.severity })
        }));
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }
    println!("{:<34} {:<9} NAME", "RULE", "SEVERITY");
    for r in &code {
        println!("{:<34} {:<9} {}", r.id, r.severity.as_str(), r.name);
    }
    for r in workflows::RULES {
        println!("{:<34} {:<9} {}", r.id, r.severity.as_str(), r.name);
    }
    println!(
        "\n{} code rules for {}, {} GitHub Actions workflow checks. Secret, dependency and hidden-Unicode checks are described in the README.",
        code.len(),
        SUPPORTED_LANGUAGES.join(", "),
        workflows::RULES.len()
    );
    Ok(())
}

fn init_logging(verbose: u8, quiet: bool) {
    let level = match (quiet, verbose) {
        (true, _) => "error",
        (false, 0) => "warn",
        (false, 1) => "info",
        (false, 2) => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_env("GHAUDIT_LOG")
        .unwrap_or_else(|_| EnvFilter::new(format!("ghaudit={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();
}
