//! sec_auditor - GitHub Security Analysis CLI
//!
//! A high-performance security analysis tool for GitHub repositories.

use clap::{Parser, Subcommand, ValueEnum};
use sec_auditor::{
    config::{Config, OutputFormat},
    reporter::create_reporter,
    ScanResult, Scanner, Severity,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Maximum allowed output path depth to prevent path traversal.
const MAX_OUTPUT_DEPTH: usize = 5;

/// Validate output path for directory traversal attacks.
///
/// Ensures the path:
/// 1. Is within the current working directory or below
/// 2. Does not contain path traversal sequences (..)
/// 3. Is not an absolute path pointing outside allowed areas
fn validate_output_path(path: &Path) -> anyhow::Result<PathBuf> {
    // Convert to absolute path to resolve any relative components
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Canonicalize to resolve symlinks and normalize path
    let canonical = match absolute.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // Path may not exist yet, check parent directory
            if let Some(parent) = absolute.parent() {
                let canonical_parent = parent.canonicalize()?;
                canonical_parent.join(absolute.file_name().unwrap_or_default())
            } else {
                return Err(anyhow::anyhow!(
                    "Invalid output path: cannot canonicalize parent directory"
                ));
            }
        }
    };

    // Check path depth to prevent deeply nested traversal
    let depth = canonical.components().count();
    if depth > MAX_OUTPUT_DEPTH + 3 {
        // +3 accounts for prefix like C:\ on Windows or / on Unix
        return Err(anyhow::anyhow!(
            "Output path exceeds maximum allowed depth ({} components)",
            MAX_OUTPUT_DEPTH
        ));
    }

    // Verify no suspicious patterns remain after canonicalization
    let path_str = canonical.to_string_lossy();
    if path_str.contains("..") || path_str.contains("~") {
        return Err(anyhow::anyhow!(
            "Output path contains invalid characters after normalization"
        ));
    }

    Ok(canonical)
}
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Parse a severity string into a Severity enum.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "none" => Severity::None,
        _ => Severity::Low, // Default to low
    }
}

/// High-performance security analysis for GitHub repositories
#[derive(Parser)]
#[command(name = "sec_auditor")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress all output except errors
    #[arg(short, long)]
    quiet: bool,

    /// Output format
    #[arg(short = 'f', long, default_value = "text")]
    format: OutputFormatArg,

    /// Output file (stdout if not specified)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// GitHub token (or set GITHUB_TOKEN env var)
    #[arg(long)]
    token: Option<String>,

    /// Configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy)]
enum OutputFormatArg {
    Text,
    Json,
    Sarif,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Text => OutputFormat::Text,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a repository or local path
    Scan {
        /// Repository (owner/repo), URL, or local path
        target: String,

        /// Enable SAST analysis
        #[arg(long, default_value = "true")]
        sast: bool,

        /// Enable SCA (dependency) analysis
        #[arg(long, default_value = "true")]
        sca: bool,

        /// Enable secret detection
        #[arg(long, default_value = "true")]
        secrets: bool,

        /// Enable AI-driven analysis
        #[arg(long)]
        ai: bool,

        /// Enable provenance verification
        #[arg(long)]
        provenance: bool,

        /// Languages to analyze (comma-separated)
        #[arg(long, default_value = "rust,python,javascript,go")]
        languages: String,

        /// Maximum file size to analyze (bytes)
        #[arg(long, default_value = "1048576")]
        max_file_size: usize,

        /// Minimum severity to report
        #[arg(long, default_value = "low")]
        min_severity: String,
    },

    /// Scan all repositories in an organization
    Org {
        /// Organization name
        name: String,

        /// Maximum repositories to scan
        #[arg(long, default_value = "100")]
        max_repos: usize,
    },

    /// Scan all repositories for a user
    User {
        /// Username
        name: String,

        /// Maximum repositories to scan
        #[arg(long, default_value = "100")]
        max_repos: usize,
    },

    /// Search and scan repositories
    Search {
        /// Search query (GitHub search syntax)
        query: String,

        /// Maximum repositories to scan
        #[arg(long, default_value = "10")]
        max_repos: usize,
    },

    /// Verify supply chain provenance
    Verify {
        /// Path to Cargo.lock or package-lock.json
        path: PathBuf,
    },

    /// Check rate limit status
    RateLimit,
}

/// Initialize the logging subsystem based on CLI verbosity.
fn setup_logging(verbose: u8, quiet: bool) {
    let log_level = match (verbose, quiet) {
        (_, true) => Level::ERROR,
        (0, false) => Level::WARN,
        (1, false) => Level::INFO,
        (2, false) => Level::DEBUG,
        _ => Level::TRACE,
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level.to_string())),
        )
        .init();
}

/// Setup graceful shutdown signal handling.
fn setup_shutdown_handler() -> Arc<AtomicBool> {
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Failed to listen for shutdown signal: {}", e);
            return;
        }

        warn!("Received interrupt signal, initiating graceful shutdown...");
        shutdown_flag_clone.store(true, Ordering::SeqCst);

        // If we get a second signal, force exit
        if let Ok(()) = tokio::signal::ctrl_c().await {
            error!("Received second interrupt, forcing shutdown");
            std::process::exit(130);
        }
    });

    shutdown_flag
}

/// Load and merge configuration from file and CLI options.
fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    let mut config = if let Some(ref config_path) = &cli.config {
        Config::from_file(config_path)?
    } else {
        Config::default()
    };

    // Override with CLI options
    if let Some(ref token) = cli.token {
        config.github.token = Some(token.clone());
    }
    config.output.format = cli.format.into();
    config.output.output_path = cli.output.clone();

    Ok(config)
}

/// Execute the scan command with the given configuration.
async fn execute_scan(
    config: &Config,
    target: String,
    sast: bool,
    sca: bool,
    secrets: bool,
    ai: bool,
    provenance: bool,
    languages: String,
    max_file_size: usize,
    min_severity: String,
) -> anyhow::Result<ScanResult> {
    let mut scan_config = config.clone();
    scan_config.analysis.enable_sast = sast;
    scan_config.analysis.enable_sca = sca;
    scan_config.analysis.enable_secrets = secrets;
    scan_config.analysis.enable_ai = ai;
    scan_config.analysis.enable_provenance = provenance;
    scan_config.analysis.languages = languages
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .collect();
    scan_config.analysis.max_file_size = max_file_size;
    let min_sev = parse_severity(&min_severity);
    scan_config.analysis.min_severity = min_sev;

    let scanner = Scanner::new(scan_config)?;
    let mut result = scanner.scan_repository(&target).await?;
    result.findings.retain(|f| f.severity >= min_sev);

    Ok(result)
}

/// Execute organization scan.
async fn execute_org_scan(config: &Config, name: String, max_repos: usize) -> anyhow::Result<ScanResult> {
    let mut org_config = config.clone();
    org_config.github.max_repos = max_repos;
    let scanner = Scanner::new(org_config)?;
    Ok(scanner.scan_repository(&format!("org:{}", name)).await?)
}

/// Execute user scan.
async fn execute_user_scan(config: &Config, name: String, max_repos: usize) -> anyhow::Result<ScanResult> {
    let mut user_config = config.clone();
    user_config.github.max_repos = max_repos;
    let scanner = Scanner::new(user_config)?;
    Ok(scanner.scan_repository(&format!("user:{}", name)).await?)
}

/// Execute search scan.
async fn execute_search(config: &Config, query: String, max_repos: usize) -> anyhow::Result<ScanResult> {
    let mut search_config = config.clone();
    search_config.github.max_repos = max_repos;
    let scanner = Scanner::new(search_config)?;
    Ok(scanner.scan_repository(&query).await?)
}

/// Execute provenance verification.
async fn execute_verify(scanner: &Scanner, path: PathBuf) -> anyhow::Result<ScanResult> {
    let findings = scanner.verify_provenance(&path).await?;
    let mut result = sec_auditor::ScanResult::new(path.display().to_string());
    for finding in findings {
        result.add_finding(finding);
    }
    Ok(result)
}

/// Check GitHub rate limit status.
async fn check_rate_limit(config: &Config) -> anyhow::Result<()> {
    if config.github.token.is_none() {
        error!("GitHub token required for rate limit check");
        std::process::exit(1);
    }

    let github = sec_auditor::crawler::GitHubClient::new(config.github.clone())?;
    let status = github.check_rate_limit().await?;

    println!("GitHub API Rate Limit Status:");
    println!("  Limit: {}", status.limit);
    println!("  Remaining: {}", status.remaining);
    println!("  Reset in: {}s", status.seconds_until_reset());

    if status.is_limited() {
        println!("\nWarning: You are currently rate limited!");
    }

    Ok(())
}

/// Exit with appropriate code based on findings.
fn exit_with_findings(result: &ScanResult) -> ! {
    let critical = result
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                sec_auditor::Severity::Critical | sec_auditor::Severity::High
            )
        })
        .count();

    if critical > 0 {
        std::process::exit(1);
    }
    std::process::exit(0);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    setup_logging(cli.verbose, cli.quiet);
    let shutdown_flag = setup_shutdown_handler();
    let config = load_config(&cli)?;

    if shutdown_flag.load(Ordering::SeqCst) {
        warn!("Shutdown requested before scan started");
        return Ok(());
    }

    let scanner = Scanner::new(config.clone())?;

    // Extract output config before consuming config in match
    let output_format = config.output.format.clone();
    let output_path = config.output.output_path.clone();

    let result = match cli.command {
        Commands::Scan {
            target,
            sast,
            sca,
            secrets,
            ai,
            provenance,
            languages,
            max_file_size,
            min_severity,
        } => {
            execute_scan(
                &config,
                target,
                sast,
                sca,
                secrets,
                ai,
                provenance,
                languages,
                max_file_size,
                min_severity,
            )
            .await?
        }
        Commands::Org { name, max_repos } => execute_org_scan(&config, name, max_repos).await?,
        Commands::User { name, max_repos } => execute_user_scan(&config, name, max_repos).await?,
        Commands::Search { query, max_repos } => execute_search(&config, query, max_repos).await?,
        Commands::Verify { path } => execute_verify(&scanner, path).await?,
        Commands::RateLimit => {
            check_rate_limit(&config).await?;
            return Ok(());
        }
    };

    let reporter = create_reporter(output_format);
    let report = reporter.generate(&result);

    // Output report using extracted path
    if let Some(ref path) = output_path {
        let validated_path = validate_output_path(path)?;
        let mut temp_file = tempfile::NamedTempFile::new_in(
            validated_path.parent().unwrap_or_else(|| Path::new("."))
        )?;
        temp_file.write_all(report.as_bytes())?;
        temp_file.persist(&validated_path)?;
        info!("Report written to: {}", validated_path.display());
    } else {
        println!("{}", report);
    }

    exit_with_findings(&result);
}
