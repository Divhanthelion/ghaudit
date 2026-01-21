//! sec_auditor - GitHub Security Analysis CLI
//!
//! A high-performance security analysis tool for GitHub repositories.

use clap::{Parser, Subcommand, ValueEnum};
use sec_auditor::{
    config::{Config, OutputFormat},
    reporter::create_reporter,
    Scanner, Severity,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let log_level = match cli.verbose {
        0 if cli.quiet => Level::ERROR,
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level.to_string())),
        )
        .init();

    // Set up graceful shutdown handling
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    // Spawn a task to handle shutdown signals
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
            std::process::exit(130); // Standard exit code for SIGINT
        }
    });

    // Load configuration
    let mut config = if let Some(ref config_path) = cli.config {
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

    // Create scanner
    let scanner = Scanner::new(config.clone())?;

    // Check for early shutdown
    if shutdown_flag.load(Ordering::SeqCst) {
        warn!("Shutdown requested before scan started");
        return Ok(());
    }

    // Execute command
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
            // Update config based on flags
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

            // Filter findings by minimum severity
            result.findings.retain(|f| f.severity >= min_sev);
            result
        }

        Commands::Org { name, max_repos } => {
            let mut org_config = config.clone();
            org_config.github.max_repos = max_repos;
            let scanner = Scanner::new(org_config)?;
            scanner.scan_repository(&format!("org:{}", name)).await?
        }

        Commands::User { name, max_repos } => {
            let mut user_config = config.clone();
            user_config.github.max_repos = max_repos;
            let scanner = Scanner::new(user_config)?;
            scanner.scan_repository(&format!("user:{}", name)).await?
        }

        Commands::Search { query, max_repos } => {
            let mut search_config = config.clone();
            search_config.github.max_repos = max_repos;
            let scanner = Scanner::new(search_config)?;
            scanner.scan_repository(&query).await?
        }

        Commands::Verify { path } => {
            let findings = scanner.verify_provenance(&path).await?;
            let mut result = sec_auditor::ScanResult::new(path.display().to_string());
            for finding in findings {
                result.add_finding(finding);
            }
            result
        }

        Commands::RateLimit => {
            if config.github.token.is_none() {
                error!("GitHub token required for rate limit check");
                std::process::exit(1);
            }

            let github = sec_auditor::crawler::GitHubClient::new(config.github)?;
            let status = github.check_rate_limit().await?;

            println!("GitHub API Rate Limit Status:");
            println!("  Limit: {}", status.limit);
            println!("  Remaining: {}", status.remaining);
            println!("  Reset in: {}s", status.seconds_until_reset());

            if status.is_limited() {
                println!("\nWarning: You are currently rate limited!");
            }

            return Ok(());
        }
    };

    // Generate and output report
    let reporter = create_reporter(config.output.format);
    let report = reporter.generate(&result);

    if let Some(ref output_path) = config.output.output_path {
        std::fs::write(output_path, &report)?;
        info!("Report written to: {}", output_path.display());
    } else {
        println!("{}", report);
    }

    // Exit with non-zero code if critical/high findings
    let critical = result
        .findings
        .iter()
        .filter(|f| matches!(f.severity, sec_auditor::Severity::Critical | sec_auditor::Severity::High))
        .count();

    if critical > 0 {
        std::process::exit(1);
    }

    Ok(())
}
