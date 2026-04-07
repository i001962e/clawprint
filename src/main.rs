//! Clawprint CLI - Flight recorder for OpenClaw agent runs
//!
//! Usage:
//!   clawprint record --gateway ws://127.0.0.1:18789 [--out ./clawprints]
//!   clawprint list --out ./clawprints
//!   clawprint view --run <run_id> [--open]
//!   clawprint replay --run <run_id> --offline
//!   clawprint stats --run <run_id>

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;
use std::io::{IsTerminal, Write as _};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

static USE_COLOR: AtomicBool = AtomicBool::new(true);

/// Print macro that strips ANSI codes when color is disabled
macro_rules! cprintln {
    ($($arg:tt)*) => {
        if USE_COLOR.load(Ordering::Relaxed) {
            println!($($arg)*);
        } else {
            let s = format!($($arg)*);
            println!("{}", strip_ansi(&s));
        }
    };
}

macro_rules! cprint {
    ($($arg:tt)*) => {
        if USE_COLOR.load(Ordering::Relaxed) {
            print!($($arg)*);
        } else {
            let s = format!($($arg)*);
            print!("{}", strip_ansi(&s));
        }
    };
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_host(host: &str) -> Result<[u8; 4]> {
    let addr: Ipv4Addr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid host address: {}", host))?;
    Ok(addr.octets())
}

/// Print the large CLAWPRINT ASCII text banner (for startup/main display)
fn print_banner_large() {
    let art = r#"
  ╔═╗╦  ╔═╗╦ ╦╔═╗╦═╗╦╔╗╔╔╦╗
  ║  ║  ╠═╣║║║╠═╝╠╦╝║║║║ ║
  ╚═╝╩═╝╩ ╩╚╩╝╩  ╩╚═╩╝╚╝ ╩
"#;
    for line in art.lines() {
        if !line.is_empty() {
            cprintln!("{}", line.bright_cyan().bold());
        }
    }
    cprintln!(
        "  {} ~ {}\n",
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "Every molt leaves a mark.".bright_white(),
    );
}

/// Print a small per-command header with crab icon
fn print_banner(subtitle: &str) {
    cprintln!(
        "  {} {} {} ~ {}\n",
        "><>".bright_cyan().bold(),
        "clawprint".bright_cyan(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        subtitle.bright_white(),
    );
}

#[cfg(feature = "mcp")]
use rmcp::ServiceExt as _;
#[cfg(feature = "mcp")]
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};

#[cfg(feature = "cryptowerk")]
use clawprint::proof::CryptowerkConfig;
use clawprint::{
    Config,
    daemon::{run_daemon, run_daemon_with_shutdown},
    record::RecordingSession,
    replay::{diff_runs, generate_transcript, replay_run},
    storage::{RunStorage, list_runs_with_stats, resolve_run_id},
    viewer::{start_viewer, start_viewer_with_shutdown},
};

#[derive(Parser)]
#[command(name = "clawprint")]
#[command(about = "Every molt leaves a mark. Trace. Verify. Trust.")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record agent runs from gateway
    Record {
        /// Gateway WebSocket URL
        #[arg(short, long, default_value = "ws://127.0.0.1:18789")]
        gateway: String,
        /// Output directory for recordings
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Run name/ID (auto-generated if not specified)
        #[arg(long)]
        run_name: Option<String>,
        /// Gateway auth token (auto-discovered from ~/.openclaw/openclaw.json if omitted)
        #[arg(short, long)]
        token: Option<String>,
        /// Disable secret redaction
        #[arg(long)]
        no_redact: bool,
        /// Batch size for SQLite commits
        #[arg(long, default_value = "100")]
        batch_size: usize,
        /// Register the finalized run seal with Cryptowerk after local verification
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk: bool,
        /// Cryptowerk API base URL
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_base_url: Option<String>,
        /// Cryptowerk API key
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_api_key: Option<String>,
    },
    /// List recorded runs
    List {
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
    },
    /// View a recorded run (opens HTTP viewer)
    View {
        /// Run ID to view
        #[arg(short, long)]
        run: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Open in browser automatically
        #[arg(long)]
        open: bool,
        /// Host to bind the viewer (use 0.0.0.0 for network access)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port for viewer server
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Bearer token for HTTP auth (recommended when using --host 0.0.0.0)
        #[arg(long)]
        token: Option<String>,
    },
    /// Replay a recorded run
    Replay {
        /// Run ID to replay
        #[arg(short, long)]
        run: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Offline mode (no gateway contact)
        #[arg(long)]
        offline: bool,
        /// Export transcript to file
        #[arg(long)]
        export: Option<PathBuf>,
    },
    /// Compare two runs
    Diff {
        /// First run ID
        #[arg(long)]
        run_a: String,
        /// Second run ID
        #[arg(long)]
        run_b: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
    },
    /// Verify run integrity
    Verify {
        /// Run ID to verify
        #[arg(short, long)]
        run: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
    },
    /// Show run statistics
    Stats {
        /// Run ID to analyze
        #[arg(short, long)]
        run: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
    },
    /// Start MCP server (for Claude Desktop integration)
    #[cfg(feature = "mcp")]
    Mcp {
        /// Directory containing the ledger
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Transport: "stdio" (default, for local Claude Desktop) or "sse" (for network access)
        #[arg(long, default_value = "stdio")]
        transport: String,
        /// Host to bind SSE server (only used with --transport sse)
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// Port for SSE server (only used with --transport sse)
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Bearer token for HTTP auth (recommended for SSE transport)
        #[arg(long)]
        token: Option<String>,
    },
    /// Open a recording in the web viewer (latest run if none specified)
    Open {
        /// Run ID to view (opens the most recent run if omitted)
        #[arg(short, long)]
        run: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Host to bind the viewer (use 0.0.0.0 for network access)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port for viewer server
        #[arg(short, long, default_value = "8080")]
        port: u16,
        /// Bearer token for HTTP auth (recommended when using --host 0.0.0.0)
        #[arg(long)]
        token: Option<String>,
    },
    /// Run multiple services (daemon, viewer, MCP) in a single process
    Serve {
        /// Enable daemon (continuous recording)
        #[arg(long)]
        daemon: bool,
        /// Enable web viewer
        #[arg(long)]
        viewer: bool,
        /// Enable MCP SSE server
        #[cfg(feature = "mcp")]
        #[arg(long)]
        mcp: bool,
        /// Gateway WebSocket URL (for daemon)
        #[arg(short, long, default_value = "ws://127.0.0.1:18789")]
        gateway: String,
        /// Output directory
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Gateway auth token (auto-discovered from ~/.openclaw/openclaw.json if omitted)
        #[arg(short, long)]
        token: Option<String>,
        /// Disable secret redaction (for daemon)
        #[arg(long)]
        no_redact: bool,
        /// Batch size for SQLite commits (for daemon)
        #[arg(long, default_value = "100")]
        batch_size: usize,
        /// Register daemon event hashes with Cryptowerk as they are recorded
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk: bool,
        /// Cryptowerk API base URL
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_base_url: Option<String>,
        /// Cryptowerk API key
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_api_key: Option<String>,
        /// Host to bind the viewer
        #[arg(long, default_value = "127.0.0.1")]
        viewer_host: String,
        /// Port for viewer server
        #[arg(long, default_value = "8080")]
        viewer_port: u16,
        /// Host to bind the MCP SSE server
        #[cfg(feature = "mcp")]
        #[arg(long, default_value = "0.0.0.0")]
        mcp_host: String,
        /// Port for MCP SSE server
        #[cfg(feature = "mcp")]
        #[arg(long, default_value = "3000")]
        mcp_port: u16,
    },
    /// Run as a 24/7 daemon recording to a continuous ledger
    Daemon {
        /// Gateway WebSocket URL
        #[arg(short, long, default_value = "ws://127.0.0.1:18789")]
        gateway: String,
        /// Output directory for the ledger
        #[arg(short, long, default_value = "./clawprints")]
        out: PathBuf,
        /// Gateway auth token (auto-discovered from ~/.openclaw/openclaw.json if omitted)
        #[arg(short, long)]
        token: Option<String>,
        /// Disable secret redaction
        #[arg(long)]
        no_redact: bool,
        /// Batch size for SQLite commits
        #[arg(long, default_value = "100")]
        batch_size: usize,
        /// Register daemon event hashes with Cryptowerk as they are recorded
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk: bool,
        /// Cryptowerk API base URL
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_base_url: Option<String>,
        /// Cryptowerk API key
        #[cfg(feature = "cryptowerk")]
        #[arg(long)]
        cryptowerk_api_key: Option<String>,
    },
}

fn format_duration(secs: i64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, mins, s)
    } else if mins > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", s)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Try to read the gateway auth token from ~/.openclaw/openclaw.json
fn discover_openclaw_token() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let config_path = PathBuf::from(home).join(".openclaw").join("openclaw.json");
    let content = std::fs::read_to_string(&config_path).ok()?;
    let config: serde_json::Value = serde_json::from_str(&content).ok()?;
    config
        .pointer("/gateway/auth/token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(feature = "mcp")]
async fn start_mcp_sse_with_shutdown(
    ledger_path: PathBuf,
    host: [u8; 4],
    port: u16,
    token: Option<String>,
    ct: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let mcp_ct = ct.child_token();
    let service: StreamableHttpService<clawprint::mcp::ClawprintMcp, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(clawprint::mcp::ClawprintMcp::new(ledger_path.clone())),
            Default::default(),
            StreamableHttpServerConfig {
                stateful_mode: true,
                cancellation_token: mcp_ct,
                ..Default::default()
            },
        );

    let app = axum::Router::new().nest_service("/mcp", service);
    let app = if let Some(ref tok) = token {
        app.layer(axum::middleware::from_fn_with_state(
            std::sync::Arc::new(tok.clone()),
            clawprint::viewer::bearer_auth,
        ))
    } else {
        app
    };

    let addr = std::net::SocketAddr::from((host, port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async move {
            ct.cancelled().await;
        })
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Respect NO_COLOR env var and non-TTY output
    if std::env::var("NO_COLOR").is_ok() || !std::io::stdout().is_terminal() {
        USE_COLOR.store(false, Ordering::Relaxed);
    }

    let cli = Cli::parse();

    // Only show info logs for record command; others use warn to keep output clean
    let default_log = match &cli.command {
        Commands::Record { .. } | Commands::Daemon { .. } | Commands::Serve { .. } => {
            "clawprint=info"
        }
        _ => "clawprint=warn",
    };

    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| default_log.to_string()))
        .init();

    match cli.command {
        Commands::Record {
            gateway,
            out,
            run_name,
            token,
            no_redact,
            batch_size,
            #[cfg(feature = "cryptowerk")]
            cryptowerk,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_base_url,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_api_key,
        } => {
            let auth_token = match token {
                Some(t) => {
                    info!("Using token from --token flag");
                    Some(t)
                }
                None => match discover_openclaw_token() {
                    Some(t) => {
                        info!("Auto-discovered token from ~/.openclaw/openclaw.json");
                        Some(t)
                    }
                    None => {
                        warn!(
                            "No auth token found. Pass --token or configure gateway.auth.token in ~/.openclaw/openclaw.json"
                        );
                        None
                    }
                },
            };

            #[cfg(feature = "cryptowerk")]
            let cryptowerk =
                CryptowerkConfig::from_sources(cryptowerk, cryptowerk_base_url, cryptowerk_api_key);

            let config = Config {
                output_dir: out,
                redact_secrets: !no_redact,
                gateway_url: gateway,
                auth_token,
                batch_size,
                flush_interval_ms: 200,
                #[cfg(feature = "cryptowerk")]
                cryptowerk,
                #[cfg(not(feature = "cryptowerk"))]
                cryptowerk: None,
            };

            print_banner("Tracking molt activity");
            info!("Wire: {}", config.gateway_url);
            info!("Ledger: {:?}", config.output_dir);
            info!(
                "Redaction: {}",
                if config.redact_secrets { "on" } else { "off" }
            );
            #[cfg(feature = "cryptowerk")]
            if let Some(cryptowerk) = &config.cryptowerk {
                if cryptowerk.is_configured() {
                    info!("Cryptowerk: enabled");
                } else {
                    warn!(
                        "Cryptowerk requested without an API key; external anchoring will be skipped"
                    );
                }
            }

            let session = RecordingSession::start(config, run_name).await?;
            let run_id = session.run_id().clone();

            info!(
                "Tapped into wire — capturing traces ({})",
                &run_id.0[..8.min(run_id.0.len())]
            );
            info!("Ctrl+C to seal the ledger");

            tokio::signal::ctrl_c().await?;

            info!("\nSealing ledger...");
            let summary = session.stop().await?;

            let id_short = &run_id.0[..8.min(run_id.0.len())];
            let integrity = if summary.valid {
                "SEALED"
            } else {
                "COMPROMISED"
            };

            cprintln!(
                "\n  {} {}\n",
                "Impression captured:".green().bold(),
                id_short.bright_blue()
            );
            cprintln!(
                "    Duration: {} | Traces: {} | Size: {} | Ledger: {}",
                format_duration(summary.duration_secs),
                summary.event_count.to_string().cyan(),
                format_bytes(summary.size_bytes).dimmed(),
                if summary.valid {
                    integrity.green().to_string()
                } else {
                    integrity.red().to_string()
                },
            );
            cprintln!("\n    {}", "Examine the evidence:".dimmed());
            cprintln!(
                "      clawprint stats --run {} --out {:?}",
                id_short,
                summary.out_dir
            );
            cprintln!(
                "      clawprint open  --run {} --out {:?}\n",
                id_short,
                summary.out_dir
            );
        }

        Commands::List { out } => {
            let runs = list_runs_with_stats(&out)?;

            if runs.is_empty() {
                cprintln!("{}", "No recorded runs found.".yellow());
                return Ok(());
            }

            print_banner_large();
            print_banner("Recordings");
            cprintln!(
                "  {:<14} {:<20} {:<14} {:>8}  {:>10}",
                "RUN ID".bold().dimmed(),
                "STARTED".bold().dimmed(),
                "DURATION".bold().dimmed(),
                "TRACES".bold().dimmed(),
                "SIZE".bold().dimmed(),
            );
            cprintln!("  {}", "─".repeat(70).dimmed());

            let mut total_events: u64 = 0;
            let mut total_size: u64 = 0;

            for (run_id, meta, size) in &runs {
                let dur = meta
                    .ended_at
                    .map(|end| {
                        let d = end.signed_duration_since(meta.started_at);
                        format_duration(d.num_seconds())
                    })
                    .unwrap_or_else(|| "recording...".to_string());

                total_events += meta.event_count;
                total_size += size;

                let id_short = &run_id.0[..8.min(run_id.0.len())];
                cprintln!(
                    "  {:<14} {:<20} {:<14} {:>8}  {:>10}",
                    id_short.bright_blue(),
                    meta.started_at
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string()
                        .dimmed(),
                    dur.green(),
                    meta.event_count.to_string().cyan(),
                    format_bytes(*size).dimmed(),
                );
            }

            cprintln!("  {}", "─".repeat(70).dimmed());
            cprintln!(
                "  {} runs  {}  {}\n",
                runs.len().to_string().bold(),
                format!("{} traces", total_events).cyan(),
                format_bytes(total_size).dimmed(),
            );
        }

        Commands::View {
            run,
            out,
            open,
            host,
            port,
            token,
        } => {
            let host_octets = parse_host(&host)?;
            if host == "0.0.0.0" && token.is_none() {
                warn!("Binding to 0.0.0.0 without --token: viewer is open to the network");
            }
            let run_id = resolve_run_id(&run, &out)?;
            let id_short = &run_id.0[..8.min(run_id.0.len())];
            let display_host = if host == "0.0.0.0" { "0.0.0.0" } else { &host };
            print_banner(&format!("Viewer — {}", id_short));
            cprintln!(
                "  {}\n",
                format!("http://{}:{}", display_host, port).underline()
            );
            if token.is_some() {
                cprintln!("  {}\n", "Auth: Bearer token required".green());
            }

            if open {
                let url = format!("http://127.0.0.1:{}/view/{}", port, run_id.0);
                let _ = open::that(&url);
            }

            start_viewer(out, host_octets, port, token).await?;
        }

        Commands::Open {
            run,
            out,
            host,
            port,
            token,
        } => {
            let host_octets = parse_host(&host)?;
            if host == "0.0.0.0" && token.is_none() {
                warn!("Binding to 0.0.0.0 without --token: viewer is open to the network");
            }
            let run_id = match run {
                Some(r) => resolve_run_id(&r, &out)?,
                None => {
                    // Find the latest run by started_at
                    let runs = list_runs_with_stats(&out)?;
                    if runs.is_empty() {
                        cprintln!("{}", "No recorded runs found.".yellow());
                        return Ok(());
                    }
                    let (latest_id, _, _) = runs
                        .into_iter()
                        .max_by_key(|(_, meta, _)| meta.started_at)
                        .unwrap();
                    latest_id
                }
            };

            let id_short = &run_id.0[..8.min(run_id.0.len())];
            let url = format!("http://127.0.0.1:{}/view/{}", port, run_id.0);
            print_banner(&format!("Opening run {}", id_short));
            cprintln!("  {}\n", url.underline());
            if token.is_some() {
                cprintln!("  {}\n", "Auth: Bearer token required".green());
            }

            let _ = open::that(&url);
            start_viewer(out, host_octets, port, token).await?;
        }

        Commands::Replay {
            run,
            out,
            offline,
            export,
        } => {
            let run_id = resolve_run_id(&run, &out)?;
            info!("Replaying run: {}", run_id.0);

            let result = replay_run(&run_id, &out, offline)?;
            let transcript = generate_transcript(&result);

            if let Some(export_path) = export {
                std::fs::write(&export_path, &transcript)?;
                cprintln!(
                    "  {} Transcript exported to {:?}",
                    "OK".green().bold(),
                    export_path,
                );
            } else {
                cprintln!("{}", transcript);
            }
        }

        Commands::Diff { run_a, run_b, out } => {
            let run_a = resolve_run_id(&run_a, &out)?;
            let run_b = resolve_run_id(&run_b, &out)?;

            info!("Comparing runs: {} vs {}", run_a.0, run_b.0);

            let diff = diff_runs(&run_a, &run_b, &out)?;
            cprintln!("{}", diff);
        }

        Commands::Verify { run, out } => {
            let run_id = resolve_run_id(&run, &out)?;
            let storage = RunStorage::open(run_id.clone(), &out)?;

            let id_short = &run_id.0[..8.min(run_id.0.len())];
            print_banner(&format!("Verify — {}", id_short));
            cprint!("  Inspecting chain of evidence... ");
            std::io::stdout().flush()?;

            match storage.verify_chain() {
                Ok(true) => {
                    cprintln!("{}", "INTACT".green().bold());
                    cprintln!("  Traces:    {}", storage.event_count().to_string().cyan());
                    cprintln!(
                        "  Root hash: {}",
                        storage.root_hash().unwrap_or_default().dimmed()
                    );
                    cprintln!(
                        "  {}",
                        "No tampering detected. The trail is clean.".dimmed()
                    );
                }
                Ok(false) => {
                    cprintln!("{}", "COMPROMISED".red().bold());
                    eprintln!("  Chain broken — evidence may have been altered");
                    std::process::exit(1);
                }
                Err(e) => {
                    cprintln!("{}: {}", "ERROR".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        #[cfg(feature = "mcp")]
        Commands::Mcp {
            out,
            transport,
            host,
            port,
            token,
        } => {
            match transport.as_str() {
                "stdio" => {
                    // MCP server: stdout is JSON-RPC only, all logging to stderr
                    let service = clawprint::mcp::ClawprintMcp::new(out)
                        .serve(rmcp::transport::stdio())
                        .await
                        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;
                    service
                        .waiting()
                        .await
                        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;
                }
                "sse" => {
                    let host_octets = parse_host(&host)?;
                    if host == "0.0.0.0" && token.is_none() {
                        warn!(
                            "Binding to 0.0.0.0 without --token: MCP server is open to the network"
                        );
                    }
                    print_banner("MCP Server (SSE)");

                    let ct = tokio_util::sync::CancellationToken::new();
                    let ledger_path = out.clone();
                    let service: StreamableHttpService<
                        clawprint::mcp::ClawprintMcp,
                        LocalSessionManager,
                    > = StreamableHttpService::new(
                        move || Ok(clawprint::mcp::ClawprintMcp::new(ledger_path.clone())),
                        Default::default(),
                        StreamableHttpServerConfig {
                            stateful_mode: true,
                            cancellation_token: ct.child_token(),
                            ..Default::default()
                        },
                    );

                    let app = axum::Router::new().nest_service("/mcp", service);
                    let app = if let Some(ref tok) = token {
                        app.layer(axum::middleware::from_fn_with_state(
                            std::sync::Arc::new(tok.clone()),
                            clawprint::viewer::bearer_auth,
                        ))
                    } else {
                        app
                    };

                    let addr = std::net::SocketAddr::from((host_octets, port));

                    cprintln!(
                        "  MCP endpoint: {}\n",
                        format!("http://{}:{}/mcp", host, port).underline()
                    );
                    if token.is_some() {
                        cprintln!("  {}\n", "Auth: Bearer token required".green());
                    }
                    cprintln!("  Claude Desktop config:");
                    cprintln!("  {{");
                    cprintln!("    \"mcpServers\": {{");
                    cprintln!("      \"clawprint\": {{");
                    cprintln!("        \"url\": \"http://{}:{}/mcp\"", host, port);
                    cprintln!("      }}");
                    cprintln!("    }}");
                    cprintln!("  }}\n");
                    cprintln!("  Ledger: {:?}", out);

                    let listener = tokio::net::TcpListener::bind(addr).await?;
                    axum::serve(listener, app.into_make_service())
                        .with_graceful_shutdown(async move {
                            tokio::signal::ctrl_c().await.ok();
                            ct.cancel();
                        })
                        .await?;
                }
                other => bail!("Unknown transport '{}'. Use 'stdio' or 'sse'.", other),
            }
        }

        Commands::Serve {
            daemon,
            viewer,
            #[cfg(feature = "mcp")]
            mcp,
            gateway,
            out,
            token,
            no_redact,
            batch_size,
            #[cfg(feature = "cryptowerk")]
            cryptowerk,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_base_url,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_api_key,
            viewer_host,
            viewer_port,
            #[cfg(feature = "mcp")]
            mcp_host,
            #[cfg(feature = "mcp")]
            mcp_port,
        } => {
            #[cfg(not(feature = "mcp"))]
            let mcp = false;
            #[cfg(not(feature = "mcp"))]
            let mcp_host = "0.0.0.0".to_string();
            #[cfg(not(feature = "mcp"))]
            let mcp_port: u16 = 3000;

            if !daemon && !viewer && !mcp {
                bail!("Enable at least one service: --daemon, --viewer, or --mcp");
            }

            print_banner("Serving");

            let ct = tokio_util::sync::CancellationToken::new();

            // Ctrl+C handler
            {
                let ct = ct.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    ct.cancel();
                });
            }

            let mut handles: Vec<tokio::task::JoinHandle<Result<()>>> = Vec::new();

            if daemon {
                let auth_token = match token.clone() {
                    Some(t) => {
                        info!("Using token from --token flag");
                        Some(t)
                    }
                    None => match discover_openclaw_token() {
                        Some(t) => {
                            info!("Auto-discovered token from ~/.openclaw/openclaw.json");
                            Some(t)
                        }
                        None => {
                            warn!(
                                "No auth token found. Pass --token or configure gateway.auth.token in ~/.openclaw/openclaw.json"
                            );
                            None
                        }
                    },
                };

                #[cfg(feature = "cryptowerk")]
                let cryptowerk =
                    CryptowerkConfig::from_sources(cryptowerk, cryptowerk_base_url, cryptowerk_api_key);

                let config = Config {
                    output_dir: out.clone(),
                    redact_secrets: !no_redact,
                    gateway_url: gateway.clone(),
                    auth_token,
                    batch_size,
                    flush_interval_ms: 200,
                    #[cfg(feature = "cryptowerk")]
                    cryptowerk,
                    #[cfg(not(feature = "cryptowerk"))]
                    cryptowerk: None,
                };

                cprintln!(
                    "  {} Daemon: wire={}",
                    "+".green().bold(),
                    config.gateway_url.dimmed(),
                );

                let ct = ct.clone();
                handles.push(tokio::spawn(async move {
                    run_daemon_with_shutdown(config, ct).await
                }));
            }

            if viewer {
                let vh_octets = parse_host(&viewer_host)?;
                if viewer_host == "0.0.0.0" && token.is_none() {
                    warn!(
                        "Binding viewer to 0.0.0.0 without --token: viewer is open to the network"
                    );
                }

                cprintln!(
                    "  {} Viewer: {}",
                    "+".green().bold(),
                    format!("http://{}:{}", viewer_host, viewer_port).underline(),
                );

                let base_path = out.clone();
                let tok = token.clone();
                let ct = ct.clone();
                handles.push(tokio::spawn(async move {
                    start_viewer_with_shutdown(base_path, vh_octets, viewer_port, tok, ct).await
                }));
            }

            #[cfg(feature = "mcp")]
            if mcp {
                let mh_octets = parse_host(&mcp_host)?;
                if mcp_host == "0.0.0.0" && token.is_none() {
                    warn!(
                        "Binding MCP to 0.0.0.0 without --token: MCP server is open to the network"
                    );
                }

                cprintln!(
                    "  {} MCP SSE: {}",
                    "+".green().bold(),
                    format!("http://{}:{}/mcp", mcp_host, mcp_port).underline(),
                );

                let ledger_path = out.clone();
                let tok = token.clone();
                let ct = ct.clone();
                handles.push(tokio::spawn(async move {
                    start_mcp_sse_with_shutdown(ledger_path, mh_octets, mcp_port, tok, ct).await
                }));
            }

            cprintln!("\n  ~ Ctrl+C to shut down all services\n");

            let results = futures::future::join_all(handles).await;
            for result in results {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("Service error: {}", e),
                    Err(e) => warn!("Task panicked: {}", e),
                }
            }

            info!("All services stopped");
        }

        Commands::Daemon {
            gateway,
            out,
            token,
            no_redact,
            batch_size,
            #[cfg(feature = "cryptowerk")]
            cryptowerk,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_base_url,
            #[cfg(feature = "cryptowerk")]
            cryptowerk_api_key,
        } => {
            let auth_token = match token {
                Some(t) => {
                    info!("Using token from --token flag");
                    Some(t)
                }
                None => match discover_openclaw_token() {
                    Some(t) => {
                        info!("Auto-discovered token from ~/.openclaw/openclaw.json");
                        Some(t)
                    }
                    None => {
                        warn!(
                            "No auth token found. Pass --token or configure gateway.auth.token in ~/.openclaw/openclaw.json"
                        );
                        None
                    }
                },
            };

            #[cfg(feature = "cryptowerk")]
            let cryptowerk =
                CryptowerkConfig::from_sources(cryptowerk, cryptowerk_base_url, cryptowerk_api_key);

            let config = Config {
                output_dir: out,
                redact_secrets: !no_redact,
                gateway_url: gateway,
                auth_token,
                batch_size,
                flush_interval_ms: 200,
                #[cfg(feature = "cryptowerk")]
                cryptowerk,
                #[cfg(not(feature = "cryptowerk"))]
                cryptowerk: None,
            };

            print_banner("Watching the wire");
            info!("Wire: {}", config.gateway_url);
            info!("Ledger: {:?}", config.output_dir);
            info!(
                "Redaction: {}",
                if config.redact_secrets { "on" } else { "off" }
            );
            #[cfg(feature = "cryptowerk")]
            if let Some(cryptowerk) = &config.cryptowerk {
                if cryptowerk.is_configured() {
                    info!("Cryptowerk: enabled");
                } else {
                    warn!(
                        "Cryptowerk requested without an API key; external anchoring will be skipped"
                    );
                }
            }

            run_daemon(config).await?;
        }

        Commands::Stats { run, out } => {
            let run_id = resolve_run_id(&run, &out)?;
            let storage = RunStorage::open(run_id.clone(), &out)?;

            let id_short = &run_id.0[..8.min(run_id.0.len())];
            print_banner(&format!("Stats — {}", id_short));

            // Event breakdown
            let breakdown = storage.event_count_by_kind()?;
            let total: u64 = breakdown.values().sum();

            cprintln!("  {}", "Event Breakdown".bold());
            cprintln!("  {}", "─".repeat(50).dimmed());

            let mut sorted: Vec<_> = breakdown.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            let max_count = sorted.first().map(|(_, c)| **c).unwrap_or(1);

            for (kind, count) in &sorted {
                let pct = (**count as f64 / total as f64) * 100.0;
                let bar_len = ((**count as f64 / max_count as f64) * 25.0) as usize;
                let bar: String = "█".repeat(bar_len);
                cprintln!(
                    "  {:<16} {:>6} ({:>5.1}%) {}",
                    kind.cyan(),
                    count.to_string().bright_white(),
                    pct,
                    bar.green(),
                );
            }
            cprintln!(
                "  {:<16} {:>6}",
                "TOTAL".bold(),
                total.to_string().bright_white().bold()
            );

            // Agent runs
            let agent_runs = storage.agent_run_ids()?;
            cprintln!(
                "\n  {}: {}",
                "Agent Runs".bold(),
                agent_runs.len().to_string().cyan(),
            );

            // Timeline
            let timeline = storage.events_timeline()?;
            if !timeline.is_empty() {
                cprintln!("\n  {}", "Events per Minute".bold());
                cprintln!("  {}", "─".repeat(50).dimmed());

                let max_rate = timeline.iter().map(|(_, c)| *c).max().unwrap_or(1);
                for (minute, count) in &timeline {
                    let bar_len = ((*count as f64 / max_rate as f64) * 30.0) as usize;
                    let bar: String = "▓".repeat(bar_len);
                    cprintln!(
                        "  {} {:>5} {}",
                        minute.dimmed(),
                        count.to_string().bright_white(),
                        bar.bright_blue(),
                    );
                }
            }

            // Storage
            let size = storage.storage_size_bytes()?;
            cprintln!(
                "\n  {}: {}\n",
                "Storage Size".bold(),
                format_bytes(size).cyan(),
            );
        }
    }

    Ok(())
}
