//! honeymcp CLI. Loads a persona, opens the logger, and runs a transport.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;

use honeymcp::detect::Registry;
use honeymcp::logger::Logger;
use honeymcp::persona::Persona;
use honeymcp::server::Dispatcher;
use honeymcp::stats::LoggerStatsProvider;
use honeymcp::stix::{self, StixSourceEvent};
use honeymcp::transport::http::HttpTransport;
use honeymcp::transport::stdio::StdioTransport;
use honeymcp::transport::Transport;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportKind {
    Stdio,
    Http,
}

#[derive(Debug, Parser)]
#[command(
    name = "honeymcp",
    version,
    about = "An MCP honeypot that collects threat intelligence from attackers."
)]
struct Cli {
    /// Path to a persona YAML file. Required for honeypot mode; ignored when
    /// `--export-stix` is set.
    #[arg(short, long, required_unless_present = "export_stix")]
    persona: Option<PathBuf>,

    /// SQLite database path.
    #[arg(long, default_value = "hive.db")]
    db: PathBuf,

    /// Optional JSONL mirror log.
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Wire transport.
    #[arg(long, value_enum, default_value_t = TransportKind::Stdio)]
    transport: TransportKind,

    /// Bind address for the HTTP transport.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http_addr: String,

    /// Skip threat-detection heuristics. Useful for pure-capture mode where you want
    /// raw events without any post-processing.
    #[arg(long)]
    disable_detectors: bool,

    /// Export the SQLite corpus to a STIX 2.1 Bundle JSON file and exit.
    /// Mutually exclusive with honeypot mode — when set, the binary does
    /// the export and returns without binding to a transport.
    #[arg(long, value_name = "PATH")]
    export_stix: Option<PathBuf>,

    /// Maximum number of recent sessions to include in the STIX export.
    /// Default 1000 covers a small VPS deployment; raise it for full-corpus
    /// dumps. Only honored together with `--export-stix`.
    #[arg(long, default_value_t = 1000)]
    export_stix_max_sessions: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _observability_guard = honeymcp::observability::init()?;

    let cli = Cli::parse();

    if let Some(out_path) = cli.export_stix.as_ref() {
        return run_stix_export(&cli.db, out_path, cli.export_stix_max_sessions).await;
    }

    let persona_path = cli
        .persona
        .as_ref()
        .expect("clap requires --persona unless --export-stix is set");
    let persona = Persona::from_path(persona_path)?;
    info!(persona = %persona.name, tools = persona.tools.len(), "persona loaded");

    let logger = Logger::open(&cli.db, cli.jsonl.as_deref()).await?;
    let registry = if cli.disable_detectors {
        Registry::disabled()
    } else {
        Registry::default_enabled()
    };
    info!(detectors = registry.len(), "detection registry loaded");
    let dispatcher: Arc<Dispatcher> =
        Arc::new(Dispatcher::with_registry(persona, logger, registry));

    match cli.transport {
        TransportKind::Stdio => {
            let session_id = format!("stdio-{}", honeymcp::logger::now_ms());
            let mut transport = StdioTransport::from_std(session_id);
            transport.run(dispatcher).await?;
        }
        TransportKind::Http => {
            let addr: SocketAddr = cli
                .http_addr
                .parse()
                .with_context(|| format!("parsing --http-addr {}", cli.http_addr))?;
            let stats = LoggerStatsProvider::new(
                dispatcher.logger().clone(),
                dispatcher.persona().name.clone(),
                dispatcher.persona().version.clone(),
            )
            .into_arc();
            let mut transport = HttpTransport::new(addr)
                .with_stats(stats)
                .with_logger(dispatcher.logger().clone());
            transport.run(dispatcher).await?;
        }
    }
    Ok(())
}

/// Read events + detections from the SQLite logger and write a STIX 2.1
/// Bundle to disk. Bypasses the dispatcher / persona path entirely so
/// operators can produce a TAXII-ingestable bundle from any honeymcp DB
/// without standing up a transport.
async fn run_stix_export(
    db: &std::path::Path,
    output: &std::path::Path,
    max_sessions: i64,
) -> Result<()> {
    let logger = Logger::open(db, None)
        .await
        .with_context(|| format!("opening sqlite db at {}", db.display()))?;
    // include_operator=false so the export matches the public-corpus story
    // every other surface tells: probes and operator validation curls are
    // honeymcp-internal and don't belong in a TI feed.
    let rows = logger
        .recent_events_with_detections(max_sessions, false)
        .await
        .context("loading events for stix export")?;

    let events: Vec<StixSourceEvent> = rows.into_iter().map(stix::raw_row_to_stix_event).collect();
    let total_detections: usize = events.iter().map(|e| e.detections.len()).sum();
    let bundle = stix::build_bundle(&events);
    stix::write_bundle_to_path(&bundle, output)?;

    info!(
        events = events.len(),
        detections = total_detections,
        path = %output.display(),
        "stix export written"
    );
    Ok(())
}
