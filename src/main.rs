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
    /// Path to a persona YAML file.
    #[arg(short, long)]
    persona: PathBuf,

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let _observability_guard = honeymcp::observability::init()?;

    let cli = Cli::parse();

    let persona = Persona::from_path(&cli.persona)?;
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
