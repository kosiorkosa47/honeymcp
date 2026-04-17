//! honeymcp CLI. Loads a persona, opens the logger, and runs a transport.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use honeymcp::logger::Logger;
use honeymcp::persona::Persona;
use honeymcp::server::Dispatcher;
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    let persona = Persona::from_path(&cli.persona)?;
    info!(persona = %persona.name, tools = persona.tools.len(), "persona loaded");

    let logger = Logger::open(&cli.db, cli.jsonl.as_deref()).await?;
    let dispatcher: Arc<Dispatcher> = Arc::new(Dispatcher::new(persona, logger));

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
            let mut transport = HttpTransport::new(addr);
            transport.run(dispatcher).await?;
        }
    }
    Ok(())
}
