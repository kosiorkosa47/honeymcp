//! honeymcp CLI. Loads a persona, opens the logger, and runs a transport.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use honeymcp::logger::Logger;
use honeymcp::persona::Persona;
use honeymcp::server::Dispatcher;
use honeymcp::transport::stdio::StdioTransport;
use honeymcp::transport::Transport;

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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // tracing goes to stderr so it never corrupts the stdio JSON-RPC frames we write to stdout.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    let persona = Persona::from_path(&cli.persona)?;
    info!(persona = %persona.name, tools = persona.tools.len(), "persona loaded");

    let logger = Logger::open(&cli.db, cli.jsonl.as_deref()).await?;
    let dispatcher = Arc::new(Dispatcher::new(persona, logger));

    let session_id = format!("stdio-{}", honeymcp::logger::now_ms());
    let mut transport = StdioTransport::from_std(session_id);
    transport.run(dispatcher).await?;
    Ok(())
}
