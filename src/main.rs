//! honeymcp CLI. Loads a persona, opens the logger, and runs a transport.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use tracing::info;

use honeymcp::canary;
use honeymcp::detect::Registry;
use honeymcp::logger::Logger;
use honeymcp::persona::{Persona, PersonaSet};
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
    /// Persona to serve, as `[key=]path`. Repeatable: pass `--persona` several
    /// times to serve multiple personas from one process, each reachable at
    /// `/<key>/mcp` (the bare `/mcp` serves the default). When `key=` is
    /// omitted the persona's own name is used as the route key. Required for
    /// honeypot mode; ignored when `--export-stix` is set.
    /// Example: `--persona aws=personas/aws-admin.yaml --persona personas/github-admin.yaml`.
    #[arg(short, long, value_name = "[KEY=]PATH")]
    persona: Vec<String>,

    /// Route key of the persona served at the bare `/mcp` endpoint. Defaults to
    /// the first `--persona` given. Must match one of the loaded keys.
    #[arg(long)]
    default_persona: Option<String>,

    /// Path to a canary token map (YAML with a top-level `canary:` table).
    /// Substituted into `{{canary.*}}` placeholders in persona responses.
    /// When omitted, falls back to `$HONEYMCP_CANARIES`, then `./canaries.yaml`
    /// if present, then no canaries (placeholders render as realistic fakes).
    #[arg(long)]
    canaries: Option<PathBuf>,

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

    /// Import a canary-alert JSON export into SQLite and exit. Stores only
    /// safe alert metadata plus a raw-object hash for deduplication.
    #[arg(long, value_name = "PATH")]
    import_canary_hits: Option<PathBuf>,

    /// Backfill canary marker exposures for existing `tools/call` rows and
    /// exit. Requires the same `--persona` set used by the running instance.
    #[arg(long)]
    backfill_canary_exposures: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _observability_guard = honeymcp::observability::init()?;

    let cli = Cli::parse();

    if let Some(out_path) = cli.export_stix.as_ref() {
        return run_stix_export(&cli.db, out_path, cli.export_stix_max_sessions).await;
    }

    if cli.backfill_canary_exposures || cli.import_canary_hits.is_some() {
        let logger = Logger::open(&cli.db, None)
            .await
            .with_context(|| format!("opening sqlite db at {}", cli.db.display()))?;

        if cli.backfill_canary_exposures {
            if cli.persona.is_empty() {
                anyhow::bail!("--backfill-canary-exposures requires at least one --persona");
            }
            let persona_set = build_persona_set(&cli.persona, cli.default_persona.as_deref())?;
            run_canary_exposure_backfill(&logger, &persona_set).await?;
        }

        if let Some(path) = cli.import_canary_hits.as_ref() {
            run_canary_hit_import(&logger, path).await?;
        }

        return Ok(());
    }

    if cli.persona.is_empty() {
        anyhow::bail!("at least one --persona is required unless --export-stix is set");
    }
    let persona_set = build_persona_set(&cli.persona, cli.default_persona.as_deref())?;
    info!(
        personas = persona_set.len(),
        default = persona_set.default_key(),
        "persona set loaded"
    );

    let canaries = honeymcp::persona::load_canaries_default(cli.canaries.as_deref())
        .context("loading canary token map")?;
    if canaries.is_empty() {
        info!("no canary tokens configured; {{canary.*}} placeholders render as realistic fakes");
    } else {
        info!(canaries = canaries.len(), "canary token map loaded");
    }

    let logger = Logger::open(&cli.db, cli.jsonl.as_deref()).await?;
    let registry = if cli.disable_detectors {
        Registry::disabled()
    } else {
        Registry::default_enabled()
    };
    info!(detectors = registry.len(), "detection registry loaded");
    let dispatcher: Arc<Dispatcher> = Arc::new(
        Dispatcher::with_persona_set(persona_set, logger, registry).with_canaries(canaries),
    );

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

async fn run_canary_hit_import(logger: &Logger, path: &std::path::Path) -> Result<()> {
    let hits = canary::load_hits_from_path(path)?;
    let summary = logger.import_canary_hits(&hits).await?;
    println!(
        "canary hits import: total={} inserted={} ignored={}",
        summary.total, summary.inserted, summary.ignored
    );
    Ok(())
}

async fn run_canary_exposure_backfill(logger: &Logger, personas: &PersonaSet) -> Result<()> {
    let rows = logger.canary_backfill_events().await?;
    let mut events_seen = 0usize;
    let mut events_with_markers = 0usize;
    let mut marker_rows = 0usize;

    for row in rows {
        events_seen += 1;
        let params = match row.params.as_deref() {
            Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(v) => v,
                Err(_) => continue,
            },
            None => continue,
        };
        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => continue,
        };
        let persona = row
            .persona
            .as_deref()
            .and_then(|name| personas.by_name(name))
            .unwrap_or_else(|| personas.default_persona());
        let markers = persona
            .canary_markers_for_tool(tool_name)
            .unwrap_or_default();
        if markers.is_empty() {
            continue;
        }
        logger
            .record_canary_exposures(row.event_id, row.timestamp_ms, &markers)
            .await?;
        events_with_markers += 1;
        marker_rows += markers.len();
    }

    println!(
        "canary exposure backfill: scanned={} events_with_markers={} marker_rows={}",
        events_seen, events_with_markers, marker_rows
    );
    Ok(())
}

/// Parse `--persona [key=]path` specs into a routed [`PersonaSet`]. The route
/// key defaults to the persona's own name; the default route key (served at
/// bare `/mcp`) is the explicit `--default-persona` or the first spec.
fn build_persona_set(specs: &[String], default_key: Option<&str>) -> Result<PersonaSet> {
    let mut entries: Vec<(String, Persona)> = Vec::with_capacity(specs.len());
    let mut first_key: Option<String> = None;
    for spec in specs {
        let (key_opt, path) = split_persona_spec(spec);
        let persona = Persona::from_path(&path)
            .with_context(|| format!("loading persona {}", path.display()))?;
        let key = key_opt.unwrap_or_else(|| persona.name.clone());
        if entries.iter().any(|(k, _)| k == &key) {
            anyhow::bail!("duplicate persona route key {key:?} (from spec {spec:?})");
        }
        info!(key = %key, persona = %persona.name, tools = persona.tools.len(), "persona loaded");
        first_key.get_or_insert_with(|| key.clone());
        entries.push((key, persona));
    }
    let default = default_key
        .map(str::to_string)
        .or(first_key)
        .expect("non-empty persona specs guaranteed by caller");
    PersonaSet::new(entries, default)
}

/// Split a `[key=]path` persona spec. A `key=` prefix is recognised only when
/// the text before the first `=` looks like a bare route key (no path
/// separators or dots), so `--persona ./a.yaml` is not mistaken for a key.
fn split_persona_spec(spec: &str) -> (Option<String>, PathBuf) {
    if let Some((maybe_key, rest)) = spec.split_once('=') {
        let looks_like_key = !maybe_key.is_empty()
            && !maybe_key.contains('/')
            && !maybe_key.contains('\\')
            && !maybe_key.contains('.');
        if looks_like_key {
            return (Some(maybe_key.to_string()), PathBuf::from(rest));
        }
    }
    (None, PathBuf::from(spec))
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
