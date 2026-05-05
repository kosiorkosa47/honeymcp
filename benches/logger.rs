//! Logger write throughput benchmark.
//!
//! What this measures:
//!
//! - End-to-end `Logger::record` latency: SQLite INSERT + JSONL append.
//!   The two surfaces share a path inside `record`, so this is the upper
//!   bound on how fast one honeymcp instance can ingest events on commodity
//!   hardware before back-pressure shows up on the request path.
//!
//! What this is *not*:
//!
//! - Postgres recorder is gated behind `--features postgres`; that path
//!   is scaffold-only today (see `docs/scope-decisions.md` SD-3) so it
//!   stays out of this bench. When the Postgres recorder lands the
//!   structure here is the template for `benches/logger_postgres.rs`.
//!
//! Run with `cargo bench --bench logger`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use honeymcp::logger::{hash_params, LogEntry, Logger};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::runtime::Runtime;

fn make_entry(params: Value) -> LogEntry {
    LogEntry {
        timestamp_ms: 0,
        method: "tools/call".into(),
        params_hash: hash_params(&Some(params.clone())),
        params: Some(params),
        client_name: Some("bench".into()),
        client_version: Some("0".into()),
        session_id: "bench-session".into(),
        response_summary: "ok".into(),
        transport: Some("http".into()),
        remote_addr: Some("203.0.113.7:51000".into()),
        user_agent: Some("bench/1.0".into()),
        client_meta: None,
        is_operator: false,
    }
}

fn bench_logger_record(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("logger/record");

    for (label, payload_fn) in [
        ("small_200B", small_payload as fn() -> Value),
        ("medium_2KB", medium_payload),
        ("large_64KB", large_payload),
    ] {
        // Each iteration writes one event; criterion surfaces ev/s.
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(label), &(), |b, _| {
            // Per-iter setup: fresh tempdir + fresh logger so the bench
            // doesn't measure the cost of growing files across millions of
            // criterion samples. The amortised SQLite trim path
            // (every 1000 inserts) is exercised separately by the unit
            // tests; here we want a clean micro-throughput number.
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let tmp = TempDir::new().expect("tempdir");
                    let db = tmp.path().join("hive.db");
                    let jsonl = tmp.path().join("hive.jsonl");
                    let logger = Logger::open(&db, Some(&jsonl)).await.expect("logger");
                    let entry = make_entry(payload_fn());

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let _ = black_box(logger.record(black_box(&entry)).await);
                    }
                    start.elapsed()
                })
            });
        });
    }

    group.finish();
}

fn small_payload() -> Value {
    json!({"name": "read_file", "arguments": {"path": "/etc/passwd"}})
}

fn medium_payload() -> Value {
    let blob = "x".repeat(2 * 1024);
    json!({"name": "run", "arguments": {"command": format!("echo {}", blob)}})
}

fn large_payload() -> Value {
    let blob = "x".repeat(64 * 1024);
    json!({"name": "write_file", "arguments": {"content": blob}})
}

criterion_group!(benches, bench_logger_record);
criterion_main!(benches);
