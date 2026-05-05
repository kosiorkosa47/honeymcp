//! Dispatcher end-to-end benchmark.
//!
//! What this measures:
//!
//! - `Dispatcher::handle_request` for the three wire methods every MCP
//!   client sends in its first second of life: `initialize`, `tools/list`,
//!   `tools/call`.
//! - The persona pipeline (load → tools/list build → canned-response
//!   lookup) plus detector dispatch plus logger write, all together. This
//!   is the closest single number we have to "max sustainable req/s on
//!   one box".
//!
//! What this is *not*:
//!
//! - Network latency. This bench bypasses the http transport so the
//!   numbers reflect dispatcher cost, not Caddy or kernel TCP.
//! - Multi-session contention. Each iteration uses a single session id;
//!   contention benchmarks are tracked separately as the sessions hashmap
//!   becomes load-bearing.
//!
//! Run with `cargo bench --bench dispatcher`.

use std::sync::Arc;

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use honeymcp::logger::Logger;
use honeymcp::persona::Persona;
use honeymcp::protocol::{JsonRpcRequest, JsonRpcResponse, RequestId};
use honeymcp::server::Dispatcher;
use honeymcp::transport::{Handler, RequestContext};
use serde_json::json;
use tempfile::TempDir;
use tokio::runtime::Runtime;

#[async_trait]
trait DispatcherHandler: Sync + Send {
    async fn handle(&self, req: JsonRpcRequest, ctx: RequestContext) -> Option<JsonRpcResponse>;
}

#[async_trait]
impl DispatcherHandler for Dispatcher {
    async fn handle(&self, req: JsonRpcRequest, ctx: RequestContext) -> Option<JsonRpcResponse> {
        // Reuses the `Handler` trait Dispatcher implements for the http
        // transport so the bench exercises the same code path as the
        // production handler call.
        Handler::handle_request(self, req, ctx).await
    }
}

async fn build_dispatcher(tmp: &TempDir) -> Arc<Dispatcher> {
    let db = tmp.path().join("hive.db");
    let logger = Logger::open(&db, None).await.expect("logger open");

    // Use the github-admin persona that ships in the repo so the bench
    // exercises a realistic tools/list payload (six tools, varied schemas,
    // canned responses with hundreds of bytes each).
    let persona_yaml = std::fs::read_to_string("personas/github-admin.yaml")
        .expect("personas/github-admin.yaml is part of the repo and must be readable from cwd");
    let persona: Persona = serde_yaml::from_str(&persona_yaml).expect("parse persona");

    Arc::new(Dispatcher::new(persona, logger))
}

fn bench_handle_request(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");

    type RequestBuilder = Box<dyn Fn() -> JsonRpcRequest>;
    let scenarios: Vec<(&str, RequestBuilder)> = vec![
        (
            "initialize",
            Box::new(|| JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: "initialize".into(),
                id: Some(RequestId::Number(1)),
                params: Some(json!({
                    "protocolVersion": "2025-06-18",
                    "clientInfo": {"name": "bench", "version": "1.0"}
                })),
            }),
        ),
        (
            "tools_list",
            Box::new(|| JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: "tools/list".into(),
                id: Some(RequestId::Number(2)),
                params: None,
            }),
        ),
        (
            "tools_call_read_file",
            Box::new(|| JsonRpcRequest {
                jsonrpc: "2.0".into(),
                method: "tools/call".into(),
                id: Some(RequestId::Number(3)),
                params: Some(json!({
                    "name": "read_file",
                    "arguments": {
                        "repo": "acme-corp/internal-api",
                        "path": ".env"
                    }
                })),
            }),
        ),
    ];

    let mut group = c.benchmark_group("dispatcher/handle_request");

    for (label, build_req) in &scenarios {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(label), &(), |b, _| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let tmp = TempDir::new().expect("tempdir");
                    let dispatcher = build_dispatcher(&tmp).await;
                    let ctx = RequestContext {
                        session_id: "bench-session".to_string(),
                        transport: "bench",
                        remote_addr: Some("127.0.0.1:0".to_string()),
                        user_agent: Some("bench/1.0".to_string()),
                        client_meta: None,
                    };

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let req = build_req();
                        let _ = black_box(dispatcher.handle(black_box(req), ctx.clone()).await);
                    }
                    start.elapsed()
                })
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_handle_request);
criterion_main!(benches);
