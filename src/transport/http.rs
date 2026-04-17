//! HTTP + SSE transport.
//!
//! Implements the MCP "HTTP + Server-Sent Events" transport:
//!
//! - `GET /sse` — opens a long-lived SSE stream for a session. The server first emits
//!   an `event: endpoint` with a `data:` URL that tells the client where to POST. All
//!   subsequent JSON-RPC responses for that session are written back to the SSE stream
//!   as `event: message` frames.
//! - `POST /message` — JSON-RPC request. Response is ALSO returned in the POST body
//!   (so plain curl works), and, if an SSE stream is currently attached to the session,
//!   a copy is dispatched there as well.
//!
//! CORS is fully permissive on purpose — this is a honeypot and we want to entice
//! browser-based attackers too.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::protocol::JsonRpcRequest;
use crate::stats::StatsProvider;
use crate::transport::{Handler, RequestContext, Transport};

pub struct HttpTransport {
    addr: SocketAddr,
    stats: Option<Arc<dyn StatsProvider>>,
}

impl HttpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, stats: None }
    }

    pub fn with_stats(mut self, stats: Arc<dyn StatsProvider>) -> Self {
        self.stats = Some(stats);
        self
    }
}

#[derive(Clone)]
struct AppState {
    handler: Arc<dyn Handler>,
    stats: Option<Arc<dyn StatsProvider>>,
    sessions: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
}

#[derive(Debug, Deserialize)]
struct SessionQuery {
    session_id: Option<String>,
}

fn generate_session_id() -> String {
    let ts = crate::logger::now_ms();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("http-{ts:x}-{nanos:x}")
}

fn resolve_session_id(q: &SessionQuery, headers: &HeaderMap) -> String {
    q.session_id
        .clone()
        .or_else(|| {
            headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(generate_session_id)
}

fn header_meta(headers: &HeaderMap) -> (Option<String>, Option<Value>) {
    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let client_meta = xff.map(|x| json!({ "x_forwarded_for": x }));
    (ua, client_meta)
}

#[async_trait]
impl Transport for HttpTransport {
    async fn run(&mut self, handler: Arc<dyn Handler>) -> Result<()> {
        let state = AppState {
            handler,
            stats: self.stats.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        };

        let cors = tower_http::cors::CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any);

        let app = Router::new()
            .route("/sse", get(sse_handler))
            .route("/message", post(message_handler))
            .route("/stats", get(stats_handler))
            .route("/dashboard", get(dashboard_handler))
            .route("/", get(dashboard_handler))
            .route("/healthz", get(|| async { "ok" }))
            .layer(cors)
            .with_state(state);

        info!(addr = %self.addr, "http transport listening");
        let listener = tokio::net::TcpListener::bind(self.addr)
            .await
            .with_context(|| format!("binding to {}", self.addr))?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("axum serve failed")?;
        Ok(())
    }
}

/// Embedded static dashboard. Single-file vanilla JS polls `/stats` every 5 s and
/// renders a small terminal-styled summary page. No build step, no framework, just
/// a `<script>` block; kept inline so it ships baked into the binary.
const DASHBOARD_HTML: &str = include_str!("../dashboard.html");

async fn dashboard_handler() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
        .into_response()
}

async fn stats_handler(State(state): State<AppState>) -> Response {
    match state.stats {
        Some(provider) => match provider.stats().await {
            Ok(snap) => (StatusCode::OK, Json(snap)).into_response(),
            Err(e) => {
                warn!(error = %e, "stats query failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("stats: {e}")})),
                )
                    .into_response()
            }
        },
        None => (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "stats provider not configured"})),
        )
            .into_response(),
    }
}

async fn sse_handler(
    Query(q): Query<SessionQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = std::result::Result<Event, std::convert::Infallible>>> {
    let session_id = resolve_session_id(&q, &headers);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(session_id.clone(), tx);
    }
    debug!(session = %session_id, "sse subscriber attached");

    let sessions_for_cleanup = state.sessions.clone();
    let cleanup_id = session_id.clone();
    let initial_id = session_id.clone();

    let stream = async_stream::stream! {
        // Per MCP spec: announce the POST endpoint first.
        yield Ok(Event::default()
            .event("endpoint")
            .data(format!("/message?session_id={initial_id}")));

        while let Some(payload) = rx.recv().await {
            yield Ok(Event::default().event("message").data(payload));
        }

        // Client disconnected: evict the session sender.
        let mut sessions = sessions_for_cleanup.write().await;
        sessions.remove(&cleanup_id);
        debug!(session = %cleanup_id, "sse subscriber detached");
    };

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

async fn message_handler(
    Query(q): Query<SessionQuery>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    let session_id = resolve_session_id(&q, &headers);
    let (user_agent, client_meta) = header_meta(&headers);

    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "malformed JSON-RPC POST body");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("parse error: {e}")},
                    "id": null
                })),
            )
                .into_response();
        }
    };

    let ctx = RequestContext {
        session_id: session_id.clone(),
        transport: "http",
        remote_addr: Some(remote.to_string()),
        user_agent,
        client_meta,
    };

    let response = state.handler.handle_request(req, ctx).await;

    if let Some(resp) = response {
        let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());

        // If an SSE subscriber is attached to this session, forward the response there too.
        if let Some(tx) = state.sessions.read().await.get(&session_id).cloned() {
            let _ = tx.send(body.clone());
        }

        (StatusCode::OK, [("content-type", "application/json")], body).into_response()
    } else {
        // Notification — no response body.
        StatusCode::ACCEPTED.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcRequest, JsonRpcResponse, RequestId};
    use async_trait::async_trait;

    struct CapturingHandler {
        last_ctx: tokio::sync::Mutex<Option<RequestContext>>,
    }

    #[async_trait]
    impl Handler for CapturingHandler {
        async fn handle_request(
            &self,
            req: JsonRpcRequest,
            ctx: RequestContext,
        ) -> Option<JsonRpcResponse> {
            *self.last_ctx.lock().await = Some(ctx);
            Some(JsonRpcResponse::ok(
                req.id.unwrap_or(RequestId::Null),
                serde_json::json!({"ok": true}),
            ))
        }
    }

    #[tokio::test]
    async fn post_message_returns_response_and_sets_session_from_header() {
        let handler = Arc::new(CapturingHandler {
            last_ctx: tokio::sync::Mutex::new(None),
        });
        let state = AppState {
            handler: handler.clone(),
            stats: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/message", post(message_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let body = r#"{"jsonrpc":"2.0","method":"ping","id":7}"#;
        let resp = reqwest_post(&addr, body, Some("sess-abc"), Some("honeypot-test/1.0")).await;
        assert_eq!(resp.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(parsed["result"]["ok"], true);

        let ctx = handler.last_ctx.lock().await.clone().unwrap();
        assert_eq!(ctx.session_id, "sess-abc");
        assert_eq!(ctx.transport, "http");
        assert_eq!(ctx.user_agent.as_deref(), Some("honeypot-test/1.0"));
    }

    struct HttpResp {
        status: u16,
        body: String,
    }

    async fn reqwest_post(
        addr: &SocketAddr,
        body: &str,
        session: Option<&str>,
        ua: Option<&str>,
    ) -> HttpResp {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let session_hdr = session
            .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
            .unwrap_or_default();
        let ua_hdr = ua
            .map(|u| format!("User-Agent: {u}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "POST /message HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             {session_hdr}{ua_hdr}Connection: close\r\n\r\n{body}",
            len = body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let first_line = head.lines().next().unwrap_or("");
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        HttpResp {
            status,
            body: body.to_string(),
        }
    }
}
