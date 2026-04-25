//! HTTP transport.
//!
//! The process speaks two overlapping wire shapes so anything an attacker aims at it
//! gets captured cleanly:
//!
//! ## Streamable HTTP (MCP spec 2025-06-18, current)
//!
//! - `POST /mcp` — JSON-RPC request. Response shape is content-negotiated:
//!   - `Accept: text/event-stream` → a single-message SSE stream (the server emits the
//!     response as one `event: message` frame, then closes).
//!   - Anything else → `application/json` with the response inline.
//! - `GET /mcp` — opens a long-lived server-to-client SSE stream for the session, for
//!   out-of-band notifications. The session is identified by the `Mcp-Session-Id`
//!   header (preferred) or the `session_id` query parameter (fallback).
//! - `DELETE /mcp` — explicit session teardown. Evicts any attached SSE subscriber
//!   for the session. Always returns `204 No Content` (including for unknown
//!   sessions — we do not leak whether a session was active).
//! - The MCP protocol version travels in the `MCP-Protocol-Version` request header.
//!   The server records it in `client_meta` for threat-intel but does NOT reject
//!   missing or mismatched versions — bad headers are themselves a useful signal.
//!
//! ## HTTP + SSE (MCP spec 2024-11-05, deprecated 2025-03-26, kept for compatibility)
//!
//! - `GET /sse` — opens a long-lived SSE stream. First frame is `event: endpoint` with
//!   the POST URL. Subsequent JSON-RPC responses for the session arrive as
//!   `event: message` frames.
//! - `POST /message` — JSON-RPC request. Response is echoed in the POST body AND, if
//!   an SSE stream is attached to the session, forwarded there too.
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
    http::{self, HeaderMap, StatusCode},
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
    let mcp_proto = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let mut meta = serde_json::Map::new();
    if let Some(x) = xff {
        meta.insert("x_forwarded_for".into(), Value::String(x));
    }
    if let Some(v) = mcp_proto {
        meta.insert("mcp_protocol_version".into(), Value::String(v));
    }
    if let Some(a) = accept {
        meta.insert("accept".into(), Value::String(a));
    }
    let client_meta = if meta.is_empty() {
        None
    } else {
        Some(Value::Object(meta))
    };
    (ua, client_meta)
}

/// Decide the response shape requested by a client: inline JSON or an SSE single-message
/// stream. Per MCP spec 2025-06-18, `Accept: text/event-stream` activates the SSE path.
fn wants_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.to_ascii_lowercase().contains("text/event-stream"))
}

fn remote_addr_from(headers: &HeaderMap, peer: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next().map(|p| p.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.to_string())
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

        // Per-IP token bucket on /message: ~2 req/s sustained with a 20-request
        // burst. This is generous enough for any legitimate MCP client (bursts
        // during handshake) and hostile enough to blunt a single-source flood.
        let governor_conf = std::sync::Arc::new(
            tower_governor::governor::GovernorConfigBuilder::default()
                .per_second(2)
                .burst_size(20)
                .finish()
                .expect("valid governor config"),
        );
        let governor_layer = tower_governor::GovernorLayer {
            config: governor_conf,
        };

        // Global request-body cap: 256 KiB. An MCP JSON-RPC message that needs
        // more than that is almost certainly an attempt to exhaust memory.
        let body_limit = tower_http::limit::RequestBodyLimitLayer::new(256 * 1024);

        // /message is the only endpoint that accepts attacker-controlled input
        // large enough to matter, so rate limiting + body cap land there. /sse,
        // /stats, /dashboard, /healthz are cheap and widely probed; letting
        // those through unthrottled keeps the dashboard responsive during a
        // flood against /message.
        let message_routes = Router::new()
            .route("/message", post(message_handler))
            .route(
                "/mcp",
                post(mcp_post_handler)
                    .get(mcp_sse_handler)
                    .delete(mcp_delete_handler),
            )
            .layer(governor_layer)
            .layer(body_limit)
            .with_state(state.clone());

        let app = Router::new()
            .merge(message_routes)
            .route("/sse", get(sse_handler))
            .route("/stats", get(stats_handler))
            .route("/dashboard", get(dashboard_handler))
            .route("/version", get(version_handler))
            .route("/", get(banner_handler))
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

/// Operator banner served at `GET /`. Serves the plain-text version by default; if
/// the client sends `Accept: text/html`, the HTML version is returned instead.
///
/// Substitutes three runtime fields from env vars:
/// - `HONEYMCP_BANNER_CONTROLLER` — name of the controller (GDPR Art. 4(7))
/// - `HONEYMCP_BANNER_ABUSE_EMAIL` — monitored mailbox for data-subject requests
/// - `HONEYMCP_BANNER_CONTACT` — optional human contact name
///
/// Missing env vars fall back to `<operator not configured>` deliberately — a
/// production instance that ships a template-looking banner is better than one
/// that silently fabricates a contact address.
const BANNER_TEXT_TEMPLATE: &str = include_str!("banner.txt");
const BANNER_HTML_TEMPLATE: &str = include_str!("banner.html");

fn operator_banner_text() -> String {
    let cfg = BannerConfig::from_env();
    fill_banner(BANNER_TEXT_TEMPLATE, &cfg)
}

fn operator_banner_html() -> String {
    let cfg = BannerConfig::from_env();
    fill_banner(BANNER_HTML_TEMPLATE, &cfg)
}

struct BannerConfig {
    controller: String,
    abuse_email: String,
    contact: String,
}

impl BannerConfig {
    fn from_env() -> Self {
        let unconfigured = "<operator not configured>".to_string();
        Self {
            controller: std::env::var("HONEYMCP_BANNER_CONTROLLER")
                .unwrap_or_else(|_| unconfigured.clone()),
            abuse_email: std::env::var("HONEYMCP_BANNER_ABUSE_EMAIL")
                .unwrap_or_else(|_| unconfigured.clone()),
            contact: std::env::var("HONEYMCP_BANNER_CONTACT")
                .unwrap_or_else(|_| "research operator".to_string()),
        }
    }
}

fn fill_banner(template: &str, cfg: &BannerConfig) -> String {
    template
        .replace("{{CONTROLLER}}", &cfg.controller)
        .replace("{{ABUSE_EMAIL}}", &cfg.abuse_email)
        .replace("{{CONTACT}}", &cfg.contact)
}

fn client_accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            let lower = s.to_ascii_lowercase();
            // Prefer HTML only when the client explicitly asks for it. A plain
            // curl sends `Accept: */*`, which should stay on the text path so
            // operators doing quick probes get a readable response.
            lower.contains("text/html")
        })
}

async fn banner_handler(headers: HeaderMap) -> Response {
    if client_accepts_html(&headers) {
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            operator_banner_html(),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [("content-type", "text/plain; charset=utf-8")],
            operator_banner_text(),
        )
            .into_response()
    }
}

/// Build-time provenance stamped by `build.rs`. Surfaced verbatim at `/version` so
/// an operator can `curl /version` after a deploy and prove what is actually live
/// without trusting the docker tag or release name. The git sha picks up a
/// `-dirty` suffix when the working tree had uncommitted changes at build time;
/// any production binary should never carry that suffix.
const BUILD_GIT_SHA: &str = env!("HONEYMCP_GIT_SHA");
const BUILD_UNIX_TS: &str = env!("HONEYMCP_BUILD_UNIX_TS");

async fn version_handler() -> Response {
    let unix_ts: i64 = BUILD_UNIX_TS.parse().unwrap_or(0);
    let build_time_utc = time::OffsetDateTime::from_unix_timestamp(unix_ts)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "unknown".to_string());

    Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": BUILD_GIT_SHA,
        "build_time_utc": build_time_utc,
        "build_unix_ts": unix_ts,
    }))
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
        remote_addr: Some(remote_addr_from(&headers, remote)),
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

/// Streamable HTTP POST per MCP spec 2025-06-18.
///
/// Behaviour is identical to `/message` with two differences:
/// - Response shape follows `Accept`: `text/event-stream` returns a single-message SSE
///   stream; anything else returns plain `application/json`.
/// - The `MCP-Protocol-Version` and `Accept` headers are recorded in `client_meta`
///   alongside `x-forwarded-for`, so the dashboard / detectors can see what the client
///   claimed to speak.
///
/// Missing or mismatched `MCP-Protocol-Version` is NOT rejected. A honeypot that
/// returns HTTP 400 to malformed probes just teaches the attacker to avoid the trap.
async fn mcp_post_handler(
    Query(q): Query<SessionQuery>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    let session_id = resolve_session_id(&q, &headers);
    let (user_agent, client_meta) = header_meta(&headers);
    let event_stream = wants_event_stream(&headers);

    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "malformed JSON-RPC POST body on /mcp");
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
        remote_addr: Some(remote_addr_from(&headers, remote)),
        user_agent,
        client_meta,
    };

    let response = state.handler.handle_request(req, ctx).await;

    let Some(resp) = response else {
        // JSON-RPC notification: spec says 202 Accepted with no body. Do not promote
        // this to an SSE frame even when the client asked for event-stream.
        return (
            StatusCode::ACCEPTED,
            [(
                "mcp-session-id",
                http::HeaderValue::from_str(&session_id)
                    .unwrap_or_else(|_| http::HeaderValue::from_static("")),
            )],
        )
            .into_response();
    };

    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());

    // Echo the response to any attached GET /mcp stream for the same session, so
    // out-of-band subscribers see it too (mirrors the HTTP+SSE forwarding semantics).
    if let Some(tx) = state.sessions.read().await.get(&session_id).cloned() {
        let _ = tx.send(body.clone());
    }

    if event_stream {
        // Single-shot SSE: one `message` event carrying the response, then close.
        let body_for_stream = body.clone();
        let stream = async_stream::stream! {
            yield Ok::<_, std::convert::Infallible>(
                Event::default().event("message").data(body_for_stream)
            );
        };
        let sse = Sse::new(stream);
        let mut resp = sse.into_response();
        if let Ok(val) = http::HeaderValue::from_str(&session_id) {
            resp.headers_mut().insert("mcp-session-id", val);
        }
        resp
    } else {
        let mut headers_out = axum::http::HeaderMap::new();
        headers_out.insert(
            "content-type",
            http::HeaderValue::from_static("application/json"),
        );
        if let Ok(val) = http::HeaderValue::from_str(&session_id) {
            headers_out.insert("mcp-session-id", val);
        }
        (StatusCode::OK, headers_out, body).into_response()
    }
}

/// Streamable HTTP DELETE per MCP spec 2025-06-18: explicit session teardown.
///
/// Evicts any attached SSE subscriber for the session and returns `204 No Content`.
/// Unknown sessions also return 204 — we deliberately do not differentiate so a
/// scanner cannot probe for live session IDs by watching for 404 vs 204.
async fn mcp_delete_handler(
    Query(q): Query<SessionQuery>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    let session_id = resolve_session_id(&q, &headers);
    let existed = {
        let mut sessions = state.sessions.write().await;
        sessions.remove(&session_id).is_some()
    };
    if existed {
        debug!(session = %session_id, "/mcp session torn down by client");
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Streamable HTTP GET per MCP spec 2025-06-18: a server-to-client SSE channel for
/// unsolicited notifications tied to a session. Session routing and lifecycle are
/// identical to the legacy `/sse` handler; the only distinction is the URL.
async fn mcp_sse_handler(
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
    debug!(session = %session_id, "/mcp sse subscriber attached");

    let sessions_for_cleanup = state.sessions.clone();
    let cleanup_id = session_id.clone();

    let stream = async_stream::stream! {
        while let Some(payload) = rx.recv().await {
            yield Ok(Event::default().event("message").data(payload));
        }
        let mut sessions = sessions_for_cleanup.write().await;
        sessions.remove(&cleanup_id);
        debug!(session = %cleanup_id, "/mcp sse subscriber detached");
    };

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
    use async_trait::async_trait;

    #[test]
    fn banner_substitutes_all_placeholders_from_config() {
        let cfg = BannerConfig {
            controller: "Test Researcher".into(),
            abuse_email: "abuse@example.test".into(),
            contact: "Research Desk".into(),
        };
        let text = fill_banner(BANNER_TEXT_TEMPLATE, &cfg);
        assert!(
            text.contains("Test Researcher"),
            "controller not substituted"
        );
        assert!(
            text.contains("abuse@example.test"),
            "abuse email not substituted"
        );
        assert!(!text.contains("{{"), "placeholders remain:\n{text}");

        let html = fill_banner(BANNER_HTML_TEMPLATE, &cfg);
        assert!(html.contains("Test Researcher"));
        assert!(html.contains("abuse@example.test"));
        assert!(!html.contains("{{"));
        assert!(html.contains("mailto:abuse@example.test"));
    }

    #[test]
    fn banner_marks_missing_operator_fields_as_unconfigured() {
        let cfg = BannerConfig {
            controller: "<operator not configured>".into(),
            abuse_email: "<operator not configured>".into(),
            contact: "research operator".into(),
        };
        let text = fill_banner(BANNER_TEXT_TEMPLATE, &cfg);
        assert!(text.contains("<operator not configured>"));
    }

    #[test]
    fn banner_accept_negotiation_prefers_plain_text_by_default() {
        // `curl` default Accept: */* must not get HTML — we want operators doing
        // a quick probe to see readable text.
        let mut h = HeaderMap::new();
        h.insert("accept", "*/*".parse().unwrap());
        assert!(!client_accepts_html(&h));

        h.insert("accept", "text/plain".parse().unwrap());
        assert!(!client_accepts_html(&h));

        h.insert(
            "accept",
            "text/html,application/xhtml+xml;q=0.9".parse().unwrap(),
        );
        assert!(client_accepts_html(&h));
    }

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
            // Notifications (no `id`) get no response, same as the real server.
            let id = req.id?;
            Some(JsonRpcResponse::ok(id, serde_json::json!({"ok": true})))
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

    // ---- Streamable HTTP (MCP spec 2025-06-18) ------------------------------

    async fn spawn_app() -> (SocketAddr, Arc<CapturingHandler>) {
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
            .route(
                "/mcp",
                post(mcp_post_handler)
                    .get(mcp_sse_handler)
                    .delete(mcp_delete_handler),
            )
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
        (addr, handler)
    }

    #[tokio::test]
    async fn streamable_http_post_returns_json_when_accept_is_application_json() {
        let (addr, handler) = spawn_app().await;
        let body = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        let resp = raw_post(
            &addr,
            "/mcp",
            body,
            &[
                ("Accept", "application/json"),
                ("MCP-Protocol-Version", "2025-06-18"),
                ("Mcp-Session-Id", "streamable-abc"),
            ],
        )
        .await;
        assert_eq!(resp.status, 200);
        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type")
                    && v.contains("application/json"))
        );
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("mcp-session-id") && v == "streamable-abc"));

        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(parsed["result"]["ok"], true);

        let ctx = handler.last_ctx.lock().await.clone().unwrap();
        assert_eq!(ctx.session_id, "streamable-abc");
        assert_eq!(ctx.transport, "http");
        let meta = ctx.client_meta.unwrap();
        assert_eq!(meta["mcp_protocol_version"], "2025-06-18");
        assert_eq!(meta["accept"], "application/json");
    }

    #[tokio::test]
    async fn streamable_http_post_returns_sse_when_accept_is_event_stream() {
        let (addr, _handler) = spawn_app().await;
        let body = r#"{"jsonrpc":"2.0","method":"ping","id":2}"#;
        let resp = raw_post(
            &addr,
            "/mcp",
            body,
            &[
                ("Accept", "text/event-stream"),
                ("MCP-Protocol-Version", "2025-06-18"),
            ],
        )
        .await;
        assert_eq!(resp.status, 200);
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type")
                && v.starts_with("text/event-stream")));
        // SSE frame payload includes the JSON-RPC response on a `data:` line.
        assert!(
            resp.body.contains("event: message"),
            "body did not contain SSE message frame: {:?}",
            resp.body
        );
        assert!(
            resp.body.contains("\"result\""),
            "body did not contain JSON-RPC result: {:?}",
            resp.body
        );
    }

    #[tokio::test]
    async fn streamable_http_post_notification_returns_202_no_body() {
        let (addr, _handler) = spawn_app().await;
        // JSON-RPC notification: no `id` field => handler returns None.
        let body = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let resp = raw_post(
            &addr,
            "/mcp",
            body,
            &[
                ("Accept", "text/event-stream"),
                ("MCP-Protocol-Version", "2025-06-18"),
                ("Mcp-Session-Id", "notif-xyz"),
            ],
        )
        .await;
        assert_eq!(resp.status, 202);
        assert!(resp.body.trim().is_empty(), "body was: {:?}", resp.body);
        assert!(resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("mcp-session-id") && v == "notif-xyz"));
    }

    #[tokio::test]
    async fn streamable_http_post_malformed_body_returns_json_rpc_parse_error() {
        let (addr, _handler) = spawn_app().await;
        let resp = raw_post(
            &addr,
            "/mcp",
            "{not-json",
            &[("Accept", "application/json")],
        )
        .await;
        assert_eq!(resp.status, 400);
        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(parsed["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn version_endpoint_reports_build_provenance() {
        let app = Router::new().route("/version", get(version_handler));
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

        let resp = raw_get(&addr, "/version", &[]).await;
        assert_eq!(resp.status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        assert_eq!(parsed["name"], env!("CARGO_PKG_NAME"));
        assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
        // git_sha should be a 12-hex-char short sha (optionally with -dirty),
        // never the empty string. Falls back to "unknown" outside a git tree;
        // tests run from inside the repo so we expect a real sha here.
        let sha = parsed["git_sha"].as_str().unwrap();
        assert!(!sha.is_empty(), "git_sha empty");
        // build_unix_ts should be a positive integer; build_time_utc should
        // round-trip back to the same instant via RFC3339 parsing.
        let ts = parsed["build_unix_ts"].as_i64().unwrap();
        assert!(ts > 0, "build_unix_ts not stamped");
        let utc = parsed["build_time_utc"].as_str().unwrap();
        assert!(
            utc.contains('T') && utc.ends_with('Z'),
            "not RFC3339: {utc}"
        );
    }

    async fn raw_get(addr: &SocketAddr, path: &str, extra_headers: &[(&str, &str)]) -> HttpResp {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut hdrs = String::new();
        for (k, v) in extra_headers {
            hdrs.push_str(&format!("{k}: {v}\r\n"));
        }
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             {hdrs}Connection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let first_line = head.lines().next().unwrap_or("");
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let headers: Vec<(String, String)> = head
            .lines()
            .skip(1)
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        HttpResp {
            status,
            body: body.to_string(),
            headers,
        }
    }

    #[tokio::test]
    async fn streamable_http_delete_returns_204_whether_or_not_session_existed() {
        let (addr, _handler) = spawn_app().await;

        // Unknown session — 204 with no leaking differentiation.
        let resp = raw_delete(&addr, "/mcp?session_id=never-existed", &[]).await;
        assert_eq!(resp.status, 204);
        assert!(resp.body.trim().is_empty());

        // Create a session via POST /mcp (SSE GET is how sessions actually get
        // entered into the subscriber map, but for this test we just assert the
        // DELETE path is idempotent and does not 404/500).
        let _ = raw_post(
            &addr,
            "/mcp",
            r#"{"jsonrpc":"2.0","method":"ping","id":99}"#,
            &[("Mcp-Session-Id", "to-be-torn-down")],
        )
        .await;

        let resp = raw_delete(&addr, "/mcp", &[("Mcp-Session-Id", "to-be-torn-down")]).await;
        assert_eq!(resp.status, 204);
    }

    struct HttpResp {
        status: u16,
        body: String,
        headers: Vec<(String, String)>,
    }

    async fn reqwest_post(
        addr: &SocketAddr,
        body: &str,
        session: Option<&str>,
        ua: Option<&str>,
    ) -> HttpResp {
        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(s) = session {
            extra.push(("Mcp-Session-Id", s));
        }
        if let Some(u) = ua {
            extra.push(("User-Agent", u));
        }
        raw_post(addr, "/message", body, &extra).await
    }

    async fn raw_delete(addr: &SocketAddr, path: &str, extra_headers: &[(&str, &str)]) -> HttpResp {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut hdrs = String::new();
        for (k, v) in extra_headers {
            hdrs.push_str(&format!("{k}: {v}\r\n"));
        }
        let req = format!(
            "DELETE {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             {hdrs}Connection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let first_line = head.lines().next().unwrap_or("");
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let headers: Vec<(String, String)> = head
            .lines()
            .skip(1)
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        HttpResp {
            status,
            body: body.to_string(),
            headers,
        }
    }

    async fn raw_post(
        addr: &SocketAddr,
        path: &str,
        body: &str,
        extra_headers: &[(&str, &str)],
    ) -> HttpResp {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut hdrs = String::new();
        for (k, v) in extra_headers {
            hdrs.push_str(&format!("{k}: {v}\r\n"));
        }
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             {hdrs}Connection: close\r\n\r\n{body}",
            len = body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();

        // Streamable-HTTP SSE responses keep the connection open until the stream
        // terminates. Our single-shot `mcp_post_handler` closes after one frame,
        // so the pre-existing read_to_end works; we just bound the wait so a bug
        // doesn't hang the test harness.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let first_line = head.lines().next().unwrap_or("");
        let status = first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let headers: Vec<(String, String)> = head
            .lines()
            .skip(1)
            .filter_map(|line| {
                line.split_once(':')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        HttpResp {
            status,
            body: body.to_string(),
            headers,
        }
    }
}
