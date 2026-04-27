//! Dashboard v2 surface.
//!
//! Server-side rendered HTML via minijinja templates, with htmx + Alpine
//! handling the small amount of client-side state (operator-traffic toggle,
//! provenance footer, expand/collapse on session cards). Live updates ride
//! on Server-Sent Events.
//!
//! The full design is in `docs/dashboard-v2-design.md`. This module
//! delivers components 1 (Attack Story Timeline) and 2 (MCP Sequence
//! Diagram) plus the foundation that the other six components plug into.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use minijinja::{context, Environment};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::logger::{Logger, RawEventRow};
use crate::stats::StatsProvider;

const CSS_RAW: &str = include_str!("static/dashboard.css");
const HTMX_JS: &str = include_str!("static/htmx.min.js");
const ALPINE_JS: &str = include_str!("static/alpine.min.js");
const TPL_BASE: &str = include_str!("templates/base.html");
const TPL_INDEX: &str = include_str!("templates/index.html");

/// Compiled template environment. Cheap to clone — `Environment` keeps
/// templates in an `Arc` internally — so we build it once at boot and hand
/// references through the axum state.
pub struct DashboardEnv {
    env: Environment<'static>,
}

impl DashboardEnv {
    pub fn new() -> Result<Self> {
        let mut env = Environment::new();
        env.add_template("base.html", TPL_BASE)
            .context("loading base.html")?;
        env.add_template("index.html", TPL_INDEX)
            .context("loading index.html")?;
        Ok(Self { env })
    }

    fn render_index(&self, ctx: &IndexContext) -> Result<String> {
        let tpl = self.env.get_template("index.html")?;
        Ok(tpl.render(context! {
            css => CSS_RAW,
            stats => &ctx.stats_for_template,
            sessions => &ctx.sessions,
        })?)
    }
}

/// Shared state passed to dashboard handlers. Held under Arc to keep the
/// existing AppState pattern in transport/http.rs simple.
#[derive(Clone)]
pub struct DashboardState {
    pub env: Arc<DashboardEnv>,
    pub logger: Logger,
    pub stats: Option<Arc<dyn StatsProvider>>,
}

/// Query params for `/dashboard`. Mirrors the `/stats?include_operator=true`
/// flag so a shared URL fully reproduces the view.
#[derive(Debug, Deserialize, Default)]
pub struct DashboardQuery {
    #[serde(default)]
    pub include_operator: bool,
    #[serde(default)]
    #[allow(dead_code)] // reserved for future view= switch (timeline vs feed)
    pub view: Option<String>,
}

#[derive(Serialize)]
struct StatsForTemplate {
    total_events: i64,
    total_detections: i64,
    unique_remote_addrs_24h: i64,
    operator_traffic_included: bool,
    server: ServerForTemplate,
}

#[derive(Serialize)]
struct ServerForTemplate {
    name: String,
    version: String,
    protocol_version: String,
}

#[derive(Serialize)]
struct SessionForTemplate {
    session_id: String,
    /// URL-safe representation of `session_id` for path components.
    session_id_url: String,
    is_operator: bool,
    event_count: usize,
    detection_count: usize,
    client_ip: String,
    user_agent: String,
    last_seen_iso: String,
    last_seen_human: String,
    events: Vec<EventForTemplate>,
}

#[derive(Serialize)]
struct EventForTemplate {
    iso: String,
    relative: String,
    method: String,
    /// CSS class hint based on the method (`initialize`, `notifications`,
    /// `tools`, `other`).
    method_class: String,
    tool_name: Option<String>,
    /// True iff `tool_name` is set and is NOT in the persona's catalogue.
    /// Detected at template-prep time so the template stays free of logic.
    tool_unknown: bool,
    response_summary: String,
    detections: Vec<DetectionForTemplate>,
    params_preview: Option<String>,
}

#[derive(Serialize)]
struct DetectionForTemplate {
    detector: String,
    severity: String,
    evidence: String,
}

struct IndexContext {
    stats_for_template: StatsForTemplate,
    sessions: Vec<SessionForTemplate>,
}

/// Top-level dashboard handler. Renders the timeline view; SSE live feed
/// hangs off `/dashboard/feed`.
pub async fn index_handler(
    Query(q): Query<DashboardQuery>,
    State(state): State<DashboardState>,
) -> Response {
    let stats_provider = match &state.stats {
        Some(p) => p.clone(),
        None => {
            return (StatusCode::NOT_IMPLEMENTED, "stats provider not configured").into_response();
        }
    };

    let stats_snap = match stats_provider.stats(q.include_operator).await {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("stats: {e}")).into_response();
        }
    };

    let raw_rows = match state
        .logger
        .recent_events_with_detections(50, q.include_operator)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("event query: {e}"),
            )
                .into_response();
        }
    };

    let sessions = group_into_sessions(raw_rows);

    let stats_for_template = StatsForTemplate {
        total_events: stats_snap.total_events,
        total_detections: stats_snap.total_detections,
        unique_remote_addrs_24h: stats_snap.unique_remote_addrs_24h,
        operator_traffic_included: stats_snap.operator_traffic_included,
        server: ServerForTemplate {
            name: stats_snap.server.name,
            version: stats_snap.server.version,
            protocol_version: stats_snap.server.protocol_version.to_string(),
        },
    };

    let ctx = IndexContext {
        stats_for_template,
        sessions,
    };

    match state.env.render_index(&ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template render: {e}"),
        )
            .into_response(),
    }
}

/// Per-session SVG sequence diagram. Rendered server-side as raw SVG so
/// it works without any client-side viz library and prints / shares cleanly.
pub async fn sequence_handler(
    Path(session_id_svg): Path<String>,
    Query(q): Query<DashboardQuery>,
    State(state): State<DashboardState>,
) -> Response {
    // Strip trailing `.svg` so the URL `/dashboard/sequence/<id>.svg` is
    // compatible with axum 0.7 path matching (which does not support a
    // literal `.ext` after a path param).
    let session_id = session_id_svg
        .strip_suffix(".svg")
        .unwrap_or(&session_id_svg);
    let raw = match state
        .logger
        .recent_events_with_detections(2000, q.include_operator)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("query: {e}")).into_response();
        }
    };

    let session_events: Vec<&RawEventRow> =
        raw.iter().filter(|r| r.session_id == session_id).collect();

    if session_events.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            format!("session {session_id} not found in window"),
        )
            .into_response();
    }

    let svg = render_session_sequence_svg(session_id, &session_events);
    (
        StatusCode::OK,
        [("content-type", "image/svg+xml; charset=utf-8")],
        svg,
    )
        .into_response()
}

/// Static asset handler — htmx + alpine + css all in one route. Path
/// component selects the file. Bundled at compile time so a fresh clone
/// plus `cargo build` produces an operator-ready binary with no separate
/// asset pipeline.
pub async fn static_handler(Path(name): Path<String>) -> Response {
    let (body, ctype) = match name.as_str() {
        "htmx.min.js" => (HTMX_JS, "application/javascript; charset=utf-8"),
        "alpine.min.js" => (ALPINE_JS, "application/javascript; charset=utf-8"),
        "dashboard.css" => (CSS_RAW, "text/css; charset=utf-8"),
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    (
        StatusCode::OK,
        [
            ("content-type", ctype),
            ("cache-control", "public, max-age=86400"),
        ],
        body,
    )
        .into_response()
}

// --- helpers -------------------------------------------------------------

fn group_into_sessions(rows: Vec<RawEventRow>) -> Vec<SessionForTemplate> {
    // Preserve order of first appearance; rows came back in (last_seen DESC,
    // timestamp_ms ASC) so the first row of each session is its earliest.
    let mut grouped: BTreeMap<usize, (String, Vec<RawEventRow>)> = BTreeMap::new();
    let mut order_by_session: BTreeMap<String, usize> = BTreeMap::new();
    let mut next = 0usize;
    for row in rows {
        let idx = *order_by_session
            .entry(row.session_id.clone())
            .or_insert_with(|| {
                let i = next;
                next += 1;
                i
            });
        grouped
            .entry(idx)
            .or_insert_with(|| (row.session_id.clone(), Vec::new()))
            .1
            .push(row);
    }

    grouped
        .into_values()
        .map(|(session_id, events)| build_session_for_template(session_id, events))
        .collect()
}

fn build_session_for_template(session_id: String, events: Vec<RawEventRow>) -> SessionForTemplate {
    let event_count = events.len();
    let last = events
        .iter()
        .max_by_key(|e| e.timestamp_ms)
        .expect("non-empty session");
    let last_ts = last.timestamp_ms;

    let is_operator = events.iter().any(|e| e.is_operator);
    let user_agent = last.user_agent.clone().unwrap_or_else(|| "-".to_string());

    let client_ip = resolve_client_ip(last);

    let last_seen_iso = format_iso(last_ts);
    let last_seen_human = format_relative(last_ts, now_ms());

    let mut events_t: Vec<EventForTemplate> = events
        .iter()
        .map(|e| build_event_for_template(e, last_ts))
        .collect();
    let detection_count: usize = events_t.iter().map(|e| e.detections.len()).sum();
    // Newest first inside the card so the most recent activity is at the top.
    events_t.reverse();

    SessionForTemplate {
        session_id_url: urlencoding(&session_id),
        session_id,
        is_operator,
        event_count,
        detection_count,
        client_ip,
        user_agent,
        last_seen_iso,
        last_seen_human,
        events: events_t,
    }
}

fn build_event_for_template(e: &RawEventRow, _baseline_ts: i64) -> EventForTemplate {
    let method_class = method_class_for(&e.method);
    let (tool_name, tool_unknown) = parse_tool_name(&e.method, e.params.as_deref());
    let detections = parse_detections(e.detections_json.as_deref());
    let params_preview = e.params.as_deref().map(|p| truncate(p, 240));

    EventForTemplate {
        iso: format_iso(e.timestamp_ms),
        relative: format_relative(e.timestamp_ms, now_ms()),
        method: e.method.clone(),
        method_class,
        tool_name,
        tool_unknown,
        response_summary: e.response_summary.clone(),
        detections,
        params_preview,
    }
}

fn method_class_for(method: &str) -> String {
    if method == "initialize" {
        "initialize".into()
    } else if method.starts_with("notifications/") {
        "notifications".into()
    } else if method.starts_with("tools/") {
        "tools".into()
    } else {
        "other".into()
    }
}

fn parse_tool_name(method: &str, params: Option<&str>) -> (Option<String>, bool) {
    if method != "tools/call" {
        return (None, false);
    }
    let p = match params {
        Some(s) => s,
        None => return (None, false),
    };
    let v: Value = match serde_json::from_str(p) {
        Ok(v) => v,
        Err(_) => return (None, false),
    };
    let name = v.get("name").and_then(|n| n.as_str()).map(String::from);
    // We do not have the persona catalogue here cheaply; the dashboard
    // marks every tool name "unknown" for now and a follow-up plumbs the
    // catalogue through DashboardState. The CSS path handles both classes.
    (name, true)
}

fn parse_detections(raw: Option<&str>) -> Vec<DetectionForTemplate> {
    let s = match raw {
        Some(s) if !s.is_empty() && s != "null" => s,
        _ => return Vec::new(),
    };
    let arr: Value = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    arr.as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| {
            Some(DetectionForTemplate {
                detector: d.get("detector")?.as_str()?.to_string(),
                severity: d.get("severity")?.as_str()?.to_string(),
                evidence: d
                    .get("evidence")
                    .and_then(|v| v.as_str())
                    .map(truncate_summary)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn truncate_summary(s: &str) -> String {
    truncate(s, 140)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push_str(" …");
        out
    }
}

fn resolve_client_ip(e: &RawEventRow) -> String {
    // Prefer the XFF leftmost entry from client_meta (set by the http
    // transport when behind a reverse proxy); fall back to remote_addr
    // stripped of port.
    if let Some(meta) = e.client_meta.as_deref() {
        if let Ok(v) = serde_json::from_str::<Value>(meta) {
            if let Some(xff) = v.get("x_forwarded_for").and_then(|x| x.as_str()) {
                if let Some(first) = xff.split(',').map(str::trim).find(|s| !s.is_empty()) {
                    return first.to_string();
                }
            }
        }
    }
    match e.remote_addr.as_deref() {
        Some(a) => a
            .rsplit_once(':')
            .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
            .unwrap_or(a)
            .to_string(),
        None => "-".into(),
    }
}

fn now_ms() -> i64 {
    crate::logger::now_ms()
}

fn format_iso(ms: i64) -> String {
    let secs = ms / 1000;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| format!("@{ms}"))
}

fn format_relative(ts_ms: i64, now: i64) -> String {
    let dt = (now - ts_ms).max(0);
    let s = dt / 1000;
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

fn urlencoding(s: &str) -> String {
    // Sessions are short ASCII strings (uuid-shaped or `http-<hex>-<hex>`),
    // so a minimal percent-encoding of unsafe chars is enough.
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

// --- SVG sequence renderer ----------------------------------------------

/// Render a per-session MCP sequence diagram as standalone SVG markup.
///
/// The diagram models the protocol shape: client lifeline on the left,
/// server (persona) lifeline on the right, with one horizontal arrow per
/// JSON-RPC frame. Tool calls carry an inline tool name. Detector strikes
/// render as red bars next to the offending arrow.
fn render_session_sequence_svg(session_id: &str, events: &[&RawEventRow]) -> String {
    const W: i32 = 720;
    const ROW_H: i32 = 38;
    const CLIENT_X: i32 = 80;
    const SERVER_X: i32 = W - 80;
    const PADDING_TOP: i32 = 60;

    let h = PADDING_TOP + (events.len() as i32 + 1) * ROW_H + 40;

    let mut body = String::new();

    // Lifelines.
    body.push_str(&format!(
        r##"<line x1="{CLIENT_X}" y1="{PADDING_TOP}" x2="{CLIENT_X}" y2="{}" stroke="#2c363d" stroke-dasharray="3 4"/>
<line x1="{SERVER_X}" y1="{PADDING_TOP}" x2="{SERVER_X}" y2="{}" stroke="#2c363d" stroke-dasharray="3 4"/>
<text x="{CLIENT_X}" y="{}" fill="#7e8b86" font-size="11" text-anchor="middle">attacker</text>
<text x="{SERVER_X}" y="{}" fill="#7e8b86" font-size="11" text-anchor="middle">honeymcp</text>"##,
        h - 30,
        h - 30,
        PADDING_TOP - 18,
        PADDING_TOP - 18,
    ));

    // Title.
    body.push_str(&format!(
        r##"<text x="20" y="28" fill="#d8e3df" font-size="14" font-family="Inter, system-ui, sans-serif" font-weight="600">MCP sequence</text>
<text x="20" y="46" fill="#7e8b86" font-size="11" font-family="ui-monospace, monospace">{}</text>"##,
        escape_xml(session_id),
    ));

    for (i, ev) in events.iter().enumerate() {
        let y = PADDING_TOP + 20 + i as i32 * ROW_H;
        let going_to_server = !ev.method.starts_with("notifications/initialized");
        let (x1, x2) = if going_to_server {
            (CLIENT_X, SERVER_X)
        } else {
            (SERVER_X, CLIENT_X)
        };
        let arrow_color = method_color(&ev.method);

        // Arrow.
        body.push_str(&format!(
            r##"<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{arrow_color}" stroke-width="1.5"/>"##
        ));
        let head_x = if going_to_server { x2 - 6 } else { x2 + 6 };
        body.push_str(&format!(
            r##"<polygon points="{x2},{y} {head_x},{} {head_x},{}" fill="{arrow_color}"/>"##,
            y - 4,
            y + 4,
        ));

        // Method label.
        let label_x = (CLIENT_X + SERVER_X) / 2;
        body.push_str(&format!(
            r##"<text x="{label_x}" y="{}" fill="#d8e3df" font-size="12" font-family="ui-monospace, monospace" text-anchor="middle">{}</text>"##,
            y - 6,
            escape_xml(&ev.method),
        ));

        // Tool-name pill if applicable.
        if ev.method == "tools/call" {
            if let Some(p) = ev.params.as_deref() {
                if let Ok(v) = serde_json::from_str::<Value>(p) {
                    if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                        body.push_str(&format!(
                            r##"<text x="{label_x}" y="{}" fill="#a8e068" font-size="10" font-family="ui-monospace, monospace" text-anchor="middle">{}</text>"##,
                            y + 13,
                            escape_xml(name),
                        ));
                    }
                }
            }
        }

        // Detector strikes.
        if let Some(json) = ev.detections_json.as_deref() {
            if !json.is_empty() && json != "null" {
                if let Ok(arr) = serde_json::from_str::<Value>(json) {
                    if !arr.as_array().map(Vec::is_empty).unwrap_or(true) {
                        body.push_str(&format!(
                            r##"<rect x="{}" y="{}" width="3" height="20" fill="#ef5454"/>"##,
                            SERVER_X + 14,
                            y - 10,
                        ));
                    }
                }
            }
        }
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {h}" width="{W}" height="{h}" style="background:#0a0d0e;border-radius:4px;">
{body}
</svg>"##
    )
}

fn method_color(method: &str) -> &'static str {
    match method {
        "initialize" => "#7e8b86",
        m if m.starts_with("notifications/") => "#525f5b",
        "tools/list" => "#a8e068",
        "tools/call" => "#f5a25d",
        _ => "#d8e3df",
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(id: i64, ts: i64, session: &str, method: &str, params: Option<&str>) -> RawEventRow {
        RawEventRow {
            id,
            timestamp_ms: ts,
            session_id: session.to_string(),
            method: method.to_string(),
            params: params.map(str::to_string),
            client_name: None,
            client_version: None,
            response_summary: "ok".to_string(),
            transport: Some("http".into()),
            remote_addr: Some("203.0.113.7:54321".into()),
            user_agent: Some("nikto/2.5.0".into()),
            client_meta: None,
            is_operator: false,
            detections_json: None,
        }
    }

    #[test]
    fn escape_xml_handles_all_dangerous_chars() {
        assert_eq!(
            escape_xml(r#"<script>alert("&pwn")</script>"#),
            "&lt;script&gt;alert(&quot;&amp;pwn&quot;)&lt;/script&gt;",
        );
    }

    #[test]
    fn truncate_preserves_short_strings_and_ellipsises_long() {
        assert_eq!(truncate("hello", 10), "hello");
        let long: String = "x".repeat(50);
        let cut = truncate(&long, 10);
        assert!(cut.starts_with("xxxxxxxxxx"));
        assert!(cut.ends_with(" …"));
    }

    #[test]
    fn method_class_for_recognises_mcp_method_families() {
        assert_eq!(method_class_for("initialize"), "initialize");
        assert_eq!(
            method_class_for("notifications/initialized"),
            "notifications"
        );
        assert_eq!(method_class_for("tools/call"), "tools");
        assert_eq!(method_class_for("tools/list"), "tools");
        assert_eq!(method_class_for("resources/read"), "other");
    }

    #[test]
    fn parse_tool_name_only_for_tools_call() {
        assert_eq!(
            parse_tool_name("initialize", Some(r#"{"name":"x"}"#)).0,
            None
        );
        assert_eq!(parse_tool_name("tools/list", None).0, None);
        let (name, _unknown) =
            parse_tool_name("tools/call", Some(r#"{"name":"read_file","arguments":{}}"#));
        assert_eq!(name.as_deref(), Some("read_file"));
    }

    #[test]
    fn parse_tool_name_handles_malformed_params_gracefully() {
        assert_eq!(parse_tool_name("tools/call", Some("{not json")).0, None);
        assert_eq!(
            parse_tool_name("tools/call", Some(r#"{"no_name":true}"#)).0,
            None
        );
    }

    #[test]
    fn parse_detections_returns_empty_for_null_or_empty() {
        assert!(parse_detections(None).is_empty());
        assert!(parse_detections(Some("")).is_empty());
        assert!(parse_detections(Some("null")).is_empty());
    }

    #[test]
    fn parse_detections_extracts_well_formed_array() {
        let json = r#"[{"detector":"shell_injection","severity":"high","category":"command_injection","evidence":"; cat /etc/shadow"}]"#;
        let d = parse_detections(Some(json));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].detector, "shell_injection");
        assert_eq!(d[0].severity, "high");
        assert!(d[0].evidence.contains("/etc/shadow"));
    }

    #[test]
    fn format_relative_buckets_into_human_units() {
        let now = 100_000_000_000_i64;
        assert_eq!(format_relative(now - 30_000, now), "30s ago");
        assert_eq!(format_relative(now - 5 * 60_000, now), "5m ago");
        assert_eq!(format_relative(now - 2 * 3_600_000, now), "2h ago");
        assert_eq!(format_relative(now - 3 * 86_400_000, now), "3d ago");
        // Future timestamps clamp to 0s rather than emit a negative count.
        assert_eq!(format_relative(now + 5_000, now), "0s ago");
    }

    #[test]
    fn format_iso_round_trips_unix_ms() {
        let s = format_iso(1_700_000_000_000);
        assert!(s.contains("2023-11-14"), "got {s}");
        assert!(s.ends_with("Z") || s.contains("+"), "got {s}");
    }

    #[test]
    fn urlencoding_preserves_safe_chars_and_percent_encodes_others() {
        assert_eq!(urlencoding("abc-123_x.y~z"), "abc-123_x.y~z");
        // Slash and colon (the only ones we'd see in real session ids) get encoded.
        assert_eq!(urlencoding("a/b:c"), "a%2Fb%3Ac");
    }

    #[test]
    fn group_into_sessions_orders_by_first_appearance() {
        let rows = vec![
            raw(1, 1_000, "sess-a", "initialize", None),
            raw(2, 2_000, "sess-a", "tools/list", None),
            raw(3, 3_000, "sess-b", "initialize", None),
            raw(
                4,
                4_000,
                "sess-a",
                "tools/call",
                Some(r#"{"name":"read_file"}"#),
            ),
        ];
        let groups = group_into_sessions(rows);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].session_id, "sess-a");
        assert_eq!(groups[0].event_count, 3);
        assert_eq!(groups[1].session_id, "sess-b");
        // Events inside a session render newest-first.
        assert_eq!(groups[0].events[0].method, "tools/call");
    }

    #[test]
    fn render_sequence_svg_carries_all_required_visual_anchors() {
        let rows = vec![
            raw(1, 1_000, "sess-x", "initialize", None),
            raw(
                2,
                2_000,
                "sess-x",
                "tools/call",
                Some(r#"{"name":"read_file"}"#),
            ),
        ];
        let refs: Vec<&RawEventRow> = rows.iter().collect();
        let svg = render_session_sequence_svg("sess-x", &refs);
        assert!(svg.starts_with("<svg"), "missing svg root");
        assert!(svg.contains("sess-x"), "missing session label");
        assert!(svg.contains("attacker"), "missing client lifeline label");
        assert!(svg.contains("honeymcp"), "missing server lifeline label");
        assert!(svg.contains("initialize"), "missing initialize arrow text");
        assert!(svg.contains("tools/call"), "missing tools/call arrow text");
        assert!(svg.contains("read_file"), "missing tool name pill");
    }

    #[test]
    fn render_sequence_svg_emits_detector_strike_when_detections_present() {
        let mut row = raw(1, 1_000, "s", "tools/call", Some(r#"{"name":"x"}"#));
        row.detections_json = Some(
            r#"[{"detector":"shell_injection","severity":"high","category":"command_injection","evidence":";"}]"#
                .into(),
        );
        let refs = vec![&row];
        let svg = render_session_sequence_svg("s", &refs);
        // The strike is a red rect on the right margin; colour is fixed in render().
        assert!(svg.contains("fill=\"#ef5454\""), "missing detector strike");
    }

    #[test]
    fn resolve_client_ip_prefers_xff_leftmost_over_socket_peer() {
        let mut row = raw(1, 0, "s", "initialize", None);
        row.client_meta = Some(r#"{"x_forwarded_for":"203.0.113.7, 10.0.0.1"}"#.into());
        row.remote_addr = Some("127.0.0.1:1234".into());
        assert_eq!(resolve_client_ip(&row), "203.0.113.7");
    }

    #[test]
    fn resolve_client_ip_falls_back_to_remote_addr_without_port() {
        let mut row = raw(1, 0, "s", "initialize", None);
        row.client_meta = None;
        row.remote_addr = Some("198.51.100.42:51000".into());
        assert_eq!(resolve_client_ip(&row), "198.51.100.42");
    }

    #[test]
    fn resolve_client_ip_handles_ipv6_brackets() {
        let mut row = raw(1, 0, "s", "initialize", None);
        row.client_meta = None;
        row.remote_addr = Some("[2001:db8::1]:443".into());
        assert_eq!(resolve_client_ip(&row), "2001:db8::1");
    }
}
