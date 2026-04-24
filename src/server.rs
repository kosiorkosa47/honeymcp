//! Dispatch layer: turns a JSON-RPC request + transport context into a response, and logs
//! the interaction.
//!
//! One `Dispatcher` is shared across all sessions (it owns the persona and logger). Per-
//! session mutable state (e.g. the client name captured during `initialize`) lives in a
//! small per-session record keyed by `RequestContext::session_id`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, info, instrument, warn};

use crate::detect::{DetectionContext, Registry, SessionStats};
use crate::logger::{hash_params, now_ms, LogEntry, Logger};
use crate::persona::Persona;
use crate::protocol::{
    ErrorCode, InitializeParams, InitializeResult, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
    RequestId, ServerCapabilities, ToolCallParams, ToolCallResult, ToolsCapability,
    ToolsListResult, PROTOCOL_VERSION,
};
use crate::transport::{Handler, RequestContext};

#[derive(Default, Clone, Debug)]
pub struct SessionState {
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub stats: SessionStats,
}

pub struct Dispatcher {
    persona: Arc<Persona>,
    logger: Logger,
    registry: Arc<Registry>,
    sessions: Mutex<HashMap<String, Arc<Mutex<SessionState>>>>,
}

impl Dispatcher {
    pub fn new(persona: Persona, logger: Logger) -> Self {
        Self::with_registry(persona, logger, Registry::default_enabled())
    }

    pub fn with_registry(persona: Persona, logger: Logger, registry: Registry) -> Self {
        Self {
            persona: Arc::new(persona),
            logger,
            registry: Arc::new(registry),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn persona(&self) -> &Persona {
        &self.persona
    }

    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    async fn session_state(&self, id: &str) -> Arc<Mutex<SessionState>> {
        let mut sessions = self.sessions.lock().await;
        sessions
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(SessionState::default())))
            .clone()
    }

    fn on_initialize(
        &self,
        req: &JsonRpcRequest,
        state: &mut SessionState,
    ) -> (String, Option<JsonRpcResponse>) {
        let id = match req.id.clone() {
            Some(id) => id,
            None => return ("initialize-without-id".into(), None),
        };
        let parsed: Result<InitializeParams, _> = match &req.params {
            Some(p) => serde_json::from_value(p.clone()),
            None => serde_json::from_value(Value::Null),
        };
        if let Ok(p) = &parsed {
            if let Some(ci) = &p.client_info {
                state.client_name = Some(ci.name.clone());
                state.client_version = Some(ci.version.clone());
            }
        }
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            server_info: self.persona.server_info(),
            instructions: self.persona.instructions.clone(),
        };
        let value = serde_json::to_value(&result).unwrap_or(Value::Null);
        (
            format!(
                "initialize ok, client={}",
                state.client_name.as_deref().unwrap_or("?")
            ),
            Some(JsonRpcResponse::ok(id, value)),
        )
    }

    fn on_tools_list(&self, req: &JsonRpcRequest) -> (String, Option<JsonRpcResponse>) {
        let id = match req.id.clone() {
            Some(id) => id,
            None => return ("tools/list-without-id".into(), None),
        };
        let tools = self.persona.mcp_tools();
        let result = ToolsListResult { tools };
        let value = serde_json::to_value(&result).unwrap_or(Value::Null);
        (
            format!("tools/list n={}", self.persona.tools.len()),
            Some(JsonRpcResponse::ok(id, value)),
        )
    }

    fn on_tools_call(&self, req: &JsonRpcRequest) -> (String, Option<JsonRpcResponse>) {
        let id = match req.id.clone() {
            Some(id) => id,
            None => return ("tools/call-without-id".into(), None),
        };
        let params: ToolCallParams = match req.params.clone() {
            Some(v) => match serde_json::from_value(v) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        format!("tools/call bad params: {e}"),
                        Some(JsonRpcResponse::err(
                            id,
                            JsonRpcError::new(ErrorCode::InvalidParams, e.to_string()),
                        )),
                    )
                }
            },
            None => {
                return (
                    "tools/call missing params".into(),
                    Some(JsonRpcResponse::err(
                        id,
                        JsonRpcError::new(ErrorCode::InvalidParams, "missing params"),
                    )),
                )
            }
        };

        match self.persona.response_for(&params.name) {
            Some(content) => {
                let result = ToolCallResult {
                    content: vec![content],
                    is_error: Some(false),
                };
                let value = serde_json::to_value(&result).unwrap_or(Value::Null);
                (
                    format!("tools/call name={}", params.name),
                    Some(JsonRpcResponse::ok(id, value)),
                )
            }
            None => (
                format!("tools/call unknown tool {}", params.name),
                Some(JsonRpcResponse::err(
                    id,
                    JsonRpcError::new(
                        ErrorCode::InvalidParams,
                        format!("unknown tool: {}", params.name),
                    ),
                )),
            ),
        }
    }

    async fn log_interaction(
        &self,
        req: &JsonRpcRequest,
        summary: &str,
        ctx: &RequestContext,
        state: &SessionState,
    ) {
        let ts = now_ms();
        let entry = LogEntry {
            timestamp_ms: ts,
            method: req.method.clone(),
            params_hash: hash_params(&req.params),
            params: req.params.clone(),
            client_name: state.client_name.clone(),
            client_version: state.client_version.clone(),
            session_id: ctx.session_id.clone(),
            response_summary: summary.to_string(),
            transport: Some(ctx.transport.to_string()),
            remote_addr: ctx.remote_addr.clone(),
            user_agent: ctx.user_agent.clone(),
            client_meta: ctx.client_meta.clone(),
        };

        let event_id = match self.logger.record(&entry).await {
            Ok(id) => Some(id),
            Err(e) => {
                warn!(error = %e, "failed to persist log entry");
                None
            }
        };
        debug!(method = %req.method, transport = %ctx.transport, "logged event");

        if let Some(event_id) = event_id {
            if !self.registry.is_empty() {
                let detections = self.registry.analyze_all(&DetectionContext {
                    entry: &entry,
                    stats: &state.stats,
                });
                if !detections.is_empty() {
                    info!(
                        count = detections.len(),
                        method = %req.method,
                        "threat detections fired"
                    );
                    if let Err(e) = self
                        .logger
                        .record_detections(event_id, ts, &detections)
                        .await
                    {
                        warn!(error = %e, "failed to persist detections");
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Handler for Dispatcher {
    // Top-level tracing span for every request. Fields pulled from both the
    // JSON-RPC envelope (method, id) and the transport layer (session_id,
    // transport, remote_addr). The persona name goes on the span so OTEL
    // consumers can group by which honeypot flavour the attacker hit.
    // `skip(self, req)` keeps the giant internal types out of the span
    // attributes without losing the ergonomic parameters.
    #[instrument(
        name = "honeymcp.handle_request",
        skip(self, req),
        fields(
            method = %req.method,
            session_id = %ctx.session_id,
            transport = %ctx.transport,
            persona = %self.persona.name,
            remote_addr = ctx.remote_addr.as_deref().unwrap_or("unknown"),
            user_agent = ctx.user_agent.as_deref().unwrap_or("-"),
        )
    )]
    async fn handle_request(
        &self,
        req: JsonRpcRequest,
        ctx: RequestContext,
    ) -> Option<JsonRpcResponse> {
        let state_lock = self.session_state(&ctx.session_id).await;
        let mut state = state_lock.lock().await;

        // Update per-session stats before dispatch so detectors see the current count.
        state.stats.calls_in_session = state.stats.calls_in_session.saturating_add(1);
        match req.method.as_str() {
            "tools/list" => {
                state.stats.tools_list_count = state.stats.tools_list_count.saturating_add(1)
            }
            "tools/call" => {
                state.stats.tools_call_count = state.stats.tools_call_count.saturating_add(1)
            }
            _ => {}
        }

        let (summary, response) = match req.method.as_str() {
            "initialize" => self.on_initialize(&req, &mut state),
            "tools/list" => self.on_tools_list(&req),
            "tools/call" => self.on_tools_call(&req),
            "notifications/initialized" | "notifications/cancelled" => ("noop".to_string(), None),
            other => (
                format!("method-not-found:{other}"),
                Some(JsonRpcResponse::err(
                    req.id.clone().unwrap_or(RequestId::Null),
                    JsonRpcError::new(
                        ErrorCode::MethodNotFound,
                        format!("unknown method: {other}"),
                    ),
                )),
            ),
        };

        self.log_interaction(&req, &summary, &ctx, &state).await;

        if req.is_notification() {
            return None;
        }

        match response {
            Some(resp) => Some(resp),
            None => req.id.map(|id| {
                warn!(method = %req.method, "handler returned no response for a request");
                JsonRpcResponse::err(
                    id,
                    JsonRpcError::new(ErrorCode::InternalError, "no response"),
                )
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn make_dispatcher() -> (Arc<Dispatcher>, tempfile::TempDir) {
        let persona = Persona::from_yaml_str(
            r#"
name: test
version: "1"
tools:
  - name: echo
    response: "hello"
"#,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        let logger = Logger::open(&db, None).await.unwrap();
        (Arc::new(Dispatcher::new(persona, logger)), dir)
    }

    #[tokio::test]
    async fn initialize_returns_server_info_and_captures_client_info() {
        let (d, _dir) = make_dispatcher().await;
        let ctx = RequestContext::new("s1", "stdio");
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "initialize".into(),
            params: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "attacker", "version": "0.1"}
            })),
            id: Some(RequestId::Number(1)),
        };
        let resp = d.handle_request(req, ctx.clone()).await.expect("response");
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "test");

        let state = d.session_state(&ctx.session_id).await;
        let state = state.lock().await;
        assert_eq!(state.client_name.as_deref(), Some("attacker"));
        assert_eq!(d.logger.count_events().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn tools_call_returns_canned_response() {
        let (d, _dir) = make_dispatcher().await;
        let ctx = RequestContext::new("s1", "stdio");
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "echo", "arguments": {}})),
            id: Some(RequestId::Number(2)),
        };
        let resp = d.handle_request(req, ctx).await.expect("response");
        let result = resp.result.unwrap();
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "hello");
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let (d, _dir) = make_dispatcher().await;
        let ctx = RequestContext::new("s1", "stdio");
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "resources/list".into(),
            params: None,
            id: Some(RequestId::Number(3)),
        };
        let resp = d.handle_request(req, ctx).await.expect("response");
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, ErrorCode::MethodNotFound as i32);
    }
}
