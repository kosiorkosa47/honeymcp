//! Dispatch layer: takes a JSON-RPC request, produces a response, and logs the interaction.

use anyhow::Result;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::logger::{hash_params, now_ms, LogEntry, Logger};
use crate::persona::Persona;
use crate::protocol::{
    ErrorCode, InitializeParams, InitializeResult, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
    RequestId, ServerCapabilities, ToolCallParams, ToolCallResult, ToolsCapability,
    ToolsListResult, PROTOCOL_VERSION,
};
use crate::transport::Transport;

/// State shared across all requests in a single connection.
pub struct Session {
    pub id: String,
    pub persona: Persona,
    pub logger: Logger,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
}

impl Session {
    pub fn new(id: String, persona: Persona, logger: Logger) -> Self {
        Self {
            id,
            persona,
            logger,
            client_name: None,
            client_version: None,
        }
    }

    /// Main event loop: pull requests off the transport, dispatch, write responses.
    pub async fn run<T: Transport>(&mut self, transport: &mut T) -> Result<()> {
        info!(session = %self.id, persona = %self.persona.name, "session started");
        while let Some(req) = transport.recv().await? {
            let response = self.handle(&req).await;
            // Notifications (no id) get no response — but we still log them.
            if let Some(resp) = response {
                transport.send(&resp).await?;
            }
        }
        info!(session = %self.id, "session ended");
        Ok(())
    }

    async fn handle(&mut self, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
        let id_for_response = req.id.clone();
        let (response, summary) = match req.method.as_str() {
            "initialize" => self.on_initialize(req),
            "tools/list" => self.on_tools_list(req),
            "tools/call" => self.on_tools_call(req),
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

        self.log_interaction(req, &response).await;

        if req.is_notification() {
            return None;
        }

        match summary {
            Some(resp) => Some(resp),
            None => id_for_response.map(|id| {
                warn!(method = %req.method, "handler returned no response for a request");
                JsonRpcResponse::err(
                    id,
                    JsonRpcError::new(ErrorCode::InternalError, "no response"),
                )
            }),
        }
    }

    fn on_initialize(&mut self, req: &JsonRpcRequest) -> (String, Option<JsonRpcResponse>) {
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
                self.client_name = Some(ci.name.clone());
                self.client_version = Some(ci.version.clone());
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
                self.client_name.as_deref().unwrap_or("?")
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

    async fn log_interaction(&self, req: &JsonRpcRequest, summary: &str) {
        let entry = LogEntry {
            timestamp_ms: now_ms(),
            method: req.method.clone(),
            params_hash: hash_params(&req.params),
            params: req.params.clone(),
            client_name: self.client_name.clone(),
            client_version: self.client_version.clone(),
            session_id: self.id.clone(),
            response_summary: summary.to_string(),
        };
        if let Err(e) = self.logger.record(&entry).await {
            warn!(error = %e, "failed to persist log entry");
        } else {
            debug!(method = %req.method, "logged event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persona::Persona;
    use tempfile::tempdir;

    async fn make_session() -> (Session, tempfile::TempDir) {
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
        (Session::new("s1".into(), persona, logger), dir)
    }

    #[tokio::test]
    async fn initialize_returns_server_info_and_logs_event() {
        let (mut s, _dir) = make_session().await;
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
        let resp = s.handle(&req).await.expect("response");
        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "test");
        assert_eq!(s.client_name.as_deref(), Some("attacker"));
        assert_eq!(s.logger.count_events().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn tools_call_returns_canned_response() {
        let (mut s, _dir) = make_session().await;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "echo", "arguments": {}})),
            id: Some(RequestId::Number(2)),
        };
        let resp = s.handle(&req).await.expect("response");
        let result = resp.result.unwrap();
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "hello");
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let (mut s, _dir) = make_session().await;
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "resources/list".into(),
            params: None,
            id: Some(RequestId::Number(3)),
        };
        let resp = s.handle(&req).await.expect("response");
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, ErrorCode::MethodNotFound as i32);
    }
}
