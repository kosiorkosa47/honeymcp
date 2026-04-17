//! Minimal JSON-RPC 2.0 types.
//!
//! Spec: https://www.jsonrpc.org/specification

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC request ID can be a string, a number, or null (for notifications the field is
/// omitted entirely).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
}

/// An incoming JSON-RPC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Missing `id` means the message is a notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
}

impl JsonRpcRequest {
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A JSON-RPC response. Exactly one of `result` / `error` must be present when serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: RequestId,
}

impl JsonRpcResponse {
    pub fn ok(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn err(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Standard JSON-RPC 2.0 error codes.
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum ErrorCode {
    ParseError = -32700,
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParams = -32602,
    InternalError = -32603,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_request_with_numeric_id() {
        let raw = r#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "ping");
        assert!(matches!(req.id, Some(RequestId::Number(1))));
        assert!(!req.is_notification());
    }

    #[test]
    fn notification_has_no_id() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert!(req.is_notification());
    }

    #[test]
    fn response_ok_serialization_has_no_error_field() {
        let resp = JsonRpcResponse::ok(RequestId::Number(5), serde_json::json!({"ok": true}));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains(r#""result":{"ok":true}"#));
        assert!(!s.contains("error"));
    }

    #[test]
    fn response_err_has_no_result_field() {
        let err = JsonRpcError::new(ErrorCode::MethodNotFound, "unknown");
        let resp = JsonRpcResponse::err(RequestId::String("abc".into()), err);
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains(r#""error":"#));
        assert!(!s.contains(r#""result":"#));
    }
}
