//! Transport layer for MCP.
//!
//! The `Transport` trait owns the event loop — it reads JSON-RPC frames from whatever
//! substrate (stdio, HTTP, …) and delegates each one to a shared [`Handler`]. The handler
//! is transport-agnostic, so adding a new wire protocol means implementing `Transport`
//! without touching dispatch logic.

pub mod stdio;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};

/// Per-request context supplied by the transport to the handler. Threads the metadata
/// that's only observable at the transport layer (remote address, User-Agent, session id
/// from a header, etc.) into the dispatcher so it can be logged alongside the request.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub session_id: String,
    pub transport: &'static str,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub client_meta: Option<Value>,
}

impl RequestContext {
    pub fn new(session_id: impl Into<String>, transport: &'static str) -> Self {
        Self {
            session_id: session_id.into(),
            transport,
            remote_addr: None,
            user_agent: None,
            client_meta: None,
        }
    }
}

/// Transport-independent request handler. Returns `None` for notifications.
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle_request(
        &self,
        req: JsonRpcRequest,
        ctx: RequestContext,
    ) -> Option<JsonRpcResponse>;
}

/// A transport drives the event loop: pull requests, dispatch to handler, write responses.
#[async_trait]
pub trait Transport: Send {
    async fn run(&mut self, handler: Arc<dyn Handler>) -> anyhow::Result<()>;
}
