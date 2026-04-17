//! Transport layer for MCP. Stdio today; HTTP/SSE in a future iteration.

pub mod stdio;

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use async_trait::async_trait;

/// A transport reads incoming JSON-RPC requests and writes responses. Separating the trait
/// from the concrete implementation lets us swap stdio for HTTP/SSE without touching the
/// dispatch logic.
#[async_trait]
pub trait Transport: Send {
    async fn recv(&mut self) -> anyhow::Result<Option<JsonRpcRequest>>;
    async fn send(&mut self, response: &JsonRpcResponse) -> anyhow::Result<()>;
}
