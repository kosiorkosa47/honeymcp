//! MCP protocol types and JSON-RPC 2.0 framing.

pub mod jsonrpc;
pub mod mcp;

pub use jsonrpc::{ErrorCode, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId};
pub use mcp::{
    ClientInfo, InitializeParams, InitializeResult, ServerCapabilities, ServerInfo, Tool,
    ToolCallParams, ToolCallResult, ToolContent, ToolsListResult, PROTOCOL_VERSION,
};
