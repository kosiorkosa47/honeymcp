//! Line-delimited JSON-RPC over stdin/stdout.
//!
//! MCP uses newline-delimited JSON on stdio transports. Each frame is a single JSON value
//! terminated by `\n`.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::transport::{Handler, RequestContext, Transport};

pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    line: String,
    session_id: String,
}

impl StdioTransport<tokio::io::Stdin, tokio::io::Stdout> {
    pub fn from_std(session_id: String) -> Self {
        Self::new(tokio::io::stdin(), tokio::io::stdout(), session_id)
    }
}

impl<R, W> StdioTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: R, writer: W, session_id: String) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            line: String::new(),
            session_id,
        }
    }

    async fn read_frame(&mut self) -> Result<Option<JsonRpcRequest>> {
        loop {
            self.line.clear();
            let n = self
                .reader
                .read_line(&mut self.line)
                .await
                .context("reading JSON-RPC frame from stdin")?;
            if n == 0 {
                return Ok(None);
            }
            let trimmed = self.line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let req: JsonRpcRequest = serde_json::from_str(trimmed)
                .with_context(|| format!("parsing JSON-RPC frame: {trimmed}"))?;
            return Ok(Some(req));
        }
    }

    async fn write_frame(&mut self, response: &JsonRpcResponse) -> Result<()> {
        let mut buf = serde_json::to_vec(response).context("serializing JSON-RPC response")?;
        buf.push(b'\n');
        self.writer
            .write_all(&buf)
            .await
            .context("writing JSON-RPC response")?;
        self.writer.flush().await.context("flushing stdout")?;
        Ok(())
    }
}

#[async_trait]
impl<R, W> Transport for StdioTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn run(&mut self, handler: Arc<dyn Handler>) -> Result<()> {
        while let Some(req) = self.read_frame().await? {
            let ctx = RequestContext::new(self.session_id.clone(), "stdio");
            if let Some(resp) = handler.handle_request(req, ctx).await {
                self.write_frame(&resp).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcRequest, JsonRpcResponse, RequestId};
    use async_trait::async_trait;
    use tokio::io::duplex;

    struct PongHandler;

    #[async_trait]
    impl Handler for PongHandler {
        async fn handle_request(
            &self,
            req: JsonRpcRequest,
            _ctx: RequestContext,
        ) -> Option<JsonRpcResponse> {
            assert_eq!(req.method, "ping");
            Some(JsonRpcResponse::ok(
                req.id.unwrap_or(RequestId::Null),
                serde_json::json!({"pong": true}),
            ))
        }
    }

    #[tokio::test]
    async fn roundtrip_single_request_response() {
        let (mut client_side, server_side) = duplex(4096);
        let (server_read, mut server_write) = tokio::io::split(server_side);

        let server = tokio::spawn(async move {
            let mut t = StdioTransport::new(server_read, &mut server_write, "test".into());
            t.run(Arc::new(PongHandler)).await.unwrap();
        });

        use tokio::io::AsyncWriteExt;
        client_side
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":42}\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(&mut client_side);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: JsonRpcResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(resp.id, RequestId::Number(42)));
        assert_eq!(resp.result.unwrap(), serde_json::json!({"pong": true}));

        // Drop client so server sees EOF and the loop exits cleanly.
        drop(client_side);
        server.await.unwrap();
    }
}
