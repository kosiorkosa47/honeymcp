//! Line-delimited JSON-RPC over stdin/stdout.
//!
//! MCP uses newline-delimited JSON on stdio transports. Each frame is a single JSON value
//! terminated by `\n`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::transport::Transport;

pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    line: String,
}

impl StdioTransport<tokio::io::Stdin, tokio::io::Stdout> {
    pub fn from_std() -> Self {
        Self::new(tokio::io::stdin(), tokio::io::stdout())
    }
}

impl<R, W> StdioTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            line: String::new(),
        }
    }
}

#[async_trait]
impl<R, W> Transport for StdioTransport<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn recv(&mut self) -> Result<Option<JsonRpcRequest>> {
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
            // Peer emitted a blank line — treat it as "keep reading" by tail-recursing via a
            // loop. Simpler than pushing the caller to retry.
            return Box::pin(self.recv()).await;
        }
        let req: JsonRpcRequest = serde_json::from_str(trimmed)
            .with_context(|| format!("parsing JSON-RPC frame: {trimmed}"))?;
        Ok(Some(req))
    }

    async fn send(&mut self, response: &JsonRpcResponse) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{JsonRpcResponse, RequestId};
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_single_request_response() {
        let (mut client_side, server_side) = duplex(4096);
        let (server_read, mut server_write) = tokio::io::split(server_side);

        // Spawn server half on the duplex — it reads requests and echoes a simple response.
        let server = tokio::spawn(async move {
            let mut t = StdioTransport::new(server_read, &mut server_write);
            let req = t.recv().await.unwrap().expect("got request");
            assert_eq!(req.method, "ping");
            let resp = JsonRpcResponse::ok(
                req.id.unwrap_or(RequestId::Null),
                serde_json::json!({"pong": true}),
            );
            t.send(&resp).await.unwrap();
        });

        // Client writes one frame, reads one frame.
        use tokio::io::AsyncWriteExt;
        client_side
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":42}\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(client_side);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: JsonRpcResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(matches!(resp.id, RequestId::Number(42)));
        assert_eq!(resp.result.unwrap(), serde_json::json!({"pong": true}));

        server.await.unwrap();
    }
}
