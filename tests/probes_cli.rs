//! Integration tests for the `honeymcp-probes` binary.
//!
//! These spin up a wiremock HTTP server, run the compiled binary against it,
//! and assert that the JSON report matches the expected outcome semantics.
//!
//! They cover the cases that previously produced false positives:
//!   * JSON-RPC error body under HTTP 200 must be `rejected_rpc_error`, not `accepted`.
//!   * HTTP 429 must be `rate_limited`, not `accepted`.
//!   * HTTP 401 must be `auth_required`.
//!   * `--fail-on-critical` must not fail when the target only returned
//!     JSON-RPC error bodies (honest server case).

use std::process::Command;

use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn bin_path() -> String {
    // `cargo test` builds test binaries and the project bins into the same
    // target directory. We rely on `CARGO_BIN_EXE_honeymcp-probes` being
    // provided by cargo when the test is declared in Cargo.toml's
    // auto-discovered tests/.
    env!("CARGO_BIN_EXE_honeymcp-probes").to_string()
}

async fn run_probes(target: &str, extra: &[&str]) -> (std::process::Output, Value) {
    let mut cmd = Command::new(bin_path());
    cmd.args([
        "--target",
        target,
        "--json",
        "--timeout",
        "3",
        "--skip-handshake",
        "--category",
        "prompt-injection",
    ]);
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd.output().expect("failed to spawn probes binary");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("probes did not emit JSON: {e}\nstdout: {stdout}"));
    (out, doc)
}

fn outcomes(doc: &Value) -> Vec<String> {
    doc["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["outcome"].as_str().unwrap_or("").to_string())
        .collect()
}

fn accepted_flags(doc: &Value) -> Vec<bool> {
    doc["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["accepted"].as_bool().unwrap_or(false))
        .collect()
}

#[tokio::test]
async fn honest_server_returning_rpc_errors_is_not_accepted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"unknown tool"},"id":1}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    let target = format!("{}/message", server.uri());
    let (out, doc) = run_probes(&target, &[]).await;

    assert!(
        out.status.success(),
        "probes exited non-zero without --fail-on-critical: {:?}",
        out.status
    );
    let outs = outcomes(&doc);
    assert!(
        outs.iter().all(|o| o == "rejected_rpc_error"),
        "expected all rejected_rpc_error, got {outs:?}"
    );
    let flags = accepted_flags(&doc);
    assert!(
        flags.iter().all(|b| !b),
        "no probe should be accepted against an honest server"
    );
}

#[tokio::test]
async fn vulnerable_server_returning_rpc_result_is_accepted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"ok"}]},"id":1}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    let target = format!("{}/message", server.uri());
    let (_out, doc) = run_probes(&target, &[]).await;
    let outs = outcomes(&doc);
    assert!(
        outs.iter().all(|o| o == "accepted"),
        "expected all accepted, got {outs:?}"
    );
}

#[tokio::test]
async fn rate_limited_responses_are_not_accepted() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(429).set_body_string("too many"))
        .mount(&server)
        .await;

    let target = format!("{}/message", server.uri());
    let (_out, doc) = run_probes(&target, &[]).await;
    let outs = outcomes(&doc);
    assert!(
        outs.iter().all(|o| o == "rate_limited"),
        "expected all rate_limited, got {outs:?}"
    );
}

#[tokio::test]
async fn auth_required_is_reported_separately() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let target = format!("{}/message", server.uri());
    let (_out, doc) = run_probes(&target, &[]).await;
    let outs = outcomes(&doc);
    assert!(
        outs.iter().all(|o| o == "auth_required"),
        "expected all auth_required, got {outs:?}"
    );
}

#[tokio::test]
async fn fail_on_critical_ignores_rpc_errors() {
    // Honest server returns JSON-RPC errors for every probe. Even with
    // --fail-on-critical the exit code must be 0, otherwise the CI gate
    // would break every honest MCP server that rejects unknown tools.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":1}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    let target = format!("{}/message", server.uri());
    let out = Command::new(bin_path())
        .args([
            "--target",
            &target,
            "--json",
            "--timeout",
            "3",
            "--skip-handshake",
            "--category",
            "secret-exfil",
            "--fail-on-critical",
        ])
        .output()
        .expect("failed to spawn probes binary");
    assert!(
        out.status.success(),
        "fail-on-critical should NOT fire on rpc-error-only responses; got {:?}",
        out.status
    );
}

#[tokio::test]
async fn bearer_token_is_forwarded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/message"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer test-token-123",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"jsonrpc":"2.0","result":{},"id":1}"#,
            "application/json",
        ))
        .mount(&server)
        .await;

    // No fallback mock on 404 -> wiremock returns 404 if the bearer matcher
    // does not match, and our probe classifies that as http_error.
    let target = format!("{}/message", server.uri());
    let out = Command::new(bin_path())
        .args([
            "--target",
            &target,
            "--json",
            "--timeout",
            "3",
            "--skip-handshake",
            "--category",
            "prompt-injection",
            "--bearer",
            "test-token-123",
        ])
        .output()
        .expect("failed to spawn probes binary");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("probes did not emit JSON");
    let outs = outcomes(&doc);
    assert!(
        outs.iter().all(|o| o == "accepted"),
        "bearer token should have reached the server; got outcomes {outs:?}"
    );
}
