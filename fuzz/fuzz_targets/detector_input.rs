//! Fuzz target for the detector pipeline.
//!
//! Why: detectors run on attacker-controlled `params`. A panic in any
//! detector crashes the async dispatcher task and stops event logging
//! mid-session. proptest already caught one slice-on-non-char-boundary
//! panic in shell_injection.rs; this target keeps coverage-guided fuzzing
//! on top of that as a permanent regression net.
//!
//! Strategy: feed raw bytes through serde_json::from_slice to get a Value
//! (most fuzz inputs won't parse — that's fine, those iterations exit
//! cheaply), then push the parsed value through Registry::default_enabled
//! exactly the way the dispatcher does. Random method strings come from
//! the same byte stream so the fuzzer can exercise method-string-aware
//! detectors too.
//!
//! Run locally:
//!   cargo +nightly fuzz run detector_input -- -max_total_time=60

#![no_main]

use honeymcp::detect::{DetectionContext, Registry, SessionStats};
use honeymcp::logger::{hash_params, LogEntry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte for method-length prefix + some bytes for the
    // method itself. Below that there's nothing useful to feed the pipeline.
    if data.len() < 2 {
        return;
    }
    let method_len = (data[0] as usize).min(data.len() - 1).min(64);
    let method_bytes = &data[1..1 + method_len];
    let body = &data[1 + method_len..];

    let method = String::from_utf8_lossy(method_bytes).into_owned();
    let params = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v,
        // Most random byte sequences won't parse as JSON. Skip them — the
        // fuzzer learns from coverage and will mutate towards inputs that
        // do parse. We don't want every iteration to bottom out here.
        Err(_) => return,
    };

    let entry = LogEntry {
        timestamp_ms: 0,
        method,
        params_hash: hash_params(&Some(params.clone())),
        params: Some(params),
        client_name: Some("fuzz".into()),
        client_version: Some("0".into()),
        session_id: "fuzz".into(),
        response_summary: String::new(),
        transport: Some("http".into()),
        remote_addr: Some("203.0.113.7:51000".into()),
        user_agent: Some("fuzz/1.0".into()),
        client_meta: None,
        is_operator: false,
    };
    let stats = SessionStats {
        calls_in_session: 1,
        tools_list_count: 0,
        tools_call_count: 1,
    };
    let ctx = DetectionContext { entry: &entry, stats: &stats };
    let registry = Registry::default_enabled();
    let _ = registry.analyze_all(&ctx);
});
