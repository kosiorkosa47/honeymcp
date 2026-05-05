//! Property: every detector returns cleanly for any input shape.
//!
//! Why: detectors run on attacker-controlled `params`. A panic in any
//! detector means the dispatcher never logs the event, never returns a
//! response, and the operator notices only via crash-loop. The test
//! suite has scripted inputs; this property covers everything outside
//! that scripted set.
//!
//! What it asserts: `Registry::analyze_all` never panics on any
//! serializable JSON value, on any reasonable string method name, with
//! any combination of session-stat counters.

use honeymcp::detect::{DetectionContext, Registry, SessionStats};
use honeymcp::logger::{hash_params, LogEntry};
use proptest::prelude::*;
use serde_json::{json, Value};

/// proptest strategy that produces "json-shaped" values up to a bounded
/// depth. We don't try to cover every Value variant pessimally; the goal
/// is to hit the shapes detectors actually iterate over (objects with
/// nested arrays, strings of varying length).
fn arb_json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        ".{0,256}".prop_map(Value::String),
    ];
    leaf.prop_recursive(
        4,  // max depth
        64, // max total nodes
        16, // max items per collection
        |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..16).prop_map(Value::Array),
                proptest::collection::hash_map(".{0,32}", inner, 0..16)
                    .prop_map(|map| Value::Object(map.into_iter().collect())),
            ]
        },
    )
}

fn make_entry(method: String, params: Value) -> LogEntry {
    LogEntry {
        timestamp_ms: 0,
        method,
        params_hash: hash_params(&Some(params.clone())),
        params: Some(params),
        client_name: Some("prop".into()),
        client_version: Some("0".into()),
        session_id: "prop-session".into(),
        response_summary: String::new(),
        transport: Some("http".into()),
        remote_addr: Some("203.0.113.7:51000".into()),
        user_agent: Some("prop/1.0".into()),
        client_meta: None,
        is_operator: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Detector pipeline is regex-heavy; 256 cases is enough to surface
        // catastrophic-backtracking shapes without making the suite slow.
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Random JSON params, real method name. Detector pipeline must not
    /// panic regardless of how deeply nested or how oddly typed the input is.
    #[test]
    fn analyze_all_never_panics_on_random_params(
        params in arb_json_value(),
        method in proptest::sample::select(vec![
            "initialize".to_string(),
            "tools/list".to_string(),
            "tools/call".to_string(),
            "notifications/initialized".to_string(),
            "ping".to_string(),
        ]),
        calls in 0u32..100,
        list_count in 0u32..100,
        call_count in 0u32..100,
    ) {
        let entry = make_entry(method, params);
        let stats = SessionStats {
            calls_in_session: calls,
            tools_list_count: list_count,
            tools_call_count: call_count,
        };
        let ctx = DetectionContext { entry: &entry, stats: &stats };
        let registry = Registry::default_enabled();
        let _detections = registry.analyze_all(&ctx);
    }

    /// Adversarial method names (long, unicode-heavy, control chars) must
    /// not crash the detectors that look at `entry.method` directly.
    #[test]
    fn analyze_all_never_panics_on_adversarial_method(
        method in ".{0,1024}",
    ) {
        let entry = make_entry(method, json!({}));
        let stats = SessionStats::default();
        let ctx = DetectionContext { entry: &entry, stats: &stats };
        let registry = Registry::default_enabled();
        let _detections = registry.analyze_all(&ctx);
    }

    /// Tools/call with random tool names and random arg shapes — covers
    /// the hot path for production attacker traffic.
    #[test]
    fn tools_call_with_random_arguments_never_panics(
        tool_name in ".{0,128}",
        arguments in arb_json_value(),
    ) {
        let params = json!({"name": tool_name, "arguments": arguments});
        let entry = make_entry("tools/call".into(), params);
        let stats = SessionStats {
            calls_in_session: 1,
            tools_list_count: 0,
            tools_call_count: 1,
        };
        let ctx = DetectionContext { entry: &entry, stats: &stats };
        let registry = Registry::default_enabled();
        let _detections = registry.analyze_all(&ctx);
    }
}
