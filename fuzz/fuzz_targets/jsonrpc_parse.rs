//! Fuzz target for the JSON-RPC envelope parser.
//!
//! Why: the parser is the first line of code attacker bytes touch on a live
//! honeymcp instance. proptest covers structured shapes; libfuzzer drives a
//! coverage-guided exploration that finds whatever proptest's strategies
//! miss. A panic here = process death = honeypot offline = corpus loss, so
//! the contract under fuzz is the same as under proptest: bytes go in,
//! Result comes out, no unwind.
//!
//! Run locally:
//!   cargo +nightly fuzz run jsonrpc_parse -- -max_total_time=60

#![no_main]

use honeymcp::protocol::JsonRpcRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // serde_json::from_slice is the hot path that dispatcher.rs calls on
    // every incoming HTTP body. We don't care whether it parses; we care
    // that the worst attacker-crafted bytes don't crash the runtime.
    let _ = serde_json::from_slice::<JsonRpcRequest>(data);
});
