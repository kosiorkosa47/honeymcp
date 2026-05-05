//! Property: the JSON-RPC parser never panics, regardless of input.
//!
//! Why this is load-bearing for a honeypot: the parser is the first line of
//! code attacker bytes touch. A panic here = process death = honeypot
//! offline = corpus loss. We accept "Result::Err" for any malformed input,
//! never an unwind.

use honeymcp::protocol::JsonRpcRequest;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        // 1024 cases per CI run; high enough to catch the obvious classes
        // (UTF-8 boundary cases, deeply nested arrays, alternating quotes)
        // and low enough to keep the property suite under 10 seconds.
        cases: 1024,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        // We don't care whether the input parses; we only care that no
        // input causes an unwind across the FFI-shaped boundary the parser
        // sits on. serde_json::from_slice returns Result, so a Result::Err
        // is the expected outcome for the vast majority of cases.
        let _ = serde_json::from_slice::<JsonRpcRequest>(&bytes);
    }

    /// Arbitrary UTF-8 strings never panic the parser.
    #[test]
    fn arbitrary_utf8_never_panics(s in ".{0,4096}") {
        let _ = serde_json::from_str::<JsonRpcRequest>(&s);
    }

    /// Deeply nested JSON arrays never panic before the recursion limit
    /// kicks in. serde_json caps at 128 levels; anything deeper should
    /// return Err, never overflow the stack.
    #[test]
    fn deeply_nested_arrays_return_err_not_panic(depth in 0usize..2048) {
        let mut s = String::with_capacity(depth * 2);
        for _ in 0..depth {
            s.push('[');
        }
        for _ in 0..depth {
            s.push(']');
        }
        let _ = serde_json::from_str::<JsonRpcRequest>(&s);
    }

    /// Well-formed but semantically nonsensical JSON-RPC (wrong jsonrpc
    /// version, missing method, etc.) returns Err rather than panicking
    /// inside any custom Deserialize impls we ship.
    #[test]
    fn well_formed_json_garbage_method(method in ".{0,256}", jsonrpc in ".{0,16}") {
        let envelope = serde_json::json!({
            "jsonrpc": jsonrpc,
            "method": method,
            "id": 1,
        });
        let _ = serde_json::from_value::<JsonRpcRequest>(envelope);
    }
}
