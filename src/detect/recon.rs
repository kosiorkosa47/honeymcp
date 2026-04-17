//! Recon pattern detector.
//!
//! Fires when a session looks like automated reconnaissance rather than a legitimate
//! agent turn. Two simple shapes:
//!
//! - Many `tools/list` calls in one session (a well-behaved client calls it once).
//! - Bursts of `tools/call` invocations without any `initialize` having completed.
//!
//! Real MCP clients do `initialize` → one `tools/list` → many `tools/call`. Scanners
//! skip the handshake or re-list repeatedly.

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct ReconDetector;

impl Detector for ReconDetector {
    fn name(&self) -> &'static str {
        "recon_pattern"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::Recon
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let stats = ctx.stats;

        // Repeated tools/list in the same session.
        if ctx.entry.method == "tools/list" && stats.tools_list_count >= 3 {
            return Some(Detection {
                detector: "recon_pattern",
                category: DetectionCategory::Recon,
                severity: Severity::Medium,
                evidence: format!(
                    "tools/list issued {} times in session",
                    stats.tools_list_count
                ),
                notes: Some("well-behaved clients call tools/list once".into()),
            });
        }

        // tools/call with no prior initialize (calls_in_session counts *this* event, so
        // look at whether method=tools/call and it's the very first or second in-session
        // message — real clients complete initialize first).
        if ctx.entry.method == "tools/call" && stats.calls_in_session <= 2 {
            return Some(Detection {
                detector: "recon_pattern",
                category: DetectionCategory::Recon,
                severity: Severity::Low,
                evidence: "tools/call before initialize handshake".into(),
                notes: Some(format!("session_calls={}", stats.calls_in_session)),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{ctx, make_entry};
    use crate::detect::SessionStats;
    use serde_json::json;

    #[test]
    fn triggers_on_repeated_tools_list() {
        let stats = SessionStats {
            calls_in_session: 4,
            tools_list_count: 3,
            tools_call_count: 0,
        };
        let e = make_entry("tools/list", json!(null));
        assert!(ReconDetector.analyze(&ctx(&e, &stats)).is_some());
    }

    #[test]
    fn triggers_on_tools_call_before_initialize() {
        let stats = SessionStats {
            calls_in_session: 1,
            tools_list_count: 0,
            tools_call_count: 1,
        };
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"/etc/passwd"}}),
        );
        assert!(ReconDetector.analyze(&ctx(&e, &stats)).is_some());
    }

    #[test]
    fn negative_normal_session() {
        let stats = SessionStats {
            calls_in_session: 5,
            tools_list_count: 1,
            tools_call_count: 2,
        };
        let e = make_entry(
            "tools/call",
            json!({"name":"query","arguments":{"sql":"SELECT 1"}}),
        );
        assert!(ReconDetector.analyze(&ctx(&e, &stats)).is_none());
    }
}
