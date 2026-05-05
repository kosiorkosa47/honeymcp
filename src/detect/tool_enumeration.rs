//! Tool-enumeration detector.
//!
//! A legitimate MCP client typically calls 1-3 distinct tool names per session.
//! Scanners and agent-exploit frameworks try many different tools in rapid
//! succession to find one that leaks data or executes code. When the per-session
//! `tools_call_count` exceeds a small ceiling we flag it. This is a low-severity
//! signal on its own, but combined with Recon / SecretExfil it strongly indicates
//! automated probing.

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct ToolEnumerationDetector;

const ENUMERATION_THRESHOLD: u32 = 6;

impl Detector for ToolEnumerationDetector {
    fn name(&self) -> &'static str {
        "tool_enumeration"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::Recon
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        if ctx.entry.method != "tools/call" {
            return None;
        }
        if ctx.stats.tools_call_count < ENUMERATION_THRESHOLD {
            return None;
        }
        Some(Detection {
            detector: "tool_enumeration",
            category: DetectionCategory::Recon,
            severity: Severity::Medium,
            evidence: format!(
                "{} tools/call invocations in session",
                ctx.stats.tools_call_count
            ),
            notes: Some("legitimate clients stay under 3 distinct tools per session".into()),
            // T1518: Software Discovery — calling many distinct tools in one
            // session is the MCP-shaped equivalent of mapping installed
            // capabilities. T1083 added because some tools wrap filesystem
            // primitives (read/list/grep style).
            mitre_techniques: &["T1518", "T1083"],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{ctx, make_entry};
    use crate::detect::SessionStats;
    use serde_json::json;

    #[test]
    fn triggers_over_threshold() {
        let stats = SessionStats {
            calls_in_session: 12,
            tools_list_count: 1,
            tools_call_count: 8,
        };
        let e = make_entry("tools/call", json!({"name": "whoami"}));
        assert!(ToolEnumerationDetector.analyze(&ctx(&e, &stats)).is_some());
    }

    #[test]
    fn negative_under_threshold() {
        let stats = SessionStats {
            calls_in_session: 4,
            tools_list_count: 1,
            tools_call_count: 3,
        };
        let e = make_entry("tools/call", json!({"name": "query"}));
        assert!(ToolEnumerationDetector.analyze(&ctx(&e, &stats)).is_none());
    }

    #[test]
    fn negative_on_non_tools_call_method() {
        let stats = SessionStats {
            calls_in_session: 20,
            tools_list_count: 10,
            tools_call_count: 10,
        };
        let e = make_entry("tools/list", json!(null));
        assert!(ToolEnumerationDetector.analyze(&ctx(&e, &stats)).is_none());
    }
}
