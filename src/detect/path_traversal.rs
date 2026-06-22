//! Path traversal sequences.
//!
//! Flags tool arguments containing `../` / `..\` (or their URL-encoded forms).
//! Complements `secret_exfil`, which matches *known* sensitive paths by name:
//! this catches the traversal *technique* regardless of the final target, so a
//! climb toward an arbitrary file is caught even when the destination isn't on
//! the secret-exfil list.

use regex::Regex;
use std::sync::OnceLock;

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct PathTraversalDetector;

fn pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)
            (
                \.\./                       # ../
              | \.\.\\                      # ..\
              | %2e%2e%2f                   # encoded ../
              | %2e%2e/
              | \.\.%2f
              | %2e%2e%5c                   # encoded ..\
              | \.\.%5c
            )
            ",
        )
        .expect("path traversal regex")
    })
}

impl Detector for PathTraversalDetector {
    fn name(&self) -> &'static str {
        "path_traversal"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::SecretExfil
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let params = ctx.entry.params.as_ref()?;
        let body = params.to_string();
        let m = pattern().find(&body)?;
        Some(Detection {
            detector: "path_traversal",
            category: DetectionCategory::SecretExfil,
            severity: Severity::High,
            evidence: m.as_str().to_string(),
            notes: Some(format!("traversal sequence in {} args", ctx.entry.method)),
            // T1083: File and Directory Discovery.
            // T1006: Direct Volume Access (reading files outside the intended root).
            mitre_techniques: &["T1083", "T1006"],
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
    fn triggers_on_dotdot_slash() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"../../../../etc/shadow"}}),
        );
        assert!(PathTraversalDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_url_encoded_traversal() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"get","arguments":{"path":"%2e%2e%2f%2e%2e%2fboot.ini"}}),
        );
        assert!(PathTraversalDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn negative_plain_path() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"reports/2026/q2.csv"}}),
        );
        assert!(PathTraversalDetector.analyze(&ctx(&e, &s)).is_none());
    }
}
