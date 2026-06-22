//! Cloud instance metadata (IMDS) SSRF targets.
//!
//! Fires when a tool argument references a cloud metadata endpoint. Hitting the
//! link-local metadata service is the canonical way to turn a server-side
//! request into stolen instance credentials, so any reference to one from an
//! MCP tool call is high-confidence credential theft — there is no legitimate
//! reason for an agent to ask a random MCP server to fetch `169.254.169.254`.

use regex::Regex;
use std::sync::OnceLock;

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct SsrfImdsDetector;

fn pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)
            (
                169\.254\.169\.254          # AWS / Azure / GCP IMDS
              | metadata\.google\.internal  # GCP metadata DNS name
              | 169\.254\.170\.2            # ECS task metadata
              | 100\.100\.100\.200          # Alibaba Cloud metadata
              | metadata\.azure\.com
              | fd00:ec2::254               # AWS IMDSv6
            )
            ",
        )
        .expect("imds ssrf regex")
    })
}

impl Detector for SsrfImdsDetector {
    fn name(&self) -> &'static str {
        "ssrf_imds"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::SecretExfil
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let params = ctx.entry.params.as_ref()?;
        let body = params.to_string();
        let m = pattern().find(&body)?;
        Some(Detection {
            detector: "ssrf_imds",
            category: DetectionCategory::SecretExfil,
            severity: Severity::Critical,
            evidence: m.as_str().to_string(),
            notes: Some("cloud instance metadata endpoint (credential theft via SSRF)".into()),
            // T1552.005: Unsecured Credentials — Cloud Instance Metadata API.
            // T1552: Unsecured Credentials (parent).
            mitre_techniques: &["T1552.005", "T1552"],
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
    fn triggers_on_aws_imds_ip() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"fetch_url","arguments":{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}),
        );
        assert!(SsrfImdsDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_gcp_metadata_name() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_url","arguments":{"url":"http://metadata.google.internal/computeMetadata/v1/"}}),
        );
        assert!(SsrfImdsDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn negative_ordinary_url() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"fetch","arguments":{"url":"https://api.acme-corp.com/v1/health"}}),
        );
        assert!(SsrfImdsDetector.analyze(&ctx(&e, &s)).is_none());
    }
}
