//! AWS tool-intent classifier.
//!
//! Labels `tools/call` invocations by what they would do on a real cloud
//! account — credential access (Secrets Manager / SSM reads, IAM key creation,
//! STS AssumeRole, S3 object pulls) versus discovery (account / infrastructure
//! enumeration). This turns "an attacker poked the AWS persona" into a typed
//! signal with a cloud ATT&CK mapping, on top of the path/keyword detectors.

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct AwsIntentDetector;

impl Detector for AwsIntentDetector {
    fn name(&self) -> &'static str {
        "aws_intent"
    }

    fn category(&self) -> DetectionCategory {
        // Reported per-call; this is the detector's nominal bucket.
        DetectionCategory::SecretExfil
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        if ctx.entry.method != "tools/call" {
            return None;
        }
        let name = ctx.entry.params.as_ref()?.get("name")?.as_str()?;

        let (severity, category, note, mitre): (
            Severity,
            DetectionCategory,
            &'static str,
            &'static [&'static str],
        ) = match name {
            "get_secret_value" | "get_ssm_parameter" => (
                Severity::Critical,
                DetectionCategory::SecretExfil,
                "secrets-manager / SSM parameter read",
                &["T1552", "T1555.006"],
            ),
            "create_access_key" => (
                Severity::Critical,
                DetectionCategory::SecretExfil,
                "IAM long-lived access-key creation",
                &["T1098.001", "T1078.004"],
            ),
            "assume_role" => (
                Severity::High,
                DetectionCategory::SecretExfil,
                "STS AssumeRole credential request",
                &["T1548", "T1078.004"],
            ),
            "s3_get_object" => (
                Severity::High,
                DetectionCategory::SecretExfil,
                "S3 object download",
                &["T1530"],
            ),
            "read_file" => (
                Severity::High,
                DetectionCategory::SecretExfil,
                "host file read via cloud-ops persona",
                &["T1552.001"],
            ),
            "list_secrets"
            | "list_iam_users"
            | "list_s3_buckets"
            | "describe_instances"
            | "get_caller_identity" => (
                Severity::Medium,
                DetectionCategory::Recon,
                "cloud infrastructure / account discovery",
                &["T1580", "T1087.004"],
            ),
            _ => return None,
        };

        Some(Detection {
            detector: "aws_intent",
            category,
            severity,
            evidence: name.to_string(),
            notes: Some(note.to_string()),
            mitre_techniques: mitre,
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
    fn flags_get_secret_value_as_critical_secret_exfil() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"get_secret_value","arguments":{"secret_id":"prod/iam/deploy-keys"}}),
        );
        let d = AwsIntentDetector.analyze(&ctx(&e, &s)).unwrap();
        assert_eq!(d.severity, Severity::Critical);
        assert_eq!(d.category, DetectionCategory::SecretExfil);
        assert!(!d.mitre_techniques.is_empty());
    }

    #[test]
    fn flags_discovery_tools_as_recon() {
        let s = SessionStats::default();
        let e = make_entry("tools/call", json!({"name":"list_secrets","arguments":{}}));
        let d = AwsIntentDetector.analyze(&ctx(&e, &s)).unwrap();
        assert_eq!(d.category, DetectionCategory::Recon);
    }

    #[test]
    fn ignores_unknown_tools_and_non_calls() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"search_documentation","arguments":{}}),
        );
        assert!(AwsIntentDetector.analyze(&ctx(&e, &s)).is_none());
        let e2 = make_entry("tools/list", json!({}));
        assert!(AwsIntentDetector.analyze(&ctx(&e2, &s)).is_none());
    }
}
