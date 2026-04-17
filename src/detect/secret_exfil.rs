//! Credential / secret exfiltration targets.
//!
//! Flags tool calls whose arguments reference paths or keys that only have value to
//! an attacker (SSH keys, cloud creds, `.env`, access tokens). This is the single
//! highest-signal rule in the honeypot because no legitimate agent turn should be
//! asking a random MCP server for `id_rsa`.

use regex::Regex;
use std::sync::OnceLock;

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct SecretExfilDetector;

fn pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?ix)
            (
                \.env(?:\.[a-z0-9_-]+)?\b
              | \.git/config\b
              | \.git-credentials\b
              | id_rsa(\.pub)?\b
              | id_ed25519(\.pub)?\b
              | id_ecdsa(\.pub)?\b
              | \.ssh/authorized_keys\b
              | \.ssh/known_hosts\b
              | aws[_-]?access[_-]?key[_-]?id\b
              | aws[_-]?secret[_-]?access[_-]?key\b
              | \.aws/credentials\b
              | \.aws/config\b
              | access[_-]?token\b
              | bearer\s{1,4}[a-z0-9\-_.]{10,256}
              | gh[pousr]_[a-z0-9]{20,80}         # GitHub token formats
              | sk-[a-z0-9]{20,80}                 # OpenAI-style key
              | sk-ant-[a-z0-9\-_]{20,120}         # Anthropic key prefix
              | glpat-[a-z0-9_-]{20,80}            # GitLab PAT
              | xox[baprs]-[a-z0-9-]{10,80}        # Slack token
              | AKIA[0-9A-Z]{16}                   # AWS access key id format
              | ASIA[0-9A-Z]{16}                   # AWS STS
              | /etc/passwd\b
              | /etc/shadow\b
              | /etc/group\b
              | /proc/self/environ\b
              | /proc/[0-9]+/environ\b
              | \.kube/config\b
              | \.kubeconfig\b
              | kubeconfig\.yaml\b
              | docker[-_]?config\.json\b
              | \.npmrc\b
              | \.pypirc\b
              | \.dockercfg\b
              | credentials\.json\b
              | service[-_]?account\.json\b
              | -----BEGIN\s{1,4}(?:RSA|OPENSSH|EC|DSA|PRIVATE)[\s\w]{0,40}PRIVATE\s{1,4}KEY-----
            )
            ",
        )
        .expect("secret exfil regex")
    })
}

impl Detector for SecretExfilDetector {
    fn name(&self) -> &'static str {
        "secret_exfil_targets"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::SecretExfil
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let params = ctx.entry.params.as_ref()?;
        let body = params.to_string();
        let m = pattern().find(&body)?;
        Some(Detection {
            detector: "secret_exfil_targets",
            category: DetectionCategory::SecretExfil,
            severity: Severity::Critical,
            evidence: m.as_str().to_string(),
            notes: Some(format!("method={}", ctx.entry.method)),
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
    fn triggers_on_dot_env() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"/app/.env"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_github_token_in_argument() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"auth","arguments":{"token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn negative_ordinary_path() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"docs/architecture.md"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_none());
    }

    #[test]
    fn triggers_on_etc_passwd() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"read_file","arguments":{"path":"/etc/passwd"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_anthropic_api_key() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"auth","arguments":{"key":"sk-ant-api01-abcdefghijklmnopqrstuvwxyz0123456789"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_aws_akia_literal_in_payload() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"deploy","arguments":{"cred":"AKIAIOSFODNN7EXAMPLE"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_inline_private_key_header() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"note","arguments":{"body":"-----BEGIN RSA PRIVATE KEY-----"}}),
        );
        assert!(SecretExfilDetector.analyze(&ctx(&e, &s)).is_some());
    }
}
