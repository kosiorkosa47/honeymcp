//! Operator-traffic classifier.
//!
//! A honeypot's stats are only useful if they reflect what *the internet*
//! sent, not what the operator sent while validating the deploy. Without
//! this classifier, every `curl /healthz` and every `honeymcp-probes` audit
//! lands in the same `events` table as a real attacker, and `/stats` reports
//! both indistinguishably. Week-one writeups have already been corrected
//! once because of this exact mistake (see `docs/blog/2026-04-24-first-week.md`).
//!
//! Two signals are checked at log time and ANY hit flips `is_operator = true`:
//!
//!   1. `User-Agent` starts with one of `HONEYMCP_OPERATOR_UA_PREFIXES`
//!      (default: `"honeymcp-probes/"`).
//!   2. The resolved remote IP (XFF-aware via `client_meta`, falling back to
//!      socket peer) matches an entry in `HONEYMCP_OPERATOR_IPS` (default:
//!      empty). Comparison is exact-string for now; CIDR can be added when
//!      a real operator needs it.
//!
//! Env-var configurable on purpose: a contributor running honeymcp on their
//! own VPS will have a different operator IP and different probe UA than I
//! do, and the binary should not need a recompile to teach it that.

use serde_json::Value;

/// Configuration for [`OperatorClassifier`]. Cheap to clone; carry one in the
/// dispatcher.
#[derive(Debug, Clone)]
pub struct OperatorClassifier {
    ua_prefixes: Vec<String>,
    ips: Vec<String>,
}

impl Default for OperatorClassifier {
    fn default() -> Self {
        Self {
            ua_prefixes: vec!["honeymcp-probes/".to_string()],
            ips: Vec::new(),
        }
    }
}

impl OperatorClassifier {
    /// Build a classifier from environment.
    ///
    /// - `HONEYMCP_OPERATOR_UA_PREFIXES`: comma-separated UA prefixes that
    ///   tag traffic as operator. Empty / unset falls back to the default
    ///   (`honeymcp-probes/`).
    /// - `HONEYMCP_OPERATOR_IPS`: comma-separated remote IPs that tag traffic
    ///   as operator. Empty / unset means "no IP allowlist".
    ///
    /// Whitespace around values is trimmed; empty entries are dropped.
    pub fn from_env() -> Self {
        let ua_prefixes = parse_csv_env("HONEYMCP_OPERATOR_UA_PREFIXES")
            .unwrap_or_else(|| vec!["honeymcp-probes/".to_string()]);
        let ips = parse_csv_env("HONEYMCP_OPERATOR_IPS").unwrap_or_default();
        Self { ua_prefixes, ips }
    }

    /// Decide whether the given request is operator traffic.
    ///
    /// `client_meta` is consulted for `x_forwarded_for` so traffic that
    /// reaches the binary through a Caddy / nginx reverse proxy is classified
    /// against the *client* IP, not the proxy's `127.0.0.1`. The first
    /// non-empty entry of the XFF list wins, matching the real-IP convention
    /// already used by [`crate::transport::http::remote_addr_from`].
    pub fn classify(
        &self,
        user_agent: Option<&str>,
        remote_addr: Option<&str>,
        client_meta: Option<&Value>,
    ) -> bool {
        if let Some(ua) = user_agent {
            if self.ua_prefixes.iter().any(|p| ua.starts_with(p)) {
                return true;
            }
        }

        let candidate_ip = client_meta
            .and_then(|m| m.get("x_forwarded_for"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                remote_addr.map(|a| {
                    // remote_addr can be `1.2.3.4:5678`; strip the port for IP
                    // comparison. IPv6 addresses without a port are kept whole.
                    a.rsplit_once(':')
                        .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
                        .unwrap_or(a)
                        .to_string()
                })
            });

        if let Some(ip) = candidate_ip {
            if self.ips.iter().any(|allow| allow == &ip) {
                return true;
            }
        }

        false
    }
}

fn parse_csv_env(name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(name).ok()?;
    let parts: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_match_probe_user_agent() {
        let c = OperatorClassifier::default();
        assert!(c.classify(Some("honeymcp-probes/0.5.0"), None, None));
        assert!(!c.classify(Some("curl/8.7.1"), None, None));
    }

    #[test]
    fn ip_allowlist_matches_direct_remote_addr_with_port() {
        let c = OperatorClassifier {
            ua_prefixes: vec![],
            ips: vec!["203.0.113.7".into()],
        };
        assert!(c.classify(None, Some("203.0.113.7:51000"), None));
        assert!(!c.classify(None, Some("198.51.100.1:51000"), None));
    }

    #[test]
    fn ip_allowlist_prefers_xff_over_socket_peer() {
        let c = OperatorClassifier {
            ua_prefixes: vec![],
            ips: vec!["203.0.113.7".into()],
        };
        let meta = json!({"x_forwarded_for": "203.0.113.7, 10.0.0.1"});
        // Socket peer is the proxy; XFF leftmost is the real client.
        assert!(c.classify(None, Some("127.0.0.1:1234"), Some(&meta)));
    }

    #[test]
    fn xff_with_leading_comma_does_not_false_positive_on_empty() {
        // We have seen ",213.76.110.18" shapes in the wild from Caddy.
        let c = OperatorClassifier {
            ua_prefixes: vec![],
            ips: vec!["".into()], // pathological allowlist entry
        };
        let meta = json!({"x_forwarded_for": ",213.76.110.18"});
        // Empty entries get filtered, leftmost non-empty wins.
        assert!(!c.classify(None, Some("127.0.0.1:1"), Some(&meta)));
    }

    #[test]
    fn ipv6_socket_peer_is_compared_without_brackets_or_port() {
        let c = OperatorClassifier {
            ua_prefixes: vec![],
            ips: vec!["2001:db8::1".into()],
        };
        assert!(c.classify(None, Some("[2001:db8::1]:443"), None));
    }

    #[test]
    fn no_signals_means_external_traffic() {
        let c = OperatorClassifier::default();
        assert!(!c.classify(Some("Mozilla/5.0"), Some("8.8.8.8:443"), None));
        assert!(!c.classify(None, None, None));
    }
}
