//! Scanner / automated-client fingerprinting.
//!
//! Classifies the User-Agent of the first MCP message in a session so the
//! benign-but-noisy crawler traffic (Censys, Shodan, MCP-specific scanners,
//! raw HTTP libraries) becomes a labelled dimension instead of being dropped.
//! Fires at most once per session and never on probe events (those already get
//! their own path/keyword detections).

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct ScannerFingerprintDetector;

fn classify(ua_lower: &str) -> Option<&'static str> {
    if ua_lower.contains("censys") {
        Some("censys internet-wide scanner")
    } else if ua_lower.contains("shodan") {
        Some("shodan scanner")
    } else if ua_lower.contains("mcp scan") || ua_lower.contains("mcp-scan") {
        Some("mcp-specific scanner")
    } else if ua_lower.contains("zgrab")
        || ua_lower.contains("masscan")
        || ua_lower.contains("nmap")
    {
        Some("network scanner")
    } else if ua_lower.contains("nuclei")
        || ua_lower.contains("nikto")
        || ua_lower.contains("sqlmap")
    {
        Some("vulnerability scanner")
    } else if ua_lower.contains("aiohttp")
        || ua_lower.contains("python-requests")
        || ua_lower.starts_with("python/")
        || ua_lower.contains("python-httpx")
        || ua_lower.contains("go-http-client")
        || ua_lower.contains("okhttp")
        || ua_lower.contains("curl/")
        || ua_lower.contains("wget/")
    {
        Some("automated http client")
    } else {
        None
    }
}

impl Detector for ScannerFingerprintDetector {
    fn name(&self) -> &'static str {
        "scanner_fingerprint"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::Recon
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        // Once per session, and not on the probe surface.
        if ctx.entry.method == "probe" || ctx.stats.calls_in_session > 1 {
            return None;
        }
        let ua = ctx.entry.user_agent.as_deref()?;
        let label = classify(&ua.to_ascii_lowercase())?;
        Some(Detection {
            detector: "scanner_fingerprint",
            category: DetectionCategory::Recon,
            severity: Severity::Low,
            evidence: ua.chars().take(120).collect(),
            notes: Some(label.to_string()),
            // T1595: Active Scanning. T1592: Gather Victim Host Information.
            mitre_techniques: &["T1595", "T1592"],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{ctx, make_entry};
    use crate::detect::SessionStats;
    use serde_json::json;

    fn entry_with_ua(
        method: &str,
        ua: Option<&str>,
        calls: u32,
    ) -> (crate::logger::LogEntry, SessionStats) {
        let mut e = make_entry(method, json!({}));
        e.user_agent = ua.map(String::from);
        let s = SessionStats {
            calls_in_session: calls,
            ..Default::default()
        };
        (e, s)
    }

    #[test]
    fn labels_censys_on_first_event() {
        let (e, s) = entry_with_ua(
            "initialize",
            Some("Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"),
            1,
        );
        let d = ScannerFingerprintDetector.analyze(&ctx(&e, &s)).unwrap();
        assert_eq!(d.detector, "scanner_fingerprint");
        assert!(
            !d.mitre_techniques.is_empty(),
            "must carry MITRE techniques"
        );
        assert!(d.notes.unwrap().contains("censys"));
    }

    #[test]
    fn labels_python_aiohttp() {
        let (e, s) = entry_with_ua("initialize", Some("Python/3.13 aiohttp/3.13.2"), 1);
        assert!(ScannerFingerprintDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn does_not_fire_after_first_event_or_on_probe() {
        let (e, s) = entry_with_ua("tools/list", Some("Python/3.13 aiohttp/3.13.2"), 3);
        assert!(ScannerFingerprintDetector.analyze(&ctx(&e, &s)).is_none());
        let (e2, s2) = entry_with_ua("probe", Some("CensysInspect/1.1"), 1);
        assert!(ScannerFingerprintDetector.analyze(&ctx(&e2, &s2)).is_none());
    }

    #[test]
    fn ignores_real_client_user_agent() {
        let (e, s) = entry_with_ua("initialize", Some("claude-desktop/1.2.0"), 1);
        assert!(ScannerFingerprintDetector.analyze(&ctx(&e, &s)).is_none());
    }
}
