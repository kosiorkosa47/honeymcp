//! Unicode-based obfuscation / steganography detector.
//!
//! Catches invisible formatting tricks used to smuggle payloads past simple string
//! filters: zero-width characters, bidirectional overrides, and unusual tag-block
//! glyphs. Each is near-zero frequency in legitimate tool arguments, so presence
//! alone is signal.

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct UnicodeAnomalyDetector;

fn is_zero_width(c: char) -> bool {
    matches!(
        c as u32,
        0x200B..=0x200D     // zero-width space / non-joiner / joiner
      | 0x2060..=0x2064     // word joiner etc.
      | 0xFEFF              // BOM / zero-width no-break space
    )
}

fn is_bidi_override(c: char) -> bool {
    matches!(
        c as u32,
        0x202A..=0x202E     // LRE/RLE/PDF/LRO/RLO
      | 0x2066..=0x2069     // LRI/RLI/FSI/PDI
    )
}

fn is_tag_block(c: char) -> bool {
    // The "tags" block is used for steganographic ASCII smuggling inside strings.
    (c as u32) >= 0xE0000 && (c as u32) <= 0xE007F
}

impl Detector for UnicodeAnomalyDetector {
    fn name(&self) -> &'static str {
        "unicode_anomaly"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::UnicodeAnomaly
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let params = ctx.entry.params.as_ref()?;
        let body = params.to_string();

        let mut kind: Option<&'static str> = None;
        for c in body.chars() {
            if is_zero_width(c) {
                kind = Some("zero_width");
                break;
            }
            if is_bidi_override(c) {
                kind = Some("bidi_override");
                break;
            }
            if is_tag_block(c) {
                kind = Some("tag_block");
                break;
            }
        }
        let kind = kind?;
        Some(Detection {
            detector: "unicode_anomaly",
            category: DetectionCategory::UnicodeAnomaly,
            severity: Severity::Medium,
            evidence: kind.to_string(),
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
    fn triggers_on_zero_width_space() {
        let s = SessionStats::default();
        let smuggled = "hello\u{200B}world";
        let e = make_entry(
            "tools/call",
            json!({"name":"note","arguments":{"msg": smuggled}}),
        );
        assert!(UnicodeAnomalyDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_bidi_override() {
        let s = SessionStats::default();
        let smuggled = "admin\u{202E}nimda";
        let e = make_entry(
            "tools/call",
            json!({"name":"login","arguments":{"user": smuggled}}),
        );
        assert!(UnicodeAnomalyDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn negative_ascii_payload() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"echo","arguments":{"s":"plain ascii"}}),
        );
        assert!(UnicodeAnomalyDetector.analyze(&ctx(&e, &s)).is_none());
    }
}
