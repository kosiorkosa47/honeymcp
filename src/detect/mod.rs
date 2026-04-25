//! Threat detection heuristics.
//!
//! Each detector is a stateless `impl Detector` that inspects a freshly-logged event
//! (optionally with a tiny slice of per-session state) and emits zero or one
//! [`Detection`]. The dispatcher runs the configured registry against every event
//! after it's persisted to the events table, and writes matches into the separate
//! `detections` table so analysis queries join cleanly.
//!
//! New detectors live in their own submodule under `src/detect/` and get added to
//! [`Registry::default`] below.

use serde::{Deserialize, Serialize};

use crate::logger::LogEntry;

pub mod cve_59536;
pub mod prompt_injection;
pub mod recon;
pub mod secret_exfil;
pub mod shell_injection;
pub mod tool_enumeration;
pub mod unicode_anomaly;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionCategory {
    PromptInjection,
    CommandInjection,
    Recon,
    SecretExfil,
    SupplyChain,
    UnicodeAnomaly,
}

impl DetectionCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectionCategory::PromptInjection => "prompt_injection",
            DetectionCategory::CommandInjection => "command_injection",
            DetectionCategory::Recon => "recon",
            DetectionCategory::SecretExfil => "secret_exfil",
            DetectionCategory::SupplyChain => "supply_chain",
            DetectionCategory::UnicodeAnomaly => "unicode_anomaly",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub detector: &'static str,
    pub category: DetectionCategory,
    pub severity: Severity,
    /// Short excerpt of the payload that triggered the rule.
    pub evidence: String,
    pub notes: Option<String>,
}

/// Minimal per-session view useful for stateful detectors (e.g. Recon needs the call
/// counter). Dispatcher fills this in before invoking the registry.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub calls_in_session: u32,
    pub tools_list_count: u32,
    pub tools_call_count: u32,
}

pub struct DetectionContext<'a> {
    pub entry: &'a LogEntry,
    pub stats: &'a SessionStats,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> DetectionCategory;
    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection>;
}

/// Registry is a bag of enabled detectors. Kept separate from [`Detector`] so the
/// dispatcher can ignore the CLI `--disable-detectors` flag with a single swap.
pub struct Registry {
    detectors: Vec<Box<dyn Detector>>,
}

impl Registry {
    pub fn default_enabled() -> Self {
        Self {
            detectors: vec![
                Box::new(prompt_injection::PromptInjectionDetector),
                Box::new(shell_injection::ShellInjectionDetector),
                Box::new(recon::ReconDetector),
                Box::new(secret_exfil::SecretExfilDetector),
                Box::new(cve_59536::Cve59536Detector),
                Box::new(unicode_anomaly::UnicodeAnomalyDetector),
                Box::new(tool_enumeration::ToolEnumerationDetector),
            ],
        }
    }

    pub fn disabled() -> Self {
        Self { detectors: vec![] }
    }

    pub fn analyze_all(&self, ctx: &DetectionContext) -> Vec<Detection> {
        self.detectors
            .iter()
            .filter_map(|d| d.analyze(ctx))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::logger::hash_params;
    use serde_json::Value;

    pub fn make_entry(method: &str, params: Value) -> LogEntry {
        LogEntry {
            timestamp_ms: 0,
            method: method.into(),
            params_hash: hash_params(&Some(params.clone())),
            params: Some(params),
            client_name: Some("unit-test".into()),
            client_version: Some("0".into()),
            session_id: "s1".into(),
            response_summary: "".into(),
            transport: Some("stdio".into()),
            remote_addr: None,
            user_agent: None,
            client_meta: None,
            is_operator: false,
        }
    }

    pub fn ctx<'a>(entry: &'a LogEntry, stats: &'a SessionStats) -> DetectionContext<'a> {
        DetectionContext { entry, stats }
    }
}
