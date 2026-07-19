use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryHit {
    pub observed_at_ms: i64,
    pub token_type: Option<String>,
    pub provider_event: Option<String>,
    pub later_token_use_ip: Option<String>,
    pub user_agent: Option<String>,
    pub account_id: Option<String>,
    pub input_channel: Option<String>,
    pub alert_status: Option<String>,
    pub marker: Option<String>,
    pub geo_json: Option<Value>,
    pub raw_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanaryImportSummary {
    pub total: usize,
    pub inserted: usize,
    pub ignored: usize,
}

pub fn load_hits_from_path(path: &Path) -> Result<Vec<CanaryHit>> {
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: Value = serde_json::from_str(&body).context("parsing canary hit JSON")?;
    parse_hits(&value)
}

pub fn parse_hits(value: &Value) -> Result<Vec<CanaryHit>> {
    let hits = value
        .get("hits")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("canary hit JSON must contain a hits array"))?;

    hits.iter().map(parse_hit).collect()
}

fn parse_hit(hit: &Value) -> Result<CanaryHit> {
    let observed_at_ms = hit
        .get("time_of_hit")
        .and_then(number_like_to_millis)
        .ok_or_else(|| anyhow!("canary hit is missing numeric time_of_hit"))?;
    let raw_hash = hash_json(hit);
    let aws_log = hit.pointer("/additional_info/aws_key_log_data");
    Ok(CanaryHit {
        observed_at_ms,
        token_type: string_field(hit, "token_type"),
        provider_event: aws_log.and_then(|v| first_string(v, "eventName")),
        later_token_use_ip: string_field(hit, "src_ip"),
        user_agent: string_field(hit, "useragent"),
        account_id: aws_log.and_then(|v| first_string(v, "accountId")),
        input_channel: string_field(hit, "input_channel"),
        alert_status: string_field(hit, "alert_status"),
        marker: marker_field(hit),
        geo_json: hit.get("geo_info").cloned(),
        raw_hash,
    })
}

fn number_like_to_millis(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n.saturating_mul(1000));
    }
    if let Some(n) = v.as_u64() {
        return Some((n as i64).saturating_mul(1000));
    }
    if let Some(n) = v.as_f64() {
        return Some((n * 1000.0).round() as i64);
    }
    v.as_str()
        .and_then(|s| s.parse::<f64>().ok())
        .map(|n| (n * 1000.0).round() as i64)
}

fn string_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn first_string(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn marker_field(v: &Value) -> Option<String> {
    for key in [
        "canary_marker",
        "canary_name",
        "token_name",
        "memo",
        "marker",
        "note",
    ] {
        if let Some(s) = string_field(v, key) {
            if !looks_like_secret(&s) {
                return Some(s);
            }
        }
    }
    None
}

fn looks_like_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("secret_access_key")
        || lower.contains("aws_secret")
        || s.starts_with("AKIA")
        || s.starts_with("ASIA")
        || s.len() > 96
}

fn hash_json(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(value).unwrap_or_default());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canarytokens_aws_export_without_secret_values() {
        let value = serde_json::json!({
            "hits": [{
                "time_of_hit": 1784432533.523728,
                "src_ip": "209.250.120.16",
                "useragent": "Boto3/1.43.10 Botocore/1.43.10",
                "token_type": "aws_keys",
                "input_channel": "webhook",
                "alert_status": "Unacknowledged",
                "additional_info": {
                    "aws_key_log_data": {
                        "eventName": ["GetCallerIdentity"],
                        "accountId": ["194031983756"]
                    }
                },
                "geo_info": {"country": "US"}
            }]
        });

        let hits = parse_hits(&value).unwrap();
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.observed_at_ms, 1_784_432_533_524);
        assert_eq!(hit.later_token_use_ip.as_deref(), Some("209.250.120.16"));
        assert_eq!(hit.provider_event.as_deref(), Some("GetCallerIdentity"));
        assert_eq!(hit.account_id.as_deref(), Some("194031983756"));
        assert!(hit.marker.is_none());
        assert_eq!(hit.raw_hash.len(), 64);
    }

    #[test]
    fn marker_field_rejects_obvious_credential_values() {
        let value = serde_json::json!({
            "hits": [{
                "time_of_hit": 1,
                "src_ip": "203.0.113.1",
                "token_type": "aws_keys",
                "token_name": "AKIA1234567890123456"
            }]
        });
        let hits = parse_hits(&value).unwrap();
        assert!(hits[0].marker.is_none());
    }
}
