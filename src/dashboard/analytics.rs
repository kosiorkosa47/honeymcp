use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;
use serde_json::Value;

use crate::logger::{CanaryCorrelationRow, RawEventRow};

const MAX_DASHBOARD_ROWS: usize = 5_000;

#[derive(Debug, Clone, Serialize)]
pub(super) struct DashboardAnalytics {
    pub window_label: String,
    pub event_count: usize,
    pub detection_count: usize,
    pub attack_classes: Vec<AttackClassForTemplate>,
    pub campaigns: Vec<CampaignForTemplate>,
    pub countries: Vec<CountryForTemplate>,
    pub heatmap: HeatmapForTemplate,
    pub feed_events: Vec<FeedEventForTemplate>,
    pub mcp_risk: McpRiskForTemplate,
    pub canary_correlations: Vec<CanaryCorrelationForTemplate>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AttackClassForTemplate {
    pub name: String,
    pub surface: String,
    pub goal: String,
    pub severity: String,
    pub count: usize,
    pub detections: usize,
    pub unique_sources: usize,
    pub latest_relative: String,
    pub share_pct: usize,
    pub css_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CampaignForTemplate {
    pub label: String,
    pub attack_class: String,
    pub surface: String,
    pub goal: String,
    pub severity: String,
    pub count: usize,
    pub detections: usize,
    pub source_ip: String,
    pub country_code: String,
    pub user_agent: String,
    pub sample_path: String,
    pub first_seen_iso: String,
    pub last_seen_iso: String,
    pub duration: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CountryForTemplate {
    pub code: String,
    pub name: String,
    pub count: usize,
    pub detections: usize,
    pub unique_sources: usize,
    pub top_class: String,
    pub share_pct: usize,
    pub has_position: bool,
    pub x: i32,
    pub y: i32,
    pub radius: i32,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HeatmapForTemplate {
    pub detectors: Vec<String>,
    pub rows: Vec<HeatmapRowForTemplate>,
    pub max_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HeatmapRowForTemplate {
    pub detector: String,
    pub cells: Vec<HeatmapCellForTemplate>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct HeatmapCellForTemplate {
    pub count: usize,
    pub bucket: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FeedEventForTemplate {
    pub id: i64,
    pub iso: String,
    pub relative: String,
    pub surface: String,
    pub attack_class: String,
    pub goal: String,
    pub severity: String,
    pub source_ip: String,
    pub country_code: String,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub detections: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct McpRiskForTemplate {
    pub sessions: usize,
    pub suspicious_sessions: usize,
    pub tool_calls: usize,
    pub tool_calls_with_detections: usize,
    pub unknown_methods: usize,
    pub score: usize,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CanaryCorrelationForTemplate {
    pub hit_id: i64,
    pub hit_iso: String,
    pub hit_relative: String,
    pub token_type: String,
    pub provider_event: String,
    pub later_token_use_ip: String,
    pub hit_user_agent: String,
    pub account_id: String,
    pub canary_marker: String,
    pub hit_marker: String,
    pub event_id: i64,
    pub exposure_iso: String,
    pub exposure_relative: String,
    pub exposure_source_ip: String,
    pub persona: String,
    pub method: String,
    pub tool_name: String,
    pub target: String,
    pub delay: String,
    pub response_summary: String,
}

#[derive(Debug, Clone)]
struct AttackClass {
    name: &'static str,
    surface: &'static str,
    goal: &'static str,
    severity: &'static str,
}

#[derive(Default)]
struct AttackClassAgg {
    name: String,
    surface: String,
    goal: String,
    severity: String,
    count: usize,
    detections: usize,
    latest_ms: i64,
    sources: BTreeSet<String>,
}

#[derive(Default)]
struct CampaignAgg {
    attack_class: String,
    surface: String,
    goal: String,
    severity: String,
    count: usize,
    detections: usize,
    source_ip: String,
    country_code: String,
    user_agent: String,
    sample_path: String,
    first_ms: i64,
    last_ms: i64,
}

#[derive(Default)]
struct CountryAgg {
    code: String,
    count: usize,
    detections: usize,
    sources: BTreeSet<String>,
    classes: HashMap<String, usize>,
}

pub(super) fn build_dashboard_analytics(rows: &[RawEventRow], now_ms: i64) -> DashboardAnalytics {
    let rows = if rows.len() > MAX_DASHBOARD_ROWS {
        &rows[..MAX_DASHBOARD_ROWS]
    } else {
        rows
    };

    let mut classes: BTreeMap<String, AttackClassAgg> = BTreeMap::new();
    let mut campaigns: BTreeMap<String, CampaignAgg> = BTreeMap::new();
    let mut countries: BTreeMap<String, CountryAgg> = BTreeMap::new();
    let mut detection_count = 0usize;

    for row in rows {
        let detectors = detector_names(row);
        detection_count += detectors.len();
        let class = classify(row, &detectors);
        let source_ip = source_ip(row);
        let country = country_code(row);
        let path = path_label(row);

        let class_entry = classes
            .entry(class.name.to_string())
            .or_insert_with(|| AttackClassAgg {
                name: class.name.to_string(),
                surface: class.surface.to_string(),
                goal: class.goal.to_string(),
                severity: class.severity.to_string(),
                ..Default::default()
            });
        class_entry.count += 1;
        class_entry.detections += detectors.len();
        class_entry.latest_ms = class_entry.latest_ms.max(row.timestamp_ms);
        class_entry.sources.insert(source_ip.clone());

        let campaign_key = format!(
            "{}\0{}\0{}",
            source_ip,
            row.user_agent.as_deref().unwrap_or("-"),
            class.name
        );
        let campaign = campaigns
            .entry(campaign_key)
            .or_insert_with(|| CampaignAgg {
                attack_class: class.name.to_string(),
                surface: class.surface.to_string(),
                goal: class.goal.to_string(),
                severity: class.severity.to_string(),
                source_ip: source_ip.clone(),
                country_code: country.clone(),
                user_agent: row.user_agent.clone().unwrap_or_else(|| "-".into()),
                sample_path: path.clone(),
                first_ms: row.timestamp_ms,
                last_ms: row.timestamp_ms,
                ..Default::default()
            });
        campaign.count += 1;
        campaign.detections += detectors.len();
        campaign.first_ms = campaign.first_ms.min(row.timestamp_ms);
        campaign.last_ms = campaign.last_ms.max(row.timestamp_ms);
        if campaign.sample_path == "-" && path != "-" {
            campaign.sample_path = path;
        }

        let country_entry = countries
            .entry(country.clone())
            .or_insert_with(|| CountryAgg {
                code: country.clone(),
                ..Default::default()
            });
        country_entry.count += 1;
        country_entry.detections += detectors.len();
        country_entry.sources.insert(source_ip);
        *country_entry
            .classes
            .entry(class.name.to_string())
            .or_insert(0) += 1;
    }

    let total_events = rows.len().max(1);
    let mut attack_classes: Vec<_> = classes
        .into_values()
        .map(|a| AttackClassForTemplate {
            css_class: slug(&a.name),
            share_pct: percent(a.count, total_events),
            latest_relative: relative(a.latest_ms, now_ms),
            unique_sources: a.sources.len(),
            name: a.name,
            surface: a.surface,
            goal: a.goal,
            severity: a.severity,
            count: a.count,
            detections: a.detections,
        })
        .collect();
    attack_classes.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)))
            .then_with(|| a.name.cmp(&b.name))
    });
    attack_classes.truncate(10);

    let mut campaigns: Vec<_> = campaigns
        .into_values()
        .map(|c| CampaignForTemplate {
            label: format!("{} / {}", c.source_ip, truncate(&c.attack_class, 36)),
            attack_class: c.attack_class,
            surface: c.surface,
            goal: c.goal,
            severity: c.severity,
            count: c.count,
            detections: c.detections,
            source_ip: c.source_ip,
            country_code: c.country_code,
            user_agent: truncate(&c.user_agent, 90),
            sample_path: truncate(&c.sample_path, 90),
            first_seen_iso: iso(c.first_ms),
            last_seen_iso: iso(c.last_ms),
            duration: duration(c.last_ms.saturating_sub(c.first_ms)),
        })
        .collect();
    campaigns.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| b.detections.cmp(&a.detections))
            .then_with(|| a.source_ip.cmp(&b.source_ip))
    });
    campaigns.truncate(8);

    let mut countries: Vec<_> = countries
        .into_values()
        .map(|c| {
            let top_class = c
                .classes
                .iter()
                .max_by_key(|(_, n)| **n)
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| "-".into());
            let (has_position, x, y) = country_position(&c.code)
                .map(|(x, y)| (true, x, y))
                .unwrap_or((false, 0, 0));
            CountryForTemplate {
                code: c.code.clone(),
                name: country_name(&c.code).to_string(),
                count: c.count,
                detections: c.detections,
                unique_sources: c.sources.len(),
                top_class,
                share_pct: percent(c.count, total_events),
                has_position,
                x,
                y,
                radius: (5.0 + (c.count as f64).sqrt() * 3.0).min(22.0) as i32,
            }
        })
        .collect();
    countries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
    countries.truncate(12);

    DashboardAnalytics {
        window_label: "last 24h".into(),
        event_count: rows.len(),
        detection_count,
        attack_classes,
        campaigns,
        countries,
        heatmap: build_heatmap(rows),
        feed_events: rows
            .iter()
            .take(25)
            .map(|row| feed_event(row, now_ms))
            .collect(),
        mcp_risk: build_mcp_risk(rows),
        canary_correlations: Vec::new(),
    }
}

pub(super) fn canary_correlation(
    row: &CanaryCorrelationRow,
    now_ms: i64,
) -> CanaryCorrelationForTemplate {
    CanaryCorrelationForTemplate {
        hit_id: row.hit_id,
        hit_iso: iso(row.hit_timestamp_ms),
        hit_relative: relative(row.hit_timestamp_ms, now_ms),
        token_type: row.token_type.clone().unwrap_or_else(|| "-".into()),
        provider_event: row.provider_event.clone().unwrap_or_else(|| "-".into()),
        later_token_use_ip: row
            .later_token_use_ip
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        hit_user_agent: truncate(row.hit_user_agent.as_deref().unwrap_or("-"), 90),
        account_id: row.account_id.clone().unwrap_or_else(|| "-".into()),
        canary_marker: row.canary_marker.clone(),
        hit_marker: row.hit_marker.clone().unwrap_or_else(|| "inferred".into()),
        event_id: row.event_id,
        exposure_iso: iso(row.exposure_timestamp_ms),
        exposure_relative: relative(row.exposure_timestamp_ms, now_ms),
        exposure_source_ip: row
            .exposure_source_ip
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        persona: row.persona.clone().unwrap_or_else(|| "-".into()),
        method: row.method.clone(),
        tool_name: tool_name_from_params(row.params.as_deref()).unwrap_or_else(|| "-".into()),
        target: target_label(row.params.as_deref()),
        delay: duration(row.delay_ms),
        response_summary: truncate(&row.response_summary, 90),
    }
}

pub(super) fn feed_event(row: &RawEventRow, now_ms: i64) -> FeedEventForTemplate {
    let detectors = detector_names(row);
    let class = classify(row, &detectors);
    FeedEventForTemplate {
        id: row.id,
        iso: iso(row.timestamp_ms),
        relative: relative(row.timestamp_ms, now_ms),
        surface: class.surface.to_string(),
        attack_class: class.name.to_string(),
        goal: class.goal.to_string(),
        severity: class.severity.to_string(),
        source_ip: source_ip(row),
        country_code: country_code(row),
        method: row.method.clone(),
        path: path_label(row),
        user_agent: truncate(row.user_agent.as_deref().unwrap_or("-"), 90),
        detections: detectors,
    }
}

pub(super) fn render_markdown_report(
    analytics: &DashboardAnalytics,
    include_operator: bool,
) -> String {
    let mut out = String::new();
    out.push_str("# honeymcp attack report\n\n");
    out.push_str(&format!(
        "- Window: {}\n- Scope: {}\n- Events: {}\n- Detector hits: {}\n\n",
        analytics.window_label,
        if include_operator {
            "external + operator"
        } else {
            "external only"
        },
        analytics.event_count,
        analytics.detection_count
    ));

    out.push_str("## Attack classes\n\n");
    if analytics.attack_classes.is_empty() {
        out.push_str("No events in this window.\n\n");
    } else {
        out.push_str("| Class | Surface | Goal | Events | Detections | Sources |\n");
        out.push_str("|---|---:|---|---:|---:|---:|\n");
        for a in &analytics.attack_classes {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                a.name, a.surface, a.goal, a.count, a.detections, a.unique_sources
            ));
        }
        out.push('\n');
    }

    out.push_str("## Campaigns\n\n");
    if analytics.campaigns.is_empty() {
        out.push_str("No campaign groups in this window.\n\n");
    } else {
        out.push_str("| Source | Country | Class | Events | Duration | Sample |\n");
        out.push_str("|---|---:|---|---:|---:|---|\n");
        for c in &analytics.campaigns {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | `{}` |\n",
                c.source_ip, c.country_code, c.attack_class, c.count, c.duration, c.sample_path
            ));
        }
        out.push('\n');
    }

    out.push_str("## Canary follow-through\n\n");
    if analytics.canary_correlations.is_empty() {
        out.push_str("No imported canary hits correlated in this window.\n\n");
    } else {
        out.push_str("| Marker | Event | Source | Later token-use IP | Provider event | Delay |\n");
        out.push_str("|---|---:|---|---|---|---:|\n");
        for c in &analytics.canary_correlations {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} |\n",
                c.canary_marker,
                c.event_id,
                c.exposure_source_ip,
                c.later_token_use_ip,
                c.provider_event,
                c.delay
            ));
        }
        out.push('\n');
    }

    out.push_str("## Source countries\n\n");
    if analytics.countries.is_empty() {
        out.push_str("No country signal in this window.\n\n");
    } else {
        out.push_str("| Country | Events | Sources | Top class |\n");
        out.push_str("|---|---:|---:|---|\n");
        for c in &analytics.countries {
            out.push_str(&format!(
                "| {} ({}) | {} | {} | {} |\n",
                c.name, c.code, c.count, c.unique_sources, c.top_class
            ));
        }
        out.push('\n');
    }

    out.push_str("## MCP risk\n\n");
    out.push_str(&format!(
        "- Label: {}\n- Sessions: {}\n- Suspicious sessions: {}\n- Tool calls: {}\n- Tool calls with detections: {}\n- Unknown methods: {}\n- Score: {}/100\n",
        analytics.mcp_risk.label,
        analytics.mcp_risk.sessions,
        analytics.mcp_risk.suspicious_sessions,
        analytics.mcp_risk.tool_calls,
        analytics.mcp_risk.tool_calls_with_detections,
        analytics.mcp_risk.unknown_methods,
        analytics.mcp_risk.score
    ));

    out
}

pub(super) fn render_persona_sankey_svg(rows: &[RawEventRow], now_ms: i64) -> String {
    let mut flows: HashMap<(String, String), usize> = HashMap::new();
    for row in rows.iter().take(MAX_DASHBOARD_ROWS) {
        let detectors = detector_names(row);
        let class = classify(row, &detectors);
        let persona = row
            .persona
            .clone()
            .unwrap_or_else(|| "probe surface".into());
        *flows.entry((persona, class.name.to_string())).or_insert(0) += 1;
    }

    let mut flows: Vec<_> = flows.into_iter().collect();
    flows.sort_by(|a, b| b.1.cmp(&a.1));
    flows.truncate(12);

    let width = 860;
    let height = 110 + (flows.len().max(1) as i32 * 34);
    let max = flows.iter().map(|(_, n)| *n).max().unwrap_or(1);
    let mut y = 78;
    let mut body = String::new();
    body.push_str(&format!(
        r##"<text x="24" y="32" fill="#d8e3df" font-size="15" font-family="Inter, system-ui, sans-serif" font-weight="600">Persona vs observed intent</text>
<text x="24" y="52" fill="#7e8b86" font-size="11" font-family="ui-monospace, monospace">external-only projection, {}</text>"##,
        escape_xml(&relative(now_ms - 24 * 60 * 60 * 1000, now_ms))
    ));

    if flows.is_empty() {
        body.push_str(
            r##"<text x="24" y="92" fill="#7e8b86" font-size="12" font-family="ui-monospace, monospace">no flows in window</text>"##,
        );
    }

    for ((persona, target), count) in flows {
        let stroke = (2.0 + (count as f64 / max as f64) * 18.0) as i32;
        let x1 = 190;
        let x2 = 610;
        body.push_str(&format!(
            r##"<text x="24" y="{y}" fill="#a8e068" font-size="12" font-family="ui-monospace, monospace">{}</text>
<path d="M {x1} {y} C 330 {}, 470 {}, {x2} {y}" fill="none" stroke="#a8e068" stroke-opacity="0.45" stroke-width="{stroke}" stroke-linecap="round"/>
<text x="640" y="{y}" fill="#d8e3df" font-size="12" font-family="ui-monospace, monospace">{} <tspan fill="#7e8b86">({count})</tspan></text>"##,
            escape_xml(&truncate(&persona, 22)),
            y - 18,
            y + 18,
            escape_xml(&truncate(&target, 34)),
        ));
        y += 34;
    }

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background:#0a0d0e;border-radius:4px;">
{body}
</svg>"##
    )
}

fn build_heatmap(rows: &[RawEventRow]) -> HeatmapForTemplate {
    let mut session_detectors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut detector_freq: HashMap<String, usize> = HashMap::new();

    for row in rows {
        let detectors = detector_names(row);
        if detectors.is_empty() {
            continue;
        }
        let entry = session_detectors.entry(row.session_id.clone()).or_default();
        for detector in detectors {
            *detector_freq.entry(detector.clone()).or_insert(0) += 1;
            entry.insert(detector);
        }
    }

    let mut detectors: Vec<_> = detector_freq.into_iter().collect();
    detectors.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let detectors: Vec<String> = detectors.into_iter().take(8).map(|(d, _)| d).collect();

    let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();
    for detector_set in session_detectors.values() {
        for a in &detectors {
            if !detector_set.contains(a) {
                continue;
            }
            for b in &detectors {
                if detector_set.contains(b) {
                    *pair_counts.entry((a.clone(), b.clone())).or_insert(0) += 1;
                }
            }
        }
    }

    let max_count = pair_counts.values().copied().max().unwrap_or(0);
    let rows = detectors
        .iter()
        .map(|a| {
            let cells = detectors
                .iter()
                .map(|b| {
                    let count = pair_counts
                        .get(&(a.clone(), b.clone()))
                        .copied()
                        .unwrap_or(0);
                    HeatmapCellForTemplate {
                        count,
                        bucket: bucket(count, max_count),
                    }
                })
                .collect();
            HeatmapRowForTemplate {
                detector: a.clone(),
                cells,
            }
        })
        .collect();

    HeatmapForTemplate {
        detectors,
        rows,
        max_count,
    }
}

fn build_mcp_risk(rows: &[RawEventRow]) -> McpRiskForTemplate {
    #[derive(Default)]
    struct SessionRisk {
        tool_calls: usize,
        detected_tool_calls: usize,
        unknown_methods: usize,
        detections: usize,
    }

    let mut sessions: BTreeMap<String, SessionRisk> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.method != "probe") {
        let detectors = detector_names(row);
        let s = sessions.entry(row.session_id.clone()).or_default();
        s.detections += detectors.len();
        if row.method == "tools/call" {
            s.tool_calls += 1;
            if !detectors.is_empty() {
                s.detected_tool_calls += 1;
            }
        }
        if row.response_summary.starts_with("method-not-found:") {
            s.unknown_methods += 1;
        }
    }

    let sessions_n = sessions.len();
    let suspicious_sessions = sessions
        .values()
        .filter(|s| s.detected_tool_calls > 0 || s.unknown_methods > 0 || s.detections >= 2)
        .count();
    let tool_calls: usize = sessions.values().map(|s| s.tool_calls).sum();
    let tool_calls_with_detections: usize = sessions.values().map(|s| s.detected_tool_calls).sum();
    let unknown_methods: usize = sessions.values().map(|s| s.unknown_methods).sum();
    let score = (tool_calls_with_detections * 30 + unknown_methods * 10 + suspicious_sessions * 15)
        .min(100);
    let label = if score >= 70 {
        "high"
    } else if score >= 30 {
        "medium"
    } else if sessions_n > 0 {
        "low"
    } else {
        "quiet"
    };

    McpRiskForTemplate {
        sessions: sessions_n,
        suspicious_sessions,
        tool_calls,
        tool_calls_with_detections,
        unknown_methods,
        score,
        label: label.into(),
    }
}

fn classify(row: &RawEventRow, detectors: &[String]) -> AttackClass {
    if row.method != "probe" {
        return classify_mcp(row, detectors);
    }

    let haystack = probe_haystack(row);
    if haystack.contains(".env") || haystack.contains(".git/config") {
        AttackClass {
            name: ".env / config exfil",
            surface: "probe",
            goal: "read framework, git or cloud secrets from exposed files",
            severity: "critical",
        }
    } else if haystack.contains("eval-stdin.php") || haystack.contains("phpunit") {
        AttackClass {
            name: "PHPUnit eval-stdin RCE",
            surface: "probe",
            goal: "execute PHP through exposed PHPUnit test helpers",
            severity: "critical",
        }
    } else if haystack.contains("phpinfo") {
        AttackClass {
            name: "phpinfo disclosure",
            surface: "probe",
            goal: "fingerprint PHP runtime, paths, env and loaded modules",
            severity: "medium",
        }
    } else if haystack.contains("thinkphp")
        || haystack.contains("invokefunction")
        || haystack.contains("call_user_func")
    {
        AttackClass {
            name: "ThinkPHP RCE probe",
            surface: "probe",
            goal: "reach known ThinkPHP function-invocation RCE chains",
            severity: "critical",
        }
    } else if haystack.contains("/cgi-bin/") && encoded_dotdot(&haystack) {
        AttackClass {
            name: "CGI traversal to shell",
            surface: "probe",
            goal: "escape CGI path handling and execute /bin/sh",
            severity: "critical",
        }
    } else if haystack.contains("auto_prepend_file")
        || haystack.contains("allow_url_include")
        || haystack.contains("-d+")
    {
        AttackClass {
            name: "PHP-CGI argument injection",
            surface: "probe",
            goal: "set PHP runtime flags and include attacker-controlled code",
            severity: "critical",
        }
    } else if haystack.contains("../")
        || encoded_dotdot(&haystack)
        || haystack.contains("/etc/passwd")
    {
        AttackClass {
            name: "path traversal / LFI",
            surface: "probe",
            goal: "read local files outside the web root",
            severity: "high",
        }
    } else if haystack.contains("_ignition") || haystack.contains("ignition") {
        AttackClass {
            name: "Laravel Ignition probe",
            surface: "probe",
            goal: "find debug endpoints linked to historical RCE chains",
            severity: "high",
        }
    } else if haystack.contains("/containers/json") || haystack.contains("docker") {
        AttackClass {
            name: "Docker API discovery",
            surface: "probe",
            goal: "find an exposed Docker daemon or container inventory",
            severity: "high",
        }
    } else if haystack.contains("geoserver") {
        AttackClass {
            name: "GeoServer exploit probe",
            surface: "probe",
            goal: "reach known GeoServer exploit paths",
            severity: "high",
        }
    } else if haystack.contains("metadata.google.internal")
        || haystack.contains("169.254.169.254")
        || haystack.contains("/computeMetadata/")
    {
        AttackClass {
            name: "cloud metadata probe",
            surface: "probe",
            goal: "reach instance metadata credentials",
            severity: "critical",
        }
    } else if haystack.contains("setup.cgi") || haystack.contains("mozi") {
        AttackClass {
            name: "router command injection",
            surface: "probe",
            goal: "drop malware through embedded-device command injection",
            severity: "critical",
        }
    } else if haystack.contains("/admin")
        || haystack.contains("wp-login")
        || haystack.contains("login")
        || haystack.contains("boaform")
    {
        AttackClass {
            name: "admin/login discovery",
            surface: "probe",
            goal: "discover management panels or default login surfaces",
            severity: "low",
        }
    } else if detectors.iter().any(|d| d == "scanner_fingerprint") {
        AttackClass {
            name: "internet scanner fingerprint",
            surface: "probe",
            goal: "inventory service banners and reachable paths",
            severity: "low",
        }
    } else {
        AttackClass {
            name: "generic web probe",
            surface: "probe",
            goal: "fingerprint unmodelled HTTP surface",
            severity: "low",
        }
    }
}

fn classify_mcp(row: &RawEventRow, detectors: &[String]) -> AttackClass {
    if detectors
        .iter()
        .any(|d| d == "secret_exfil_targets" || d == "ssrf_imds")
    {
        AttackClass {
            name: "MCP credential/cloud exfil",
            surface: "mcp",
            goal: "use MCP tools to read secrets, config or cloud metadata",
            severity: "critical",
        }
    } else if detectors.iter().any(|d| d == "shell_injection_patterns") {
        AttackClass {
            name: "MCP command injection",
            surface: "mcp",
            goal: "push shell metacharacters through tool arguments",
            severity: "critical",
        }
    } else if detectors
        .iter()
        .any(|d| d == "prompt_injection_markers" || d == "unicode_anomaly")
    {
        AttackClass {
            name: "MCP prompt/tool abuse",
            surface: "mcp",
            goal: "coerce agent instructions or hide malicious content",
            severity: "high",
        }
    } else if row.method == "tools/call" {
        AttackClass {
            name: "MCP tool execution",
            surface: "mcp",
            goal: "execute a fake tool and observe returned data",
            severity: "medium",
        }
    } else if row.method == "tools/list" || detectors.iter().any(|d| d == "tool_enumeration") {
        AttackClass {
            name: "MCP tool enumeration",
            surface: "mcp",
            goal: "list available tools and server capability shape",
            severity: "low",
        }
    } else if row.method == "initialize" || row.method == "notifications/initialized" {
        AttackClass {
            name: "MCP handshake recon",
            surface: "mcp",
            goal: "fingerprint protocol version, persona and server info",
            severity: "low",
        }
    } else if row.response_summary.starts_with("method-not-found:") {
        AttackClass {
            name: "MCP method fuzzing",
            surface: "mcp",
            goal: "probe unsupported JSON-RPC methods",
            severity: "medium",
        }
    } else {
        AttackClass {
            name: "MCP protocol probe",
            surface: "mcp",
            goal: "exercise MCP transport behaviour",
            severity: "low",
        }
    }
}

pub(super) fn source_ip(row: &RawEventRow) -> String {
    if let Some(meta) = row.client_meta.as_deref() {
        if let Ok(v) = serde_json::from_str::<Value>(meta) {
            if let Some(cf) = v.get("cf_connecting_ip").and_then(|x| x.as_str()) {
                if !cf.trim().is_empty() {
                    return cf.trim().to_string();
                }
            }
            if let Some(real) = v.get("x_real_ip").and_then(|x| x.as_str()) {
                if !real.trim().is_empty() {
                    return real.trim().to_string();
                }
            }
            if let Some(xff) = v.get("x_forwarded_for").and_then(|x| x.as_str()) {
                if let Some(first) = xff.split(',').map(str::trim).find(|s| !s.is_empty()) {
                    return first.to_string();
                }
            }
        }
    }
    row.remote_addr
        .as_deref()
        .map(strip_port)
        .unwrap_or("-")
        .to_string()
}

fn country_code(row: &RawEventRow) -> String {
    if let Some(meta) = row.client_meta.as_deref() {
        if let Ok(v) = serde_json::from_str::<Value>(meta) {
            for key in ["cf_ipcountry", "geoip_country", "country_code", "country"] {
                if let Some(code) = v.get(key).and_then(|x| x.as_str()) {
                    let code = code.trim().to_ascii_uppercase();
                    if code.len() == 2 && code != "XX" && code != "T1" {
                        return code;
                    }
                }
            }
        }
    }

    let ip = source_ip(row);
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) if is_private_or_reserved_v4(v4) => "PRIVATE".into(),
        Ok(IpAddr::V6(v6))
            if v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local() =>
        {
            "PRIVATE".into()
        }
        _ => "ZZ".into(),
    }
}

fn detector_names(row: &RawEventRow) -> Vec<String> {
    let Some(raw) = row.detections_json.as_deref() else {
        return Vec::new();
    };
    if raw.is_empty() || raw == "null" {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d.get("detector").and_then(|x| x.as_str()))
        .map(str::to_string)
        .collect()
}

fn path_label(row: &RawEventRow) -> String {
    if row.method != "probe" {
        if row.method == "tools/call" {
            return tool_name(row).unwrap_or_else(|| "tools/call".into());
        }
        return row.method.clone();
    }
    let Some(params) = row.params.as_deref() else {
        return "-".into();
    };
    let Ok(v) = serde_json::from_str::<Value>(params) else {
        return "-".into();
    };
    let path = v.get("path").and_then(|x| x.as_str()).unwrap_or("-");
    let query = v.get("query").and_then(|x| x.as_str());
    match query {
        Some(q) if !q.is_empty() => format!("{path}?{}", truncate(q, 60)),
        _ => path.to_string(),
    }
}

fn tool_name(row: &RawEventRow) -> Option<String> {
    tool_name_from_params(row.params.as_deref())
}

fn tool_name_from_params(params: Option<&str>) -> Option<String> {
    let params = params?;
    let v = serde_json::from_str::<Value>(params).ok()?;
    v.get("name").and_then(|x| x.as_str()).map(str::to_string)
}

fn target_label(params: Option<&str>) -> String {
    let Some(params) = params else {
        return "-".into();
    };
    let Ok(v) = serde_json::from_str::<Value>(params) else {
        return "-".into();
    };
    let Some(args) = v.get("arguments") else {
        return "-".into();
    };
    for key in ["secret_name", "secret_id", "name", "path", "bucket", "key"] {
        if let Some(s) = args.get(key).and_then(|x| x.as_str()) {
            if !s.trim().is_empty() {
                return truncate(s.trim(), 90);
            }
        }
    }
    "-".into()
}

fn probe_haystack(row: &RawEventRow) -> String {
    let mut s = row.response_summary.to_ascii_lowercase();
    if let Some(params) = row.params.as_deref() {
        s.push(' ');
        s.push_str(&params.to_ascii_lowercase());
    }
    s
}

fn strip_port(addr: &str) -> &str {
    if addr.starts_with('[') {
        return addr
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('['))
            .unwrap_or(addr);
    }
    addr.rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
        .unwrap_or(addr)
}

fn is_private_or_reserved_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 10
        || a == 127
        || a == 0
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

fn encoded_dotdot(s: &str) -> bool {
    s.contains("%2e%2e") || s.contains(".%2e") || s.contains("%2e.") || s.contains("%252e")
}

fn severity_rank(severity: &str) -> usize {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn percent(n: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        ((n as f64 / total as f64) * 100.0).round() as usize
    }
}

fn bucket(count: usize, max: usize) -> usize {
    if count == 0 || max == 0 {
        0
    } else {
        ((count as f64 / max as f64) * 4.0).ceil() as usize
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n).collect();
        out.push_str(" ...");
        out
    }
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn iso(ms: i64) -> String {
    let secs = ms / 1000;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| format!("@{ms}"))
}

fn relative(ts_ms: i64, now_ms: i64) -> String {
    let dt = (now_ms - ts_ms).max(0);
    let s = dt / 1000;
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86400)
    }
}

fn duration(ms: i64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

fn country_position(code: &str) -> Option<(i32, i32)> {
    let (lat, lon): (f64, f64) = match code {
        "US" => (39.8, -98.6),
        "CA" => (56.1, -106.3),
        "MX" => (23.6, -102.5),
        "BR" => (-14.2, -51.9),
        "AR" => (-38.4, -63.6),
        "CL" => (-35.7, -71.5),
        "GB" => (55.4, -3.4),
        "IE" => (53.4, -8.2),
        "FR" => (46.2, 2.2),
        "DE" => (51.2, 10.4),
        "NL" => (52.1, 5.3),
        "BE" => (50.5, 4.5),
        "CH" => (46.8, 8.2),
        "AT" => (47.5, 14.6),
        "IT" => (41.9, 12.6),
        "ES" => (40.5, -3.7),
        "PT" => (39.4, -8.2),
        "PL" => (51.9, 19.1),
        "CZ" => (49.8, 15.5),
        "RO" => (45.9, 24.9),
        "BG" => (42.7, 25.5),
        "UA" => (49.0, 31.4),
        "RU" => (61.5, 105.3),
        "SE" => (60.1, 18.6),
        "NO" => (60.5, 8.5),
        "FI" => (61.9, 25.7),
        "DK" => (56.3, 9.5),
        "TR" => (39.0, 35.2),
        "IL" => (31.0, 35.0),
        "AE" => (24.0, 54.0),
        "SA" => (24.0, 45.0),
        "IR" => (32.4, 53.7),
        "ZA" => (-30.6, 22.9),
        "CN" => (35.9, 104.2),
        "HK" => (22.3, 114.2),
        "TW" => (23.7, 121.0),
        "JP" => (36.2, 138.3),
        "KR" => (36.5, 127.9),
        "SG" => (1.35, 103.8),
        "IN" => (20.6, 78.9),
        "ID" => (-0.8, 113.9),
        "TH" => (15.9, 101.0),
        "VN" => (14.1, 108.3),
        "AU" => (-25.3, 133.8),
        _ => return None,
    };
    let x = (((lon + 180.0) / 360.0) * 640.0).round() as i32;
    let y = (((90.0 - lat) / 180.0) * 260.0).round() as i32;
    Some((x, y))
}

fn country_name(code: &str) -> &'static str {
    match code {
        "US" => "United States",
        "CA" => "Canada",
        "MX" => "Mexico",
        "BR" => "Brazil",
        "AR" => "Argentina",
        "CL" => "Chile",
        "GB" => "United Kingdom",
        "IE" => "Ireland",
        "FR" => "France",
        "DE" => "Germany",
        "NL" => "Netherlands",
        "BE" => "Belgium",
        "CH" => "Switzerland",
        "AT" => "Austria",
        "IT" => "Italy",
        "ES" => "Spain",
        "PT" => "Portugal",
        "PL" => "Poland",
        "CZ" => "Czechia",
        "RO" => "Romania",
        "BG" => "Bulgaria",
        "UA" => "Ukraine",
        "RU" => "Russia",
        "SE" => "Sweden",
        "NO" => "Norway",
        "FI" => "Finland",
        "DK" => "Denmark",
        "TR" => "Turkey",
        "IL" => "Israel",
        "AE" => "United Arab Emirates",
        "SA" => "Saudi Arabia",
        "IR" => "Iran",
        "ZA" => "South Africa",
        "CN" => "China",
        "HK" => "Hong Kong",
        "TW" => "Taiwan",
        "JP" => "Japan",
        "KR" => "South Korea",
        "SG" => "Singapore",
        "IN" => "India",
        "ID" => "Indonesia",
        "TH" => "Thailand",
        "VN" => "Vietnam",
        "AU" => "Australia",
        "PRIVATE" => "private/reserved",
        "ZZ" => "unknown",
        _ => "unmapped",
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(method: &str, params: Value) -> RawEventRow {
        RawEventRow {
            id: 1,
            timestamp_ms: 1_700_000_000_000,
            session_id: "s1".into(),
            method: method.into(),
            params: Some(params.to_string()),
            client_name: None,
            client_version: None,
            response_summary: "ok".into(),
            transport: Some("http".into()),
            remote_addr: Some("203.0.113.7:1234".into()),
            user_agent: Some("scanner/1".into()),
            client_meta: None,
            persona: Some("aws".into()),
            is_operator: false,
            detections_json: Some("[]".into()),
        }
    }

    fn probe(path: &str, query: Option<&str>) -> RawEventRow {
        let mut r = row(
            "probe",
            serde_json::json!({
                "http_method": "GET",
                "path": path,
                "query": query,
            }),
        );
        r.response_summary = format!("probe GET {path}");
        r.persona = None;
        r
    }

    fn detected(mut r: RawEventRow, detector: &str, severity: &str) -> RawEventRow {
        r.detections_json = Some(
            serde_json::json!([{
                "detector": detector,
                "severity": severity,
                "category": "recon",
                "evidence": "test"
            }])
            .to_string(),
        );
        r
    }

    #[test]
    fn classifies_dotenv_probe_as_secret_exfil() {
        let r = probe("/.env", None);
        let c = classify(&r, &[]);
        assert_eq!(c.name, ".env / config exfil");
        assert_eq!(c.severity, "critical");
    }

    #[test]
    fn extracts_cf_country_and_source_ip() {
        let mut r = row("initialize", serde_json::json!({}));
        r.client_meta = Some(
            serde_json::json!({
                "cf_connecting_ip": "198.51.100.42",
                "cf_ipcountry": "NL"
            })
            .to_string(),
        );
        assert_eq!(source_ip(&r), "198.51.100.42");
        assert_eq!(country_code(&r), "NL");
    }

    #[test]
    fn groups_repeated_rows_into_campaigns() {
        let r1 = probe("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", None);
        let mut r2 = r1.clone();
        r2.id = 2;
        r2.timestamp_ms += 1_000;
        let a = build_dashboard_analytics(&[r1, r2], 1_700_000_010_000);
        assert_eq!(a.campaigns[0].count, 2);
        assert_eq!(a.attack_classes[0].name, "PHPUnit eval-stdin RCE");
    }

    #[test]
    fn classifies_common_probe_families() {
        let cases = [
            (
                probe("/test.php", Some("x=phpinfo()")),
                "phpinfo disclosure",
            ),
            (
                probe(
                    "/index.php?s=/index/\\think\\app/invokefunction",
                    Some("function=call_user_func"),
                ),
                "ThinkPHP RCE probe",
            ),
            (
                probe("/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", None),
                "CGI traversal to shell",
            ),
            (
                probe(
                    "/index.php",
                    Some("-d+allow_url_include=1&auto_prepend_file=php://input"),
                ),
                "PHP-CGI argument injection",
            ),
            (
                probe("/../../../../etc/passwd", None),
                "path traversal / LFI",
            ),
            (
                probe("/_ignition/execute-solution", None),
                "Laravel Ignition probe",
            ),
            (probe("/containers/json", None), "Docker API discovery"),
            (probe("/geoserver/web/", None), "GeoServer exploit probe"),
            (
                probe(
                    "/latest/meta-data/iam/security-credentials/",
                    Some("u=169.254.169.254"),
                ),
                "cloud metadata probe",
            ),
            (
                probe(
                    "/setup.cgi",
                    Some("next_file=netgear.cfg&todo=syscmd&cmd=wget+Mozi"),
                ),
                "router command injection",
            ),
            (probe("/wp-login.php", None), "admin/login discovery"),
        ];

        for (row, expected) in cases {
            assert_eq!(classify(&row, &[]).name, expected);
        }

        let scanner = detected(probe("/random", None), "scanner_fingerprint", "low");
        assert_eq!(
            classify(&scanner, &detector_names(&scanner)).name,
            "internet scanner fingerprint"
        );
        assert_eq!(
            classify(&probe("/random", None), &[]).name,
            "generic web probe"
        );
    }

    #[test]
    fn classifies_mcp_intent_families() {
        let secret = detected(
            row(
                "tools/call",
                serde_json::json!({"name":"read_file","arguments":{"path":"/.env"}}),
            ),
            "secret_exfil_targets",
            "critical",
        );
        assert_eq!(
            classify(&secret, &detector_names(&secret)).name,
            "MCP credential/cloud exfil"
        );

        let shell = detected(
            row(
                "tools/call",
                serde_json::json!({"name":"run","arguments":{"cmd":"id; whoami"}}),
            ),
            "shell_injection_patterns",
            "critical",
        );
        assert_eq!(
            classify(&shell, &detector_names(&shell)).name,
            "MCP command injection"
        );

        let prompt = detected(
            row(
                "tools/call",
                serde_json::json!({"name":"note","arguments":{"body":"ignore previous"}}),
            ),
            "prompt_injection_markers",
            "high",
        );
        assert_eq!(
            classify(&prompt, &detector_names(&prompt)).name,
            "MCP prompt/tool abuse"
        );

        assert_eq!(
            classify(
                &row("tools/call", serde_json::json!({"name":"list_buckets"})),
                &[]
            )
            .name,
            "MCP tool execution"
        );
        assert_eq!(
            classify(&row("tools/list", serde_json::json!({})), &[]).name,
            "MCP tool enumeration"
        );
        assert_eq!(
            classify(&row("initialize", serde_json::json!({})), &[]).name,
            "MCP handshake recon"
        );

        let mut unknown = row("resources/list", serde_json::json!({}));
        unknown.response_summary = "method-not-found:resources/list".into();
        assert_eq!(classify(&unknown, &[]).name, "MCP method fuzzing");
        assert_eq!(
            classify(&row("ping", serde_json::json!({})), &[]).name,
            "MCP protocol probe"
        );
    }

    #[test]
    fn builds_report_heatmap_country_and_risk_views() {
        let mut r1 = detected(probe("/.env", None), "secret_exfil_targets", "critical");
        r1.client_meta = Some(serde_json::json!({"cf_ipcountry": "NL"}).to_string());
        let mut r2 = detected(
            row("tools/call", serde_json::json!({"name":"read_secret"})),
            "secret_exfil_targets",
            "critical",
        );
        r2.id = 2;
        r2.session_id = "mcp-risk".into();
        r2.client_meta = Some(serde_json::json!({"geoip_country": "US"}).to_string());
        let mut r3 = detected(
            row("tools/call", serde_json::json!({"name":"read_secret"})),
            "shell_injection_patterns",
            "critical",
        );
        r3.id = 3;
        r3.session_id = "mcp-risk".into();
        r3.client_meta = Some(serde_json::json!({"geoip_country": "US"}).to_string());

        let analytics = build_dashboard_analytics(&[r1, r2, r3], 1_700_000_020_000);
        assert_eq!(analytics.event_count, 3);
        assert!(analytics
            .attack_classes
            .iter()
            .any(|a| a.name == "MCP credential/cloud exfil"));
        assert!(analytics.countries.iter().any(|c| c.code == "US"));
        assert!(analytics.heatmap.max_count > 0);
        assert_eq!(analytics.mcp_risk.tool_calls, 2);
        assert_eq!(analytics.mcp_risk.tool_calls_with_detections, 2);
        assert!(analytics.mcp_risk.score >= 30);

        let report = render_markdown_report(&analytics, false);
        assert!(report.contains("honeymcp attack report"));
        assert!(report.contains("MCP credential/cloud exfil"));

        let svg = render_persona_sankey_svg(&[], 1_700_000_020_000);
        assert!(svg.contains("no flows in window"));
    }

    #[test]
    fn feed_event_summarises_source_path_and_detections() {
        let r = detected(
            probe("/.git/config", Some("a=b")),
            "secret_exfil_targets",
            "critical",
        );
        let ev = feed_event(&r, 1_700_000_030_000);
        assert_eq!(ev.attack_class, ".env / config exfil");
        assert_eq!(ev.path, "/.git/config?a=b");
        assert_eq!(ev.detections, vec!["secret_exfil_targets"]);
    }

    #[test]
    fn private_and_unknown_country_buckets_are_explicit() {
        let mut private = row("initialize", serde_json::json!({}));
        private.remote_addr = Some("10.0.0.5:1234".into());
        assert_eq!(country_code(&private), "PRIVATE");

        let mut unknown = row("initialize", serde_json::json!({}));
        unknown.remote_addr = Some("8.8.8.8:53".into());
        assert_eq!(country_code(&unknown), "ZZ");
    }

    #[test]
    fn country_tables_cover_supported_codes() {
        let codes = [
            "US", "CA", "MX", "BR", "AR", "CL", "GB", "IE", "FR", "DE", "NL", "BE", "CH", "AT",
            "IT", "ES", "PT", "PL", "CZ", "RO", "BG", "UA", "RU", "SE", "NO", "FI", "DK", "TR",
            "IL", "AE", "SA", "IR", "ZA", "CN", "HK", "TW", "JP", "KR", "SG", "IN", "ID", "TH",
            "VN", "AU",
        ];

        for code in codes {
            assert!(country_position(code).is_some(), "{code}");
            assert_ne!(country_name(code), "unmapped", "{code}");
        }

        assert_eq!(country_name("PRIVATE"), "private/reserved");
        assert_eq!(country_name("ZZ"), "unknown");
        assert_eq!(country_name("XY"), "unmapped");
        assert!(country_position("XY").is_none());
    }

    #[test]
    fn utility_helpers_cover_edge_buckets() {
        assert_eq!(bucket(0, 10), 0);
        assert_eq!(bucket(5, 10), 2);
        assert_eq!(percent(1, 4), 25);
        assert_eq!(percent(1, 0), 0);
        assert_eq!(duration(5_000), "5s");
        assert_eq!(duration(5 * 60_000), "5m");
        assert_eq!(duration(2 * 3_600_000), "2h");
        assert_eq!(severity_rank("critical"), 4);
        assert_eq!(severity_rank("unknown"), 0);
        assert_eq!(slug("MCP tool execution!"), "mcp-tool-execution");
        assert_eq!(truncate("abc", 5), "abc");
        assert!(truncate("abcdef", 3).ends_with("..."));
        assert_eq!(escape_xml("<x&y>\""), "&lt;x&amp;y&gt;&quot;");
    }
}
