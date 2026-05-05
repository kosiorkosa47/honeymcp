# MITRE ATT&CK / ATLAS mapping

Each detector emits a `mitre_techniques` slice that's persisted into the
`detections.mitre_techniques` column as a JSON array. SIEM consumers
(Splunk ES, Sentinel, Elastic, OpenSearch) can pivot directly on
technique IDs without having to re-derive the mapping from `detector`
or `category`.

The mapping below is intentionally conservative — every entry has a
direct evidence link, not a "could-conceivably-fit" association.

## Enterprise techniques

| Detector | Technique IDs | Justification |
| --- | --- | --- |
| `shell_injection_patterns` | `T1059`, `T1059.004`, `T1059.001` | Command and Scripting Interpreter / Unix Shell / PowerShell — the regex matches `curl \| sh`, `$(...)`, `;rm`, IEX-shaped chains |
| `recon_pattern` (tools/list flooding) | `T1518`, `T1083` | Software Discovery — repeated tools/list is the MCP analogue of probing installed tooling |
| `recon_pattern` (handshake skip) | `T1190`, `T1518` | Exploit Public-Facing Application — bypassing initialize is a protocol-level probe |
| `secret_exfil_targets` | `T1552`, `T1552.001`, `T1552.005` | Unsecured Credentials / Credentials In Files / Cloud Instance Metadata API — regex matches `~/.aws/credentials`, `.env`, IMDS, `metadata.google` |
| `cve_2025_59536_config_injection` | `T1190`, `T1059` | Exploit Public-Facing Application — CVE-2025-59536 is a remote config injection in `mcp-remote` chaining to RCE |
| `unicode_anomaly` | `T1027`, `T1036.005` | Obfuscated Files or Information / Match Legitimate Resource Name — bidi marks + tag-block + homoglyph subsets |
| `tool_enumeration` | `T1518`, `T1083` | Software Discovery — calling many distinct tools per session maps installed capabilities |

## ATLAS techniques (LLM-specific)

| Detector | Technique IDs | Justification |
| --- | --- | --- |
| `prompt_injection_markers` | `AML.T0051`, `AML.T0054` | LLM Prompt Injection / LLM Jailbreak — covers direct override needles + DAN-style payloads |

## Why a separate column instead of joining on `detector`

Two reasons:

1. **Stability.** Detector names are honeymcp internals; ATT&CK technique
   IDs are a stable external vocabulary. SIEM dashboards that key on
   technique IDs don't break when honeymcp renames a detector.
2. **Multi-mapping.** Detectors frequently map to multiple techniques
   (parent + sub-technique). A column of JSON arrays expresses that
   directly without a join table.

## Querying

```sql
-- All detections that map to T1059 (Command Execution)
SELECT id, detector, evidence
FROM detections
WHERE mitre_techniques LIKE '%T1059%';

-- Distinct technique IDs observed (SQLite JSON1)
SELECT DISTINCT json_each.value AS technique
FROM detections, json_each(detections.mitre_techniques)
ORDER BY technique;
```
