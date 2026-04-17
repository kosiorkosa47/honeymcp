# Announce thread - publish tomorrow morning (09:00-11:00 CET window)

Post as a REPLY to the pinned tweet (https://x.com/0xAlpha/status/2045109578614935588) so the thread is stacked beneath the original launch. Send the first tweet then chain replies using the "+" button.

---

## 1/5

Three days ago I knew nothing about MCP. Now honeymcp v0.3.1 is live in Singapore, open-source, catching its first packets.

Full writeup just published:

<LINK_TO_BLOG>

## 2/5

Six threat detectors shipped today:

- prompt_injection_markers
- shell_injection_patterns
- recon_pattern
- secret_exfil_targets
- cve_2025_59536_config_injection
- unicode_anomaly

Each fires into a separate SQLite table with severity + evidence. Querying is one `SELECT` away.

## 3/5

Three personas ship:
- postgres-admin
- github-admin
- filesystem-admin

Each is a complete fake MCP server identity in YAML. Canned responses for common attacker probe targets (`.env`, SSH keys, `/etc/passwd`) - all REDACTED, none real. Bait only.

## 4/5

Stack: Rust, axum, tokio, rusqlite. Ships as a 35 MB Docker image. $7/mo on Lightsail Singapore. Deployment guide in the repo.

Live dashboard: http://54.169.235.208:8080/dashboard

## 5/5

If you run a public MCP server or research agent-layer security, DM.

Trading pattern notes off X. Quiet.

github.com/kosiorkosa47/honeymcp

---

## Posting notes for tomorrow

- Replace `<LINK_TO_BLOG>` in tweet 1 with the actual dev.to URL after publish
- Verify the dashboard IP `54.169.235.208` is still reachable before tweet 4
- Thread should be posted in ONE sitting, not spread across hours, so it appears as a coherent drop in followers' timelines
- Best window: 09:00-11:00 CET (EU morning + US East coast wake-up)
- After the thread, unpin the "two ways to build" launch post and pin THIS new thread so visitors land on the current state, not Day 1

## LinkedIn adaptation (shorter, corporate tone)

Post on LinkedIn after the X thread is out. Paste:

---

I spent three days building honeymcp, an open-source standalone honeypot for Model Context Protocol (MCP) servers. It's live now.

MCP is Anthropic's standard for connecting AI agents to tools. It's spreading fast - Claude Desktop, Cursor, a growing ecosystem of public MCP servers. Most published security work targets prevention (gateways, classifiers). There is almost no public telemetry on what attackers actually send to MCP servers in the wild, because no one has been running a wild honeypot to collect it.

honeymcp is an attempt to close that gap.

Technical highlights from the first three days:

- Rust, Apache-2.0
- JSON-RPC 2.0 over stdio AND HTTP+SSE
- Three YAML-defined personas (postgres-admin, github-admin, filesystem-admin)
- Six pluggable threat detectors (prompt injection, shell injection, recon patterns, secret exfil targets, CVE-2025-59536 class config injection, unicode anomalies)
- SQLite + JSONL logging with per-request remote address, User-Agent, and X-Forwarded-For capture
- Ships as a 35 MB Docker image; deploys to a $7/mo Lightsail instance in Singapore
- /stats endpoint + live dashboard

Full build-in-public writeup (1500 words, code snippets, deployment notes): <LINK_TO_BLOG>

Repo: github.com/kosiorkosa47/honeymcp

If you operate MCP infrastructure and want to trade pattern notes - DM.
