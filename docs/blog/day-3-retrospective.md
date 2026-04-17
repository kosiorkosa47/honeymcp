---
title: "How I built an MCP honeypot in 72 hours"
published: false
description: "Open-source standalone honeypot for Model Context Protocol servers, in Rust, from zero to live-on-the-internet in three days. What shipped, what didn't, and what I learned building adversarial telemetry infrastructure for AI agents in public."
tags: rust, ai, security, mcp
canonical_url: https://github.com/kosiorkosa47/honeymcp
cover_image:
---

Three days ago I decided to build a honeypot for Model Context Protocol (MCP) servers.

Not a toy. Not a demo. A real standalone server that impersonates a legitimate MCP endpoint, runs on a public VPS, and collects every request attackers send.

Today it is live in Singapore at a fresh IP, version 0.3.0, accepting connections from the open internet and logging them to SQLite. The repo is public, the license is Apache-2.0, and a tiny Twitter account pivoted from something unrelated now has a small collection of replies from AI-security researchers who noticed the framing.

This is the build log.

## Why a honeypot, specifically

MCP is Anthropic's standard for how AI agents connect to tools. It is JSON-RPC 2.0 over stdio or HTTP+SSE, the spec is at `spec.modelcontextprotocol.io`, and it is spreading fast. Claude Desktop, Cursor, editor integrations, and a growing ecosystem of public MCP servers all speak it.

Every piece of MCP security work published so far targets **prevention**: gateways like MintMCP and Aembit, prompt-injection classifiers, proxy wrappers (Trail of Bits shipped `mcp-context-protector`), and research on tool-poisoning originally coined by Invariant Labs.

There is almost nothing on **detection**, and the reason is simple: **there is no public corpus of what attackers actually send to MCP servers in the wild.** You cannot write detection rules for attacks you have never seen. The vendors running agent-security products have private telemetry; the research community does not.

A honeypot solves that asymmetry. Run a convincing-enough fake MCP server, expose it to the internet, log everything, publish what you find.

## Prior art, and where this fits

A few weeks before I started, [@barvhaim](https://github.com/barvhaim) shipped [HoneyMCP](https://github.com/barvhaim/HoneyMCP) - a Python library that injects "ghost tools" into your real FastMCP server as decoy honeypots. That is a **middleware** approach: protect the server you already run by lacing it with tripwires.

My project, confusingly also called honeymcp (lowercase, Rust) takes the opposite shape:

**Middleware** (theirs): ghost tools inside your real server, protects YOUR deployment.

**Standalone** (ours): a fake MCP server in the wild, collects telemetry on attackers who aren't targeting anyone specific, publishes the corpus.

Different problems, complementary approaches. I posted the distinction as my first tweet from the rebranded account and tagged them; the response was cordial.

## What shipped in three days

### Day 1 - the protocol

Day 1 was the minimum viable MCP server: JSON-RPC 2.0 over stdio, handle `initialize` / `tools/list` / `tools/call`, load a persona from YAML, log every request to SQLite and an optional JSONL mirror. Apache-2.0, six commits, 15 passing tests, CI pipeline running fmt + clippy + tests on Ubuntu + macOS.

The stack:

```toml
tokio = "1"
serde = "1"
serde_yaml = "0.9"
rusqlite = { version = "0.31", features = ["bundled"] }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
tracing = "0.1"
```

No `unwrap()` in production paths. Everything returns `anyhow::Result`. `tracing` goes to stderr so it never corrupts the JSON-RPC frames on stdout.

### Day 2 - HTTP + Docker + deployment

Day 2 added the HTTP+SSE transport (axum 0.7), a second persona (`github-admin`), a multi-stage Dockerfile, a deployment guide, and four new columns on the event table (`transport`, `remote_addr`, `user_agent`, `client_meta`) so the honeypot can capture who is hitting it, from where, and with what tool.

I also learned that `time-core 0.1.8` silently pinned my Rust MSRV to 1.88 via edition 2024, which broke my planned `rust:1.82-slim-bookworm` base image. Lesson: check `cargo tree -d` when pinning a Docker stage to an older toolchain.

The Transport trait looks like this:

```rust
#[async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle_request(
        &self,
        req: JsonRpcRequest,
        ctx: RequestContext,
    ) -> Option<JsonRpcResponse>;
}

#[async_trait]
pub trait Transport: Send {
    async fn run(&mut self, handler: Arc<dyn Handler>) -> anyhow::Result<()>;
}
```

`RequestContext` threads per-request metadata (session id, transport tag, remote address, user agent, CloudFlare / X-Forwarded-For chain) from the wire into the dispatcher. Stdio fills it in with its fixed session id; HTTP pulls it from `ConnectInfo` and headers.

POST `/message` returns the JSON-RPC response in the body AND forwards a copy to any SSE subscriber for the same session. This is technically looser than strict MCP spec compliance (spec says POST returns 202, response only on SSE), but attackers often skip the SSE part and just hammer POST. Being generous about what we accept means catching more of them.

### Day 3 - detection + third persona + /stats

Day 3 was the first day with real adversarial content. I wrote six threat detectors:

| Detector | Category | Fires on |
|----------|----------|----------|
| `prompt_injection_markers` | PromptInjection | "ignore previous", "<\|im_start\|>", role tokens, multi-lingual variants |
| `shell_injection_patterns` | CommandInjection | `$(...)`, backticks, `curl \| sh`, chained exec |
| `recon_pattern` | Recon | Repeated `tools/list`, `tools/call` before `initialize` |
| `secret_exfil_targets` | SecretExfil | `.env`, SSH keys, cloud creds, GitHub/OpenAI tokens |
| `cve_2025_59536_config_injection` | SupplyChain | `.claude/settings.json` + hook registration |
| `unicode_anomaly` | UnicodeAnomaly | Zero-width, bidi overrides, tag-block glyphs |

Each detector is stateless but gets a small `SessionStats` snapshot (how many calls in this session, how many `tools/list` etc.) so the Recon detector can distinguish a well-behaved client (one list + many calls) from a scanner.

The trait is small:

```rust
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn category(&self) -> DetectionCategory;
    fn analyze(&self, ctx: &DetectionContext) -> Option<Detection>;
}
```

Each match writes a row into a separate `detections` table with a FK to `events(id)`, a severity, a short evidence excerpt, and the detector name. Analysis queries stay clean:

```sql
SELECT category, severity, COUNT(*)
FROM detections
GROUP BY category, severity
ORDER BY 3 DESC;
```

I added a third persona (`filesystem-admin`) with canned responses for `/etc/passwd`, `.env`, AWS credentials, SSH private keys - all REDACTED placeholders, none real. The persona exists because filesystem-style MCP servers are an attractive attacker target, so the bait needs to match.

Finally, `GET /stats` returns a JSON snapshot of the honeypot's public-facing metrics: uptime, total events, detections by category, top tools called, unique remote addresses in the last 24h. This is the surface I will hang a live dashboard on next.

## The deployment story

honeymcp runs on **AWS Lightsail in `ap-southeast-1` (Singapore), `micro_3_0` tier, $7/mo.**

Why Singapore: lower baseline latency to APAC scanners, and it gives the project a specific geographic identity on the network. Why Lightsail specifically: same UX as DigitalOcean but without the region-restriction-for-new-accounts issue I hit on DO.

Why $7/mo and not $5/mo nano: the $5 tier has 512 MB RAM, which is enough to RUN honeymcp but not enough to `cargo build` or `docker compose build` on-box. Rust compilation at release profile with LTO needs ~1.5 GB of RAM for our dependency tree (~100 crates). I got around that by building the Docker image on my laptop (`docker buildx build --platform linux/amd64`), then shipping it over SSH:

```bash
docker save honeymcp:0.3.0 | gzip | \
  ssh ubuntu@<ip> 'gunzip | sudo docker load'
```

35 MB image, one pipe, no registry needed.

The one thing that cost me 10 minutes: Docker volumes. The container runs as non-root UID 999 (I added `useradd -r honeymcp` in the Dockerfile for obvious reasons), and the host `./data` directory was owned by root. SQLite couldn't open the database file. Fix: `chown -R 999:999 ./data` on the host. Documented in `docs/DEPLOYMENT.md`.

## What it doesn't do yet

**No meaningful telemetry yet.** The honeypot has been on the internet for a few hours. That is not enough time for a fresh IP with no inbound signal to attract anything beyond incidental port scanners. Realistic first attack window: 24-72 hours. First data-drop post probably Day 5 or 6.

**No live dashboard.** `/stats` returns JSON; I will wire a vanilla-JS polling page on top next. 30 minutes of work.

**No sampling attack.** MCP now has a `sampling/createMessage` method where the server asks the client for completions - an inverted attack surface. I am not emulating it yet. On the roadmap.

**No HTTP streaming transport.** I implement the older HTTP+SSE transport; the newer single-endpoint Streamable HTTP transport is separate work.

**Three personas is thin.** `postgres-admin`, `github-admin`, `filesystem-admin`. What the ecosystem actually needs is a Slack-impersonator, a Notion-impersonator, a Linear-impersonator. I will write the next one based on the first pattern the honeypot captures - whatever attackers are asking for, I will serve back a plausible-looking version of it.

## What I learned

**Standalone beats middleware for telemetry.** Middleware protects what you already run; standalone learns what is out there. Both are needed; they do not compete.

**Accept liberally.** Being strict about MCP spec compliance (POST-returns-202-only) would reject a lot of lazy scanner traffic. For a honeypot, that is the opposite of what you want. Respond helpfully to the loosest possible superset of the protocol, log everything, score anomalies later.

**Personas are the entire product.** The Rust code is infrastructure. The persona YAMLs are what attract attackers and shape what they try. A honeypot with one great persona catches more than one with five mediocre ones. Future work is persona quality, not more features.

**Distribution matters more than code.** Shipping version 0.1 in one day was meaningless until I pinned a tweet that framed the problem sharply. The first 48 hours of a public project are dominated by positioning, not implementation.

**Building in public is a lie if nobody sees it.** Twelve replies to people in the niche in one afternoon moved this from invisible to mentioned. No amount of README polish would have done that.

## How to help

- Star the repo: `github.com/kosiorkosa47/honeymcp`
- Open an issue with a persona idea: what MCP server do you think attackers most want to hit?
- If you operate an MCP server on the public internet and want to trade pattern notes, DM me on X ([@0xAlpha](https://x.com/0xAlpha))
- If you run a private MCP honeypot or sensor and have publishable telemetry, let's compare notes

Day 4 starts tomorrow. First attack report goes out when the data is real.

*honeymcp is Apache-2.0, in Rust, and is not affiliated with Anthropic or any MCP maintainer. The repository is at https://github.com/kosiorkosa47/honeymcp. Telegram, Slack, Discord - nothing of mine is on those platforms yet; everything flows through X and GitHub for now.*
