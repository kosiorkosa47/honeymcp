<p align="center">
  <img src="assets/honeymcp-logo.png" alt="honeymcp logo" width="260"/>
</p>

# honeymcp

[![CI](https://github.com/kosiorkosa47/honeymcp/actions/workflows/ci.yml/badge.svg)](https://github.com/kosiorkosa47/honeymcp/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

> An open-source honeypot for the [Model Context Protocol](https://spec.modelcontextprotocol.io/) — impersonates a legitimate MCP server to collect threat intelligence on attacks against the MCP ecosystem.

**Status:** Building toward v1.0 on a 28-day sprint. Currently speaks Streamable HTTP (MCP spec 2025-06-18) and legacy HTTP+SSE side by side.

**Live:** [operator banner](http://54.169.235.208/) + [dashboard](http://54.169.235.208/dashboard).

## What this is

honeymcp is a **passive sensor**, not a proxy or a firewall. You stand it up on an internet-reachable host (VPS, home lab, cloud edge — the binary is ~15 MB and runs under 256 MiB of RAM), point DNS at it, and it behaves convincingly enough like a real MCP server that anyone scanning for or attacking MCP endpoints talks to it instead of moving on. Every request they send is logged, classified, and redacted before it lands on disk.

Concretely, an MCP client — a desktop agent, an IDE integration, an autonomous research runner, or a hostile scanner — connects over **stdio** or **HTTP** and speaks JSON-RPC 2.0. honeymcp completes the handshake, lists a plausible catalogue of tools from a **persona** YAML file you control (the default `postgres-admin` persona advertises a read-only SQL introspection surface; `github-admin` advertises repo admin), then returns canned, deterministic responses to `tools/call`. The attacker sees a live, responsive MCP server; you see the complete protocol trace, a SHA-256 hash of their parameters, the IP and User-Agent they arrived from, and the `MCP-Protocol-Version` header they claim. Seven independent detectors (prompt injection, shell injection, CVE-2025-59536-class hook injection, secret exfiltration attempts, unicode smuggling, reconnaissance patterns, tool-enumeration behaviour) tag each event at write time so analysts can filter for interesting traffic without scanning the whole corpus.

The operator-facing surface is small on purpose. `GET /` serves a plain-text **research-honeypot banner** with a GDPR-compliant disclosure and an abuse contact; `GET /dashboard` is a single-page HTML view over the live SQLite store; `GET /stats` returns JSON aggregates the dashboard consumes. There is no admin panel, no auth, no mutable server state exposed to the network. A separate binary, **`honeymcp-probes`**, ships in the same crate: it fires the same 13-payload attack battery that the detectors are tuned for, which lets defenders audit their *own* MCP servers without running the sensor or waiting for real attacks.

The captured data is what makes this useful. There is no publicly-available corpus of what attackers actually send to MCP servers — the protocol is new, the products using it ship quickly, and the threat-intel feeds that cover the traditional web-app class do not cover this layer yet. Running honeymcp produces that corpus for your deployment, and — with the upcoming weekly report pipeline — a redacted public telemetry feed the ecosystem can use. Captured payloads are redacted for obvious secrets (GitHub PAT, AWS access keys, PEM blocks, JWT-shaped tokens, Slack tokens) at write time in both directions, so neither the echo-back nor the log carries live credentials the attacker sent.

On the build side, this is a Rust 1.88+ single-static-binary daemon (one `cargo build --release`, no runtime deps beyond libc). Storage is SQLite by default; a Postgres backend with pgvector is available opt-in for deployments that want multi-host ingestion or embedding-based clustering. Observability is stderr-pretty-text by default, flips to structured ndjson with `HONEYMCP_LOG_FORMAT=json`, and forwards OpenTelemetry traces to any OTLP collector when built with `--features otel`. Container images are multi-arch (amd64 + arm64) and **cosign-keyless signed** via OIDC — the signing identity is the GitHub Actions runner that built the image, not a key in a vault, so every release is cryptographically tied to a specific commit in this repo.

## Why

MCP is a young protocol with a rapidly growing attack surface: **tool poisoning**, **prompt injection** carried through tool descriptions and results, **command execution** bugs in servers (e.g. `CVE-2025-59536`), and **data exfiltration** through tool calls into LLM context. There is no good public corpus of what attackers are actually doing against real MCP servers. `honeymcp` aims to be a drop-in honeypot that produces that data.

## What it does today

- Speaks **JSON-RPC 2.0 over stdio** (the baseline MCP transport).
- Speaks **Streamable HTTP** (MCP spec 2025-06-18): `POST /mcp` with `Accept`-based negotiation (JSON or single-message SSE), `GET /mcp` for server-to-client SSE, `DELETE /mcp` for explicit session teardown, session identified by `Mcp-Session-Id` header.
- Speaks **legacy HTTP+SSE** (`POST /message`, `GET /sse`) for older clients that have not moved to the 2025-06-18 transport yet.
- Handles `initialize`, `tools/list`, `tools/call`, and the common `notifications/*` frames.
- Records `MCP-Protocol-Version`, `X-Forwarded-For`, `Accept`, and `User-Agent` alongside every request for threat-intel correlation.
- Loads a **persona** from YAML — server name, version, instructions, and a list of fake tools with canned responses.
- Ships **two personas** out of the box: `postgres-admin` and `github-admin`.
- Ships as a **Docker image** for one-command deploy; release builds are cosign-keyless-signed with SPDX + CycloneDX SBOMs attached.
- Serves an **operator banner** (research-honeypot disclosure + GDPR contact) at `GET /`, dashboard at `/dashboard`.
- Runs **seven threat detectors** (prompt injection, shell injection, CVE-2025-59536-class hook injection, secret exfil, unicode anomaly, recon, tool enumeration) on every request, tagging events at write time.
- Logs every request/response to **SQLite** (primary, queryable) and optionally mirrors to **JSONL** (grep/jq-friendly), including timestamp, method, SHA-256 of params, raw params, client name/version, session id, transport, remote address, and User-Agent.

Clustering, embeddings and a public weekly threat report come in later days of the sprint (see `.local-plans/` if you are the maintainer).

## Quickstart

```bash
cargo build --release

./target/release/honeymcp \
    --persona personas/postgres-admin.yaml \
    --db hive.db \
    --jsonl hive.jsonl
```

Feed it a handshake manually to verify it's alive:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"tools/list","id":2}' \
  '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"list_tables","arguments":{}}}' \
  | ./target/release/honeymcp --persona personas/postgres-admin.yaml --db hive.db
```

Inspect collected events:

```bash
sqlite3 hive.db 'SELECT method, client_name, response_summary FROM events ORDER BY id DESC LIMIT 20;'
```

For deploying the honeypot on a public VPS with HTTPS, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

<details>
<summary>Example session output</summary>

```
$ printf '%s\n' \
    '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
    '{"jsonrpc":"2.0","method":"tools/list","id":2}' \
    '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"list_tables","arguments":{}}}' \
  | ./target/release/honeymcp --persona personas/postgres-admin.yaml --db hive.db

--- stdout (JSON-RPC responses) ---
{"jsonrpc":"2.0","result":{"capabilities":{"tools":{"listChanged":false}},"instructions":"Postgres admin MCP server. Provides read-only introspection tools for an internal production database. All queries are audited.","protocolVersion":"2024-11-05","serverInfo":{"name":"postgres-admin","version":"15.4"}},"id":1}
{"jsonrpc":"2.0","result":{"tools":[{"description":"Execute a read-only SQL query against the primary database.","inputSchema":{"properties":{"sql":{"description":"SQL statement to execute.","type":"string"}},"required":["sql"],"type":"object"},"name":"query"}, ...]},"id":2}
{"jsonrpc":"2.0","result":{"content":[{"text":"public.users\npublic.orders\npublic.sessions\npublic.api_keys\npublic.audit_log\n","type":"text"}],"isError":false},"id":3}

--- stderr (tracing, plain text) ---
2026-04-17T09:20:46Z  INFO honeymcp: persona loaded persona=postgres-admin tools=4
2026-04-17T09:20:46Z  INFO honeymcp::server: session started session=postgres-admin-...
2026-04-17T09:20:46Z  INFO honeymcp::server: session ended session=postgres-admin-...

$ sqlite3 hive.db 'SELECT COUNT(*), method FROM events GROUP BY method;'
1|initialize
1|tools/call
1|tools/list
```

Full unabridged capture: [`docs/demo-day1.txt`](docs/demo-day1.txt).

</details>


## Architecture

```mermaid
flowchart LR
    Client["MCP client<br/>(attacker)"] -- "JSON-RPC 2.0<br/>newline-delimited" --> Transport[stdio transport]
    Transport --> Session[Session dispatcher]
    Persona[(persona<br/>YAML)] --> Session
    Session -->|initialize| Init[InitializeResult]
    Session -->|tools/list| List[ToolsListResult]
    Session -->|tools/call| Call[ToolCallResult<br/>canned text]
    Session --> Logger
    Logger --> SQLite[(SQLite<br/>events table)]
    Logger --> JSONL[(JSONL append log)]
```

## Project layout

```
src/
  protocol/    JSON-RPC 2.0 + MCP payload types
  transport/   Transport trait, stdio + http (Streamable + legacy SSE)
  persona/     YAML persona loader + validator
  detect/      Seven detectors (prompt_injection, shell_injection,
               cve_59536, secret_exfil, unicode_anomaly, recon,
               tool_enumeration)
  logger/      SQLite + JSONL structured logging
  server.rs    Session / request dispatcher
  main.rs      CLI entry (clap)
  bin/probes.rs  honeymcp-probes audit CLI
personas/      Example personas (postgres-admin, github-admin)
docs/
  DEPLOYMENT.md         VPS deploy guide (Caddy + systemd)
  threat-model.md       STRIDE pass + known gaps
  legal/operator-banner.md   Research-honeypot banner template
  legal/privacy-gdpr-lia.md  GDPR Art. 6(1)(f) LIA
```

## Persona format

```yaml
name: "postgres-admin"
version: "15.4"
instructions: "..."
tools:
  - name: "query"
    description: "..."
    inputSchema: { type: object, properties: { sql: { type: string } } }
    response: "... fake result text ..."
```

The persona is the only knob you need to turn to impersonate a new service.

## honeymcp-probes

Ships as a second binary in this crate. A CLI battery of 13 attack payloads you point at any MCP endpoint to see what gets through:

```bash
honeymcp-probes --target http://your-mcp-server/message

# JSON report for CI:
honeymcp-probes --target http://your-mcp-server/message --json > report.json

# Fail the build if any Critical-severity probe gets HTTP 2xx back:
honeymcp-probes --target http://your-mcp-server/message --fail-on-critical
```

The probe taxonomy mirrors the server's detector taxonomy exactly — anything `honeymcp-probes` sends is something `honeymcp` is tuned to spot. Defenders can audit their own MCP server without needing to run the sensor.

## Development

Clone, then enable the versioned pre-commit hook (runs `cargo fmt --check` + `cargo clippy -D warnings` before every commit):

```bash
git config core.hooksPath .github/hooks
```

Toolchain: Rust 1.88+ (edition 2024 dependencies); the repo pins 1.89.0 via `rust-toolchain.toml` for local dev so `cargo-audit` / `cargo-deny` install cleanly.

```bash
make ci           # fmt-check + clippy -D warnings + test + audit + deny
make test         # just the tests
make coverage     # lcov.info via cargo-llvm-cov
make docker       # local image build
```

### Optional feature flags

Default build is SQLite + stderr logs, no external services. Two opt-in features:

- `--features postgres` — Postgres backend via sqlx 0.8.6 (pgvector-ready). Pair with `docker compose up -d postgres && make db-migrate` for a local dev DB. Concrete backend wiring is still in progress; the feature currently compiles the scaffolding only.
- `--features otel` — OpenTelemetry OTLP exporter. Spans are forwarded via gRPC/tonic to `OTEL_EXPORTER_OTLP_ENDPOINT` when set; the layer is not registered otherwise, so enabling the feature without setting the env var costs nothing.

### Runtime env vars

| Var | Effect |
|---|---|
| `RUST_LOG` | Standard `tracing` filter, default `info` |
| `HONEYMCP_LOG_FORMAT` | `pretty` (default, human-readable stderr) or `json` (ndjson for Loki / Cloudwatch / Datadog) |
| `HONEYMCP_BANNER_CONTROLLER` | Substituted into the banner served at `GET /` |
| `HONEYMCP_BANNER_ABUSE_EMAIL` | Contact address on the banner (GDPR Art. 13/14 + Art. 17 channel) |
| `HONEYMCP_BANNER_CONTACT` | Optional human contact name on the banner |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | gRPC OTLP collector URL (only with `--features otel`) |
| `OTEL_SERVICE_NAME` | Overrides `service.name` resource; defaults to `honeymcp` |

Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md) (security disclosure → [`SECURITY.md`](SECURITY.md)).

## Prior art & why honeymcp

Adjacent work exists but targets different layers:

- **MCP gateways** (MintMCP, Aembit) — protective proxies for legitimate deployments, not deception.
- **Prompt-injection classifiers** (StackOne Defender, Augustus, CloneGuard) — detect payloads, don't generate attack telemetry.
- **Agent red-team tools** (DeepTeam, Garak) — offensive side, not passive collection.

`honeymcp` fills a gap: **passive intel collection** on what attackers actually send to MCP servers in the wild, with server-shape accurate enough to sustain multi-turn interaction. Maps to OWASP Top 10 for Agentic Applications 2026 — **ASI04 (Agentic Supply Chain Vulnerabilities)** and **ASI05 (Unexpected Code Execution)**.

## Roadmap toward v1.0

Working target: `v1.0.0-rc.1` on a 28-day sprint.

| Week | Focus | Status |
|------|-------|--------|
| 1 — Foundation | stdio + Streamable HTTP + legacy HTTP+SSE, 7 detectors, CI (fmt + clippy + test matrix + audit + deny + coverage), signed release workflow, threat model + GDPR LIA | ✅ shipped |
| 2 — Infrastructure | Postgres + pgvector backend, Terraform module set, multi-region deploy (EKS central + k3s edges), observability stack | in progress |
| 3 — Analysis | Embeddings pipeline, rule + LLM classifier against OWASP T1–T15, HDBSCAN clustering, weekly report generator | pending |
| 4 — Dashboard + v1.0 | Web dashboard (live feed + clusters + reports), STIX 2.1 export, landing page, security hardening, cut `v1.0.0-rc.1` | pending |

## Verify a release

Release images and tag artifacts are signed via cosign keyless (OIDC). To verify before deploying:

```bash
cosign verify ghcr.io/kosiorkosa47/honeymcp:vX.Y.Z \
  --certificate-identity-regexp 'https://github.com/kosiorkosa47/honeymcp/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

SBOMs (SPDX + CycloneDX) are attached to each GitHub Release and also attested to the container image digest.

## License

Apache-2.0 — see `LICENSE`.
