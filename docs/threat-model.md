# Threat Model — honeymcp

This document describes how honeymcp can be misused or compromised, what is
currently defended, and where the known gaps are. It is written for operators
(people running a honeymcp instance on their own infrastructure) and for
contributors, not as a legal document.

- **Framework:** STRIDE (Spoofing, Tampering, Repudiation, Information
  disclosure, Denial of service, Elevation of privilege).
- **Last reviewed:** 2026-04-24 for honeymcp v0.5.0 + `main` (Streamable HTTP
  transport).

## 0. System context

A honeymcp deployment is one process that speaks the Model Context Protocol
(MCP) in two flavours:

- `stdio`: the process is spawned by a local MCP client (e.g. Claude Desktop).
- `http`: the process listens on a TCP port and speaks Streamable HTTP
  (`POST /mcp`, `GET /mcp`) and the legacy HTTP+SSE flow (`POST /message`,
  `GET /sse`).

The process loads a **persona** (tool catalogue + canned responses) from a
YAML file and serves plausible MCP responses back. Each request and response
is passed through a set of **detectors** (prompt injection, shell injection,
recon, etc.) and persisted to SQLite and optionally a JSONL mirror.

There are **three trust zones**:

1. **Attacker** — unauthenticated internet client, potentially scripted.
2. **Operator** — the human running the honeypot. Has the persona files,
   the database, and the host.
3. **Consumer of threat intel** — later readers of the captured corpus.

honeymcp is designed so that attackers stay in zone 1 even when they
successfully exercise the attack payloads we want to capture.

## 1. Data / secrets honeymcp itself handles

- **Captured request payloads** — may contain attacker-supplied content that
  looks like credentials (fake or real). honeymcp redacts aggressively when
  writing to logs (`src/bin/probes.rs::redact_secrets` applies the same
  patterns for outbound probe responses).
- **Persona canned responses** — static, in repo or YAML. Should not contain
  real credentials. Operator responsibility.
- **Remote address** — logged. Treated as personal data under GDPR (see
  `docs/legal/privacy-gdpr-lia.md`).
- **User-Agent + X-Forwarded-For** — logged alongside remote address.
- **SQLite DB** — local file. Operator is the controller.

## 2. STRIDE walkthrough

### 2.1 Spoofing

| Threat | Mitigation | Gap |
|---|---|---|
| Attacker impersonates a legitimate MCP client to bypass some logical check | No attempt at authentication; every client is assumed hostile | N/A — this is by design, we want all traffic |
| Attacker spoofs `X-Forwarded-For` to poison the logged `remote_addr` | Trust is placed in the reverse proxy operator. Behind Caddy / nginx the first hop is authoritative. Direct-exposed deployments should NOT trust XFF | No per-deployment toggle. Operator must either run behind a trusted proxy or edit `src/transport/http.rs` to use raw peer |
| Another process on the same host impersonates honeymcp on the same port | OS-level port binding; not distinct from any other TCP listener | Out of scope |

### 2.2 Tampering

| Threat | Mitigation | Gap |
|---|---|---|
| Attacker modifies persona YAML to change honeymcp behaviour | Persona file is read from disk at startup, requires host access. No in-protocol way to update persona from a client session | N/A |
| Attacker modifies SQLite DB to poison intel | Same — requires host access | In shared-tenancy deployments, DB file should be outside any network share |
| Supply-chain tampering of Rust crates | `cargo audit` + `cargo deny` in CI | `cargo vet` / `cargo crev` not yet configured |
| Supply-chain tampering of container image | Multi-stage Dockerfile + distroless base; release images signed with cosign keyless (OIDC) and SBOM-attested | Users must actively run `cosign verify` before deploying |

### 2.3 Repudiation

| Threat | Mitigation | Gap |
|---|---|---|
| Attacker claims they never sent a request | Every request logged with timestamp, remote address, session id, client name/version, transport, SHA-256 of params, raw params | No tamper-evident append-only log (e.g. transparency-log style). DB owner can still redact history |
| Operator claims the honeypot did not capture something | Same logging, plus optional JSONL mirror for independent grep | Operator owns both — consumers of the intel have to trust the operator |

### 2.4 Information disclosure

This is where most of the work happens. A honeypot by definition logs things,
and leaking the log back to the attacker is one of the worst failure modes.

| Threat | Mitigation | Gap |
|---|---|---|
| Attacker drops a live credential into a tool call; honeymcp echoes it back in the JSON-RPC result | Response payloads are static from persona YAML; no echoing of request content | Detectors may surface matched content to the dashboard — **do not expose the dashboard to the public internet** |
| Attacker triggers verbose error that leaks server stack / versions | axum default error handling kept, no debug bodies in production; `RUSTFLAGS: -D warnings` catches unintended debug prints | Error bodies for malformed JSON still include parser message; acceptable because it's JSON-RPC `-32700` boilerplate, but a hardened build could suppress |
| Detection of honeymcp via banner / dashboard fingerprint | **Accepted leak.** A honeypot that hides its dashboard is a honeypot that silently mis-attributes real production traffic. We serve a documented research banner (`docs/legal/operator-banner.md`) at `GET /` | N/A |
| Secrets in captured payloads leak to logs / stdout | `redact_secrets` replaces known tokens (GitHub PAT, AWS access keys, PEM keys, JWTs, Slack tokens) before writing response text | Request params stored raw for forensics; redaction only applies to responses and to probe outputs |
| Attacker reads the DB via SQL injection in some helper endpoint | No query parameters are interpolated into SQL; we use prepared statements everywhere | N/A; keep this invariant if adding endpoints |
| `/stats` / `/dashboard` expose attacker IPs to the world | Dashboard is unauthenticated by design (low-value live view, aggregates only). Deployments that want to keep this private should put it behind a VPN or reverse-proxy auth | No built-in basic-auth toggle |

### 2.5 Denial of service

| Threat | Mitigation | Gap |
|---|---|---|
| Single-IP flood against `POST /message` or `POST /mcp` | `tower_governor` per-IP token bucket: 2 req/s sustained, 20 burst | Distributed flood (botnet) not mitigated at app layer — push to the reverse proxy / Cloudflare |
| Memory exhaustion via oversized body | `RequestBodyLimitLayer` caps request body at 256 KiB | Very large streaming responses from persona not currently possible (persona is static), so no outbound cap needed |
| ReDoS in detector regexes | Each detector regex is bounded (`{1,N}` quantifiers, no nested ambiguity) and compiled lazily. Unit tests cover adversarial inputs | Adding new detectors without regex review is the risk — see CONTRIBUTING.md checklist |
| SSE subscriber leak | `/sse` and `/mcp` GET evict on client disconnect; keep-alive every 15s | Long-lived connections from hostile clients could pile up. `tower_governor` applies to the initial GET so practical ceiling is ~20 concurrent SSE per IP |
| Persistent-connection slow-loris via Streamable HTTP SSE | axum / hyper timeouts at the transport layer | No explicit per-connection write timeout; consider `tower-http::timeout` layer |

### 2.6 Elevation of privilege

| Threat | Mitigation | Gap |
|---|---|---|
| RCE via deserialisation of attacker JSON-RPC | serde_json + strongly typed `JsonRpcRequest`; no dynamic dispatch into user-supplied code paths | N/A |
| RCE via `shell_injection` / `cve_59536` detector patterns firing inside the honeypot | Detectors are pure string matchers, never execute payloads | Invariant: detectors MUST NOT use regex `replace` with attacker data into a shell or into `format!` that lands in a command line |
| Container escape | Multi-stage Dockerfile + distroless base; runs as unprivileged UID; `--read-only` friendly; no CAP_SYS_ADMIN needed | User-namespaced host recommended; we do not prescribe a specific runtime |

## 3. Honeypot-specific concerns

### 3.1 Legal exposure of operator

Running a device that intentionally accepts malicious traffic carries its own
legal surface. See:

- `docs/legal/privacy-gdpr-lia.md` for the GDPR Legitimate Interest Assessment.
- `docs/legal/operator-banner.md` for the plain-language banner shown at
  `GET /`.

The operator is the controller for any personal data captured (IP addresses,
user-agents). The defaults err on the side of less collection — no payload
beyond what the attacker sent, no third-party trackers, no cloud analytics.

### 3.2 Use as an attack tool

honeymcp contains attack *signatures* (detectors) and a probe CLI that fires
known-bad MCP payloads. The intent is defenders auditing their own servers
or pentesters in scoped engagements. The probe CLI has no auth, does not
self-scope, and does not refuse to talk to arbitrary targets.

Contributions that turn honeymcp into a more general attack framework (e.g.
persona-driven credential dumping from real upstream MCP servers, automatic
spraying) will not be merged — see `CONTRIBUTING.md`.

### 3.3 Shared-tenancy / collaborative research

If a single honeymcp instance is fed by many operators (multi-tenant honey
farm), the attacker-controlled content in the DB is a shared surface. None
of the detectors or dashboard code currently renders raw payload bytes as
HTML, but any future downstream tool that consumes the DB should treat the
`params_raw` column as tainted.

## 4. What is explicitly out of scope for now

- Byzantine operators writing to the DB directly.
- Bribed / compromised CI runners exfiltrating release-signing identity.
- Side-channel attacks against the host.
- Anything downstream of the captured corpus once it leaves the operator.
- Attacks targeting the Rust compiler itself.

## 5. Next review triggers

Re-run the STRIDE pass when any of the following changes:

- A new transport is added (e.g. WebSocket, HTTP/3, MQTT bridge).
- A new detector category is introduced that might regex-match on response
  bodies rather than just request params.
- The storage backend changes (SQLite → Postgres migration is planned).
- Any auth / session-state mechanism lands (currently stateless-per-session).
- A new category of user-supplied input appears (e.g. operator-uploaded
  personas via web UI instead of file).
