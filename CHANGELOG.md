# Changelog

## [0.4.0] - 2026-04-18 (Day 4)

### Added

- **`honeymcp-probes`** binary: a CLI that hammers an MCP endpoint with 13
  attack payloads (prompt injection, shell injection, secret-exfil targets,
  CVE-2025-59536-class hook injection, unicode smuggling, recon patterns) and
  reports what the server accepted. Intended use: defenders auditing their
  own MCP servers; CI gate via `--fail-on-critical`; researchers benchmarking
  MCP-security products. Shares the Rust crate and the attack taxonomy with
  the server-side detectors so what `probes` sends is exactly what `honeymcp`
  is tuned to detect.

### Changed

- **Real remote address preserved through reverse proxies.** The HTTP
  transport now prefers the first hop in `X-Forwarded-For` over the raw
  socket peer when building `RequestContext::remote_addr`. Deployments
  sitting behind Caddy / nginx / Cloudflare now log the actual attacker IP
  instead of the proxy's loopback address. Sample deployment uses Caddy on
  port 80 proxying to the honeymcp container on 8080; Caddy's Caddyfile is
  a one-liner.

## [0.3.3] - 2026-04-17 (Day 3 late night)

### Security hardening pass

- **Per-IP rate limit on `/message`**: token bucket via `tower_governor`, 2 req/s
  sustained with a 20-request burst. Other endpoints (`/sse`, `/stats`,
  `/dashboard`, `/healthz`) remain unthrottled so observability stays responsive
  during a flood against the ingest path.
- **Request body cap**: 256 KiB on `/message`. Larger payloads are rejected
  before they touch the JSON parser.
- **ReDoS guard**: every quantifier in `secret_exfil` and `shell_injection`
  regexes now has an upper bound. No open-ended `{N,}` or `*` that touches
  attacker input remains.
- **Container hardening** (docker-compose.yml): `mem_limit=256m`, `cpus=0.5`,
  `pids_limit=256`, `cap_drop: ALL`, `security_opt: no-new-privileges`,
  `read_only: true` rootfs with `/tmp` as 32 MB tmpfs. Log rotation 3x10 MB.
- **Dockerfile HEALTHCHECK** script that curls `/healthz` every 30 s.
- **SQLite ring-buffer**: events table is capped at 1,000,000 rows; when the
  limit is crossed we drop the oldest 100,000 rows in a single batched delete
  (detections cascade). Opportunistic trim every 1,000 inserts.
- **Params truncation**: payload values over 64 KiB are stored as a truncation
  marker with only a 2 KB prefix, preventing a single crafted request from
  writing tens of megabytes into the DB.
- **cargo-audit** now runs on every push/PR in CI via `rustsec/audit-check@v2`.

## [0.3.2] - 2026-04-17 (Day 3 night)

### Added
- Seventh detector: `tool_enumeration` fires when a single session invokes
  `tools/call` more than six times across different tool names, a scanner
  signature.
- SecretExfilDetector now covers `/etc/passwd`, `/etc/group`, `/proc/*/environ`,
  `.git-credentials`, `.ssh/known_hosts`, `.aws/config`, `.npmrc`, `.pypirc`,
  `credentials.json`, `service-account.json`, Anthropic `sk-ant-` key prefix,
  literal AWS `AKIA/ASIA` access-key ids in payloads, and inline
  `-----BEGIN * PRIVATE KEY-----` headers.

## [0.3.1] - 2026-04-17 (Day 3 evening)

### Added
- Bare-bones observability dashboard at `GET /dashboard` (also served from `/`).
  Single-file vanilla JS + inline CSS, no framework, embedded via `include_str!`.
  Polls `/stats` every 5 s and renders uptime, event counts, detections by
  category, and top tools in a terminal-styled layout.

## [0.3.0] - 2026-04-17 (Day 3)

### Added
- Pluggable threat-detection module (`src/detect/`) with six built-in heuristics:
  prompt-injection markers, shell/command injection, recon pattern, secret-exfil
  targets, CVE-2025-59536-class config injection, unicode anomalies.
- SQLite `detections` table linked to events, plus detection indexes.
- `filesystem-admin` persona (third shipped persona) with REDACTED-only canned
  content for common attacker probe targets.
- `GET /stats` endpoint on the HTTP transport: uptime, server identity, event
  counts by method, detection counts by category, unique remote addresses in
  the last 24h, top tools called.
- `.github/hooks/pre-commit` (opt-in via `git config core.hooksPath`) running
  `cargo fmt --check` + `cargo clippy -D warnings`.
- README `Development` section documenting the hook + local dev commands.

### Changed
- `Logger::record` now returns the inserted event id so detection rows can
  reference it via FK.
- Bumped `rust-version` in Cargo.toml to `1.88` to match the actual build
  floor (edition 2024 deps).
- Dispatcher tracks per-session stats (`calls_in_session`, `tools_list_count`,
  `tools_call_count`) exposed to detectors via `DetectionContext`.

### Added (CLI)
- `--disable-detectors` flag for pure-capture mode.

## [0.2.0] - 2026-04-17 (Day 2)

### Added
- HTTP + SSE transport for internet-facing deployment
- `github-admin` persona (fake GitHub MCP server)
- Multi-stage Dockerfile and docker-compose for one-command deploy
- Deployment guide (`docs/DEPLOYMENT.md`)
- `transport`, `remote_addr`, `user_agent`, `client_meta` columns in the event log

### Changed
- Transport abstracted behind a trait (stdio + http implementations)

## [0.1.0] - 2026-04-17 (Day 1)

### Added
- Initial release: JSON-RPC 2.0 over stdio
- MCP handshake, `tools/list`, `tools/call`
- YAML-defined personas with canned tool responses
- SQLite + JSONL structured logging
- `postgres-admin` persona
- Apache-2.0 license, `SECURITY.md`
