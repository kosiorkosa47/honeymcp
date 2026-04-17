# Changelog

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
