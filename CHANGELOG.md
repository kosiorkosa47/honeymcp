# Changelog

## [Unreleased]

### Added - operator surface

- **`/version` endpoint** (#17). `GET /version` returns JSON with crate name,
  version, 12-char git short sha (with a `-dirty` suffix when the working tree
  was unclean), Unix build timestamp, and an RFC3339 `build_time_utc`. Stamped
  at compile time via a new `build.rs`. Every deploy is now verifiable in one
  curl, which closed the gap that left us guessing whether the production VPS
  actually carried the changes we just merged.

- **Two new personas: `vercel-admin` and `stripe-finance`** (#27). Modelled
  on the publicly-shipped `mcp.vercel.com` surface and the Stripe MCP catalog;
  `vercel-admin` exposes 8 tools (teams, projects, deployments, build logs,
  env vars with a `reveal=true` escape hatch, redeploy, doc search) and
  `stripe-finance` exposes 7 (customers, charges, subscriptions, invoices,
  balance, refund-with-human-approval-gate). Brings the shipped persona count
  to four.

### Added - data hygiene

- **`is_operator` event tagging** (#26). New SQLite column populated at write
  time by an `OperatorClassifier` that checks two signals: User-Agent prefix
  (default `honeymcp-probes/`, configurable via
  `HONEYMCP_OPERATOR_UA_PREFIXES`) and resolved remote IP, XFF-aware, against
  an env allowlist (`HONEYMCP_OPERATOR_IPS`). All `/stats` aggregations now
  exclude operator-tagged rows by default; pass `?include_operator=true` to
  fold them back in. The response carries an `operator_traffic_included`
  flag so a third party reading the JSON knows which corpus they got.
  Closes the methodology promise made in
  [`docs/blog/2026-04-24-first-week.md`](docs/blog/2026-04-24-first-week.md).

### Added - CI + governance

- **`docker build + smoke` CI job** (#23). Builds the production Dockerfile
  on every PR, runs the resulting container against a real persona, and
  asserts `/healthz`, `/version`, `GET /` operator banner, and `POST /mcp`
  Streamable HTTP `initialize` all behave. Catches the class of regression
  that #17 → #18 surfaced: cargo CI was 7-of-7 green throughout while the
  Dockerfile build was broken because the new `build.rs` was not in the
  builder COPY. Promoted to required status check (matrix grew 7 → 8).
- **Codecov publishing** (#25, #31). `cargo-llvm-cov` already produced
  `lcov.info` as a workflow artifact; now uploaded to Codecov via
  `codecov-action@v5` with a per-repo `CODECOV_TOKEN` repo secret. README
  badge is live at the current `main` percentage (#32 switched the URL to
  the shields proxy after GitHub Camo cached the pre-token `unknown`
  state). Codecov GitHub App installed for OIDC + PR delta comments.
- **`CODEOWNERS`** (#19) with per-surface review routing (transports,
  detectors, supply chain, legal docs). Solo maintainer for now, but laid
  out so a future co-maintainer can pick up a slice without edits to every
  PR description.
- **`good first issue` triage** (#20, #21, #22) covering a shellshock-style
  probe addition, MCP-Protocol-Version coverage in the detector regression
  suite, and a persona-authoring guide.
- **Persona follow-up tracking** (#28, #29, #30): `figma-dev`,
  `cloudflare-edge`, `linear-pm`. Each issue carries enough scope and a
  link to `personas/vercel-admin.yaml` as the authoritative format
  reference.

### Changed - dependencies

- **OpenTelemetry chain bumped to 0.31** (#33). Atomic bump of `opentelemetry`
  / `opentelemetry-otlp` / `opentelemetry_sdk` 0.27 → 0.31 plus
  `tracing-opentelemetry` 0.28 → 0.32, replacing four separate Dependabot PRs
  (#9, #11, #12, #13) that were closed as superseded. The 0.31 API rename
  (`SdkTracerProvider`), the public-only `Resource::builder` constructor, and
  the runtime-less `BatchSpanProcessor` had to land together; merging the
  Dependabot PRs one at a time would have left `main` non-compiling under
  `--features otel` between merges.

- **Cargo: `thiserror` 1 → 2, `sha2` 0.10 → 0.11** (#7, #14).

- **GitHub Actions runners refreshed**: `docker/setup-buildx` 3 → 4,
  `docker/setup-qemu` 3 → 4, `docker/metadata-action` 5 → 6,
  `softprops/action-gh-release` 2 → 3, `actions/upload-artifact` 4 → 7
  (#1, #2, #4, #5, #6).

### Fixed

- **Dockerfile builder did not COPY `build.rs`** (#18). The new build
  script that stamps git sha and build timestamp errored out the first time
  we built the image post-#17 because cargo could not find the env vars at
  compile time. The hotfix copies it explicitly and notes that the
  in-image build runs without a `.git` tree (so the sha falls back to
  `unknown` for locally-built images; only CI release builds carry a real
  sha).

- **First-week blog post numbers** (#24). The original draft cited 146
  external requests and a top-tools chart dominated by `read_file`, `note`,
  `run`. Pulling the JSONL off the VPS showed 145 of 150 events were
  operator validation traffic and `honeymcp-probes` audits. Five real
  external events from three unique sources, all `initialize` /
  `tools/list`, zero `tools/call`, zero detector hits. The post now carries
  the corrected numbers and the methodology-error explanation, and a
  follow-up data-drop is gated on the external-only corpus reaching ≥200
  events from ≥30 sources.

### Notes

- Production VPS has been re-deployed (locally-built `linux/amd64` image,
  `git_sha: unknown`). The signed GHCR pull arrives with the v0.6.0 stable
  tag after the rc.7 soak window completes.
- Five Dependabot PRs remain open and intentionally not merged this cycle:
  Rust toolchain 1.89 → 1.95 (#3, needs `rust-toolchain.toml` aligned in
  the same commit), `tower_governor` 0.4 → 0.8 (#8, breaking API),
  `axum` 0.7 → 0.8 (#10, transport-wide refactor), `rusqlite` 0.31 → 0.39
  (#15, schema-touching), `tower_governor` carries the same constraint.
  Each is tracked as a follow-up rather than batched into a release.

## [0.6.0-rc.1] - 2026-04-24

### Added - transport

- **Streamable HTTP transport** (MCP spec 2025-06-18). The current MCP transport
  runs side by side with the legacy HTTP+SSE flow:
  - `POST /mcp` does `Accept`-header content negotiation. `Accept:
    text/event-stream` gets a single-message SSE frame carrying the response;
    anything else gets inline `application/json`. Notifications (no `id`)
    return `202 Accepted` with no body regardless of `Accept`.
  - `GET /mcp` opens a long-lived server-to-client SSE stream for the session,
    same lifecycle as `/sse` but under the spec-current path.
  - `DELETE /mcp` explicit session teardown. Returns `204 No Content` for both
    known and unknown session ids so a scanner cannot use it as a liveness
    oracle.
  - Session routing prefers the `Mcp-Session-Id` header; query parameter still
    honoured as fallback. The response echoes `Mcp-Session-Id` back.
  - `MCP-Protocol-Version` and `Accept` are now recorded in `client_meta`
    alongside `x-forwarded-for`, so dashboard and detectors can see what the
    client claimed to speak. Missing / mismatched protocol versions are NOT
    rejected - a honeypot that returns 400 to malformed probes teaches the
    attacker to avoid the trap.
  - Legacy `/message` + `/sse` paths unchanged for clients still on the
    2024-11-05 spec.

### Added - operator surface

- **Operator banner at `GET /`.** Dashboard moves to `/dashboard`; the root now
  serves a research-honeypot disclosure (what is captured, why, how to request
  erasure) as the primary surface visible to unsolicited scanners.
  - Content negotiation: clients asking for `text/html` get the styled HTML
    banner with a `noindex` meta; everything else (including `curl` default
    `*/*`) gets plain text so quick probes stay readable.
  - Runtime substitution from `HONEYMCP_BANNER_CONTROLLER`,
    `HONEYMCP_BANNER_ABUSE_EMAIL`, `HONEYMCP_BANNER_CONTACT` env vars.
    Missing vars fall back to `<operator not configured>` deliberately.

### Added - release + supply chain

- **Signed release workflow** (`.github/workflows/release.yml`). Triggered on
  `v*.*.*` and `v*.*.*-rc.*` tags, runs three jobs:
  - `build`: cross-compiled binaries for 5 targets (linux x86_64 / aarch64,
    macOS x86_64 / aarch64, Windows x86_64), each packaged with LICENSE +
    README + CHANGELOG and a `.sha256`.
  - `container`: multi-arch GHCR image (`linux/amd64` + `linux/arm64`),
    signed with cosign keyless (OIDC - no key stored in the repo), SBOM
    generated via Syft in both SPDX and CycloneDX and attested to the image
    digest with `cosign attest`.
  - `publish`: extracts this CHANGELOG section as release notes and creates
    the GitHub Release, attaching binaries + SBOMs (prerelease=true for
    `-rc.*` tags).
  - Consumers verify with
    `cosign verify ghcr.io/kosiorkosa47/honeymcp:vX.Y.Z --certificate-identity-regexp '.../honeymcp/.*' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`.

### Added - CI

- New `deny` and `coverage` jobs in `.github/workflows/ci.yml`, on top of the
  existing `fmt` / `clippy` / `test (ubuntu + macos)` / `audit` suite. Five
  required checks now tell you which category broke at a glance. Coverage
  uploads `lcov.info` as a 14-day workflow artifact (no third-party token).

### Added - documentation

- **`docs/threat-model.md`** - STRIDE walkthrough against the transport +
  detector layer. Per-category table of threat / current mitigation / known
  gap, plus a honeypot-specific section on operator legal exposure,
  use-as-attack-tool risk, and shared-tenancy concerns. Explicit
  out-of-scope list + review triggers.
- **`docs/legal/operator-banner.md`** - plain-text + HTML templates of the
  banner served at `GET /`, with the substitution placeholders and a
  what-not-to-change policy for deployments.
- **`docs/legal/privacy-gdpr-lia.md`** - Legitimate Interest Assessment
  under GDPR Art. 6(1)(f) + Recital 49. Captured-fields inventory, Art. 6
  three-part test, data-subject rights handling (Art. 13/14/15/17/21/77),
  TOM inventory, publication defaults (IP truncation to `/24` or `/48`
  before sharing derived datasets), operator signature block.

### Added - observability

- New `honeymcp::observability` module, single call at startup wires up the
  tracing stack. Two env knobs:
  - `HONEYMCP_LOG_FORMAT=json` switches the stderr `fmt` layer from pretty
    to structured ndjson (one event per line, ready to ship to
    Loki / Cloudwatch / Datadog without a parser).
  - Opt-in OTLP exporter behind `--features otel`. When built with the
    feature **and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are
    forwarded via gRPC/tonic to the configured collector; when either is
    false, the OTEL layer is not registered and there is zero runtime
    cost. `OTEL_SERVICE_NAME` defaults to `honeymcp`.
- `observability::init()` returns a `Guard` that the binary holds until
  shutdown; dropping it flushes the OTLP exporter so in-flight spans are
  not lost on graceful exit.

### Added - storage scaffolding

- Optional Postgres backend behind `--features postgres` (sqlx 0.8.6,
  postgres-only features to avoid a libsqlite3-sys collision with
  rusqlite's bundled copy). Default build is unchanged - SQLite + JSONL
  remains the only storage path without the feature flag.
- `migrations/20260424_0001_init.sql` / `_0002_pgvector.sql` - schema
  (sessions, events, detections, personas_snapshot) + pgvector HNSW
  index for 384-dim sentence-transformer embeddings.
- `docker compose up -d postgres` starts `pgvector/pgvector:pg16` bound
  to `127.0.0.1:5432` only. `make db-migrate` applies the SQL files via
  psql against `DATABASE_URL`.
- `src/logger/postgres.rs` is a stub; `connect()` bails with an explicit
  "not implemented yet" so no `postgres://` URL accidentally routes
  into the void. Concrete backend lands in a follow-up commit.

### Added - repo scaffolding

- `rust-toolchain.toml` pin (1.89.0 - needs to be >= 1.89 for `cargo-audit`
  to compile), `deny.toml` with licence allow-list tuned to the actual
  dependency tree, `Makefile` (`fmt` / `lint` / `test` / `audit` / `deny` /
  `coverage` / `docker` / `ci` / `clean`), `.editorconfig`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  GitHub issue + PR templates with a security-advisory contact link.
- `make ci` is the local one-shot: `cargo fmt --check && cargo clippy -D
  warnings && cargo test && cargo audit && cargo deny check`.

### Security

- Bumped `rustls-webpki` 0.103.12 -> 0.103.13 to pick up the fix for
  RUSTSEC-2026-0104 (reachable panic in CRL parsing, advisory published
  2026-04-22). Transitive via `reqwest` -> `rustls` -> `rustls-webpki`.

### Testing

- `transport::http` coverage grew from 1 -> 10 integration tests: legacy
  `POST /message`, Streamable `POST /mcp` JSON, SSE, notification -> 202,
  malformed-body parse error, `DELETE /mcp` for known and unknown sessions,
  banner placeholder substitution, Accept-header negotiation.

## [0.5.0] - 2026-04-18

### Fixed

- **`honeymcp-probes` semantics overhaul.** The 0.4.0 probes shipped with a
  sequence of defects that made the output misleading as an audit signal:
  - Response body was never parsed as JSON-RPC, so every HTTP 200 counted as
    "accepted" regardless of whether the server actually returned an RPC
    `error` or a `result`. Now the body is parsed and `error` responses are
    classified as rejected (with a separate surface for rate-limited and
    auth-required cases).
  - No MCP handshake before session-dependent probes, so servers that enforce
    `initialize` first would reject every probe as protocol-violating rather
    than substantively. A single pre-flight `initialize` now runs before the
    session-bearing probes unless `--skip-handshake` is set.
  - Response redaction was one-directional: request payloads with live
    secrets would be redacted before logging, but anything the server echoed
    back in its response was written verbatim. Response text is now redacted
    symmetrically.
  - `--bearer` / `--header` flags for authenticated audits; `--no-redact` for
    researchers who know what they're doing and want raw capture.

### Changed

- `[[bin]]` table split: `honeymcp` and `honeymcp-probes` are now explicit
  binaries in `Cargo.toml` rather than relying on auto-discovery. This makes
  `cargo install --path .` and `cargo build --release --bin honeymcp-probes`
  unambiguous.
- `wiremock` added as a dev-dependency. Drives `tests/probes_cli.rs` (6 tests)
  against a controlled HTTP surface so the accepted-vs-rejected classifier
  has repeatable fixtures.

### Tests

- 18/18 green across the workspace (library unit tests + `probes_cli`
  integration tests).

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
