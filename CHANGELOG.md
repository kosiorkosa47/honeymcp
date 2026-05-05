# Changelog

## [Unreleased]

## [0.7.0] - 2026-05-05

The enterprise-grade hardening release. Seven PRs landed in one sitting,
each independent, all touching a different surface a SOC buyer audits
before approving honeymcp for deployment: performance numbers,
crash-resistance contracts, detector-to-MITRE mapping, TI-feed export,
day-2 ops docs, and SLSA Level 3 build provenance.

### Added - SLSA Level 3 build provenance

- **Every release artifact ships with a signed in-toto attestation**
  via `actions/attest-build-provenance@v3` in both the per-target
  build matrix and the container job. Binaries are verifiable with
  `gh attestation verify <artifact> --owner kosiorkosa47`; the
  container image attestation is bound to the OCI manifest so
  `gh attestation verify-image` resolves without a separate file.
- [`docs/SLSA.md`](docs/SLSA.md) walks through what L3 actually
  guarantees, gives copy-pasteable verification recipes for binaries
  and images, maps each L3 requirement to how honeymcp satisfies it,
  and documents why the project explicitly does not claim L4
  (Cargo's network access during `cargo fetch` fails the hermetic
  build test; not worth `cargo vendor` overhead at current scale).
- The release stack is now signature ✓ + SBOM ✓ + provenance ✓ —
  the same trust model the kernel and Kubernetes ship with.

### Added - operational runbook + service-level objectives

- [`docs/RUNBOOK.md`](docs/RUNBOOK.md) is the page on-call reaches
  for when something looks wrong: deploy with cosign-verify gating,
  five common alert templates with response procedures, ten triage
  SQL queries (per-category detection volume, MITRE technique
  distinct-list, top attacker IPs, prompt-injection-plus-recon
  chain detection), atomic backup via `VACUUM INTO`, scaling
  ceilings with bottleneck order (SQLite → detector pipeline →
  network), and decommission with `shred`.
- [`docs/SLOS.md`](docs/SLOS.md) publishes the project's public
  service-level objectives: 99.9% liveness over 30 days, 99% p99
  ingest within 250 ms, 100% detection accuracy backed by the
  property + fuzz suites, 100% persistence on graceful exit, 100%
  build-provenance reporting at `/version`. Each SLO names its SLI
  source and explains the number, including the explicit non-SLOs
  (dashboard latency, multi-region, throughput beyond 1k events/s
  on SQLite).

### Added - STIX 2.1 export with MITRE attack-pattern refs

- New `--export-stix <path>` CLI flag dumps the SQLite corpus as a
  STIX 2.1 Bundle suitable for direct TAXII / OpenCTI / Sentinel TI
  / Splunk Add-on for STIX ingestion.
- Each detection becomes one `indicator` (custom STIX pattern over
  `x-honeymcp-detection`, severity + category in `labels`,
  indicator_types mapped per category) plus one `observed-data` per
  event carrying request envelope custom properties (session_id,
  method, remote_addr, user_agent), plus one `attack-pattern` per
  MITRE technique (deduped across the bundle, carrying canonical
  external_references with mitre-attack URLs for `T*` and
  mitre-atlas URLs for `AML.T*`).
- `relationship` objects link `indicator -> based-on -> observed-data`
  and `indicator -> indicates -> attack-pattern`.
- Indicator / attack-pattern / observed-data IDs are UUID v5 under a
  project-pinned namespace, so re-exporting the same DB produces
  stable refs that downstream TAXII consumers dedupe on naturally.
- 14 unit tests covering bundle structure, deterministic IDs, dedup,
  ATT&CK vs ATLAS URL routing, STIX 2.1 string-literal escaping,
  and the SQL-aggregate-to-source adapter functions.

### Added - MITRE ATT&CK / ATLAS technique mapping

- `Detection.mitre_techniques: &'static [&'static str]` populated by
  every shipped detector with the relevant ATT&CK Enterprise or
  ATLAS technique IDs (shell injection → T1059 family, prompt
  injection → AML.T0051 + AML.T0054, secret exfil → T1552 family,
  recon → T1518 + T1083, CVE-2025-59536 → T1190 + T1059, unicode
  anomaly → T1027 + T1036.005, tool enumeration → T1518 + T1083).
- Persisted via backwards-compatible `add_column_if_missing` to
  `detections.mitre_techniques` as a JSON-encoded array. SIEM
  consumers query the column verbatim; existing operators upgrade in
  place without manual schema work.
- [`docs/MITRE-MAPPING.md`](docs/MITRE-MAPPING.md) tabulates the
  mapping with justification for every technique pick and includes
  sample SQL using SQLite JSON1 to enumerate observed techniques.
- Contract test suite (`tests/mitre_mapping.rs`, 8 cases) drives
  every detector with a tailored payload, asserts at least one
  well-formed technique ID comes back, and validates the format
  (Enterprise vs ATLAS bands). Catches typos like `T01059` at test
  time and ensures any future detector emits a non-empty slice.

### Added - cargo-fuzz harness with two libfuzzer targets

- `fuzz/fuzz_targets/jsonrpc_parse.rs` runs `serde_json::from_slice`
  for `JsonRpcRequest` (the dispatcher's body parser) under
  coverage-guided mutation.
- `fuzz/fuzz_targets/detector_input.rs` splits the byte stream into
  a method prefix + JSON body, parses the body, and pushes the
  synthesized `LogEntry` through `Registry::default_enabled().analyze_all`
  exactly the way the dispatcher does. Exercises all seven shipped
  detectors under fuzz.
- `.github/workflows/fuzz.yml` runs both targets for 60 s on every
  push to main and every PR, with a 15-minute job cap and crash-
  artifact upload on failure so failed runs are debuggable without
  re-running locally. Pinned to nightly Rust because libfuzzer's
  sanitizer flags aren't stabilized.
- Local validation: `jsonrpc_parse` churned 375 k inputs in 11 s
  with zero crashes; `detector_input` independently rediscovered the
  shell-injection char-boundary panic the property suite caught,
  confirming both layers cover the same contract from different
  angles.

### Added - property-based tests for parser, detectors, persona loader

- Three suites under `tests/property_*.rs` running on every
  `cargo test` invocation: 1024 cases for the JSON-RPC parser, 256
  cases × three case-shapes for the detector pipeline, 256 cases
  for the persona YAML loader. Each suite asserts the crash-
  resistance contract — bytes in, `Result::Err` out, never an
  unwind — for attacker-facing code paths.
- **Found a real bug.** The detector suite immediately surfaced a
  slice-on-non-char-boundary panic in `src/detect/shell_injection.rs:57`
  on multi-byte UTF-8 input (emoji, RTL marks, surrogate-pair
  lookalikes). Fixed by snapping the regex match window to char
  boundaries via `is_char_boundary` walk-back/walk-forward. The
  shrunk counter-example is checked in under
  `tests/property_detectors.proptest-regressions` so the regression
  replays on every CI run.

### Added - performance benchmark suite

- **Three criterion benches** under `benches/` covering the detector
  pipeline (`detectors.rs`), the SQLite + JSONL recorder
  (`logger.rs`), and the dispatcher end-to-end path
  (`dispatcher.rs`). Each suite runs on payload sizes that mirror
  real attacker traffic: a 200 B recon probe, a 2 KB prompt-injection
  attempt, and a 64 KB worst case the regex engine has to defend
  against.
- README "Performance" section publishes the M1 baseline as a real
  table — detector pipeline at ~220 k events/s for small payloads
  scaling down to ~2.1 k events/s at 64 KB, dispatcher end-to-end at
  ~1.2-3.4 k req/s depending on method. The recorder is the
  bottleneck, not the detector — that ratio is intentional.
- `bench` profile inherits from `release` plus `debug = true` so
  symbols survive into criterion's flamegraphs without changing what
  an operator actually runs.
- CI gains a `cargo bench --no-run` smoke compile so that future PRs
  can't break the bench harness silently while leaving cargo test
  green.

### Changed - scope clarification

- **Three criterion benches** under `benches/` covering the detector
  pipeline (`detectors.rs`), the SQLite + JSONL recorder
  (`logger.rs`), and the dispatcher end-to-end path
  (`dispatcher.rs`). Each suite runs on payload sizes that mirror
  real attacker traffic: a 200 B recon probe, a 2 KB prompt-injection
  attempt, and a 64 KB worst case the regex engine has to defend
  against.
- README "Performance" section publishes the M1 baseline as a real
  table — detector pipeline at ~220 k events/s for small payloads
  scaling down to ~2.1 k events/s at 64 KB, dispatcher end-to-end at
  ~1.2-3.4 k req/s depending on method. The recorder is the
  bottleneck, not the detector — that ratio is intentional.
- `bench` profile inherits from `release` plus `debug = true` so
  symbols survive into criterion's flamegraphs without changing what
  an operator actually runs.
- CI gains a `cargo bench --no-run` smoke compile so that future PRs
  can't break the bench harness silently while leaving cargo test
  green.

### Changed - scope clarification

- **Roadmap rewritten with honest scope** ([`docs/scope-decisions.md`](docs/scope-decisions.md)).
  The original 28-day flagship plan (Terraform module set, multi-region
  EKS + k3s deploy, ML classifier with HDBSCAN clustering) is formally
  cut on the `v0.6` line. The README roadmap table now shows what is
  shipped, what is scaffolded, and what is cut, with a link to the ADR
  file explaining why each cut happened. `v0.7` intent is documented in
  the same place: production OTLP wiring, Postgres recorder
  implementation, comparison page, and the first responsibly-disclosed
  MCP-ecosystem CVE.

### Added - persona authoring docs

- Documented the persona YAML schema, tool description conventions,
  canned response matching behaviour, and a full `kubernetes-cluster`
  worked example in [`docs/personas.md`](docs/personas.md) (#22).

### Added - dashboard v2 foundation

- **Server-rendered dashboard at `/dashboard`** (#42). Drops the legacy
  single-file vanilla-JS embed (440 lines polling `/stats` every 5 s) in
  favour of a `minijinja` server-side surface with htmx + Alpine.js for
  small client-side state. All assets (templates, CSS, htmx, alpine) ship
  inside the binary via `include_str!`; no `node_modules`, no separate
  frontend repo, no asset pipeline. The full design is in
  [`docs/dashboard-v2-design.md`](docs/dashboard-v2-design.md).

- **Attack Story Timeline** is the new primary view. Sessions, not
  requests, are the unit of analysis. Each session card carries an
  external/operator dot, an event count, a detector count, and the
  last-seen IP and User-Agent. Expanding a card shows every event in
  the session ordered newest-first with detector strikes inline and a
  collapsible params preview.

- **MCP Sequence Diagram** at `/dashboard/sequence/<id>.svg`. Renders a
  per-session protocol diagram server-side as standalone SVG: client
  lifeline left, persona right, one arrow per JSON-RPC frame, tool
  name pill on every `tools/call`, red strike on the right margin where
  a detector fired. This is the visualisation no other honeypot
  dashboard ships and is the headline component of the rewrite.

- **Build provenance footer** on every dashboard page, hydrated from
  `/version`. Shows the running version, 12-char git short sha,
  RFC3339 build time, and a `cosign verified` marker linking to the
  GHCR-signed image.

- **Honest-by-default counters.** Every count on the dashboard is the
  external corpus by default; the toggle is a real query parameter
  (`?include_operator=true`) so URLs are shareable and the methodology
  stays visible.

- **16 unit tests** for dashboard helpers (XML escaping, MCP method
  classification, tool-name parsing, detection JSON parsing, relative
  time formatting, URL encoding, session grouping, sequence SVG
  shape, IP resolution with XFF precedence). Patch coverage on the new
  module rose from 0 to ~70%.

### Changed

- `HttpTransport` gains `with_logger()`. The dashboard surface mounts
  only when both stats and logger are present; otherwise `/dashboard`
  returns 503 with a clear message rather than serving an empty UI.
- `Logger::recent_events_with_detections` is the single query feeding
  both the timeline and the SVG path; it returns a wide `RawEventRow`
  with the detection JSON aggregated server-side so handlers don't fan
  out into multiple SQL paths.
- README link to the Model Context Protocol now points at the
  `/docs/getting-started/intro` page instead of the raw spec (#40).

### Notes

- The legacy `src/dashboard.html` embed has been removed. Operators on
  `0.6.0` will lose the v1 dashboard at deploy time but gain the v2
  one with no compose changes; the route stays at `/dashboard`.
- Six remaining dashboard components from the design doc (Sankey,
  detector co-occurrence heatmap, live SSE feed, geo-IP pulse map,
  full provenance panel, methodology sidebar) are tracked as
  follow-ups and ship incrementally without further breaking
  changes.

## [0.6.0] - 2026-04-27

This is the first stable cut. The release closes the gap between
`0.6.0-rc.1` (the smoke-test cut on 2026-04-24) and the production
deploy that has been running on the Singapore Lightsail box since
2026-04-25 19:06 UTC. 36+ hours of soak under live Censys traffic and
operator validation, no restarts, no panic, no drift on `/healthz`.

The signed GHCR image (`ghcr.io/kosiorkosa47/honeymcp:0.6.0`) is the
first one I'd recommend pulling rather than building locally; it carries
a real `git_sha` (the in-image build context now includes the workspace
checkout that `release.yml` performs) and is signed via cosign keyless
OIDC, with SPDX + CycloneDX SBOMs attested to the image digest.

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
