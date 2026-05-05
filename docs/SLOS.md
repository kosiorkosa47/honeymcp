# honeymcp — Service Level Objectives

These are the SLOs honeymcp targets in production. They are public so
operators can hold the project accountable and so prospective users
can decide whether honeymcp is appropriate for their threat-intel
budget.

All numbers are measured against a single small VPS deployment
(2 vCPU, 2 GiB RAM, NVMe-backed SSD). Multi-host or Postgres-backed
deployments have different ceilings; see [`docs/RUNBOOK.md`](RUNBOOK.md).

## Definitions

- **Window:** rolling 30 days. Recomputed daily.
- **Error budget:** `(1 - SLO) × window`. e.g. a 99.9% SLO over 30
  days = 43m 12s of allowed downtime per window.
- **Incident:** any continuous period during which the SLI fell below
  the target threshold.

## SLOs

### SLO-1: Liveness

`GET /healthz` returns `200 OK` within 200 ms.

| Target | Window | Error budget |
| --- | --- | --- |
| **99.9%** | 30 days | 43m 12s |

**SLI source:** external HTTP probe every 30 s (e.g. UptimeRobot, Better Stack).

**Why this number:** honeymcp is a passive sensor — every minute it's
down is a minute of lost capture. 99.9% is the highest credible
target on a single small VPS without redundancy.

### SLO-2: Event ingestion

A request that reaches `POST /mcp` is fully persisted (events row +
detections rows + JSONL append) within 250 ms p99.

| Target | Window | Error budget |
| --- | --- | --- |
| **99%** | 30 days | 7h 12m |

**SLI source:** `tracing` span `handle_request` duration histogram,
exported via `--features otel` to a collector. Local-only operators
without OTLP can grep `journalctl` for `latency_ms` fields.

**Why this number:** the dispatcher benchmarks at ~600 µs end-to-end
on M1 for a small payload (`benches/dispatcher.rs`). 250 ms p99 leaves
~400× headroom for SQLite contention spikes and detector regex
backtracking on large payloads.

### SLO-3: Detection accuracy

For every event whose params trigger one of the documented detector
patterns, the corresponding row appears in the `detections` table
within the same transaction as the `events` row.

| Target | Window | Error budget |
| --- | --- | --- |
| **100%** | n/a | 0 |

**SLI source:** `tests/property_detectors.rs` + `tests/mitre_mapping.rs`
+ libfuzzer harness in `fuzz/fuzz_targets/detector_input.rs` ensure
the detector pipeline never panics on attacker-controlled input. CI
runs the full suite on every PR; a regression is a release blocker.

**Why this number:** detection is the core value. A miss is a silent
data-quality failure that an analyst can't see until they query the
DB and notice an obvious match isn't tagged. 100% is achievable
because the contract is local: detector → row in the same transaction.

### SLO-4: Persistence

Once a request returns a non-error response to the client, its event
row is durable. No log loss on graceful or unclean process exit.

| Target | Window | Error budget |
| --- | --- | --- |
| **100%** | n/a | 0 |

**SLI source:** SQLite WAL mode + `synchronous = NORMAL` (default).
JSONL mirror is `O_APPEND` + `flush()` per write. Both crash-safe up
to and including a power loss (last in-flight write may be lost).

**Why this number:** corpus integrity is non-negotiable. We accept up
to 1 lost write on power loss as part of the SQLite default
durability tradeoff; anything worse is a bug.

### SLO-5: Build provenance

Every deployed honeymcp binary reports a non-`unknown` `git_sha` at
`GET /version`.

| Target | Window | Error budget |
| --- | --- | --- |
| **100%** | n/a | 0 |

**SLI source:** `curl /version` smoke step in the deploy pipeline. A
binary with `git_sha = unknown` is automatically blocked from
production deploys (see `docs/RUNBOOK.md` post-deploy smoke).

**Why this number:** without provenance, you can't reason about which
detectors are running. CI signs and SBOMs every release; a deploy
that loses the sha isn't safe to run on a public IP.

## SLOs we explicitly don't make

- **Latency for `GET /dashboard`.** It's an analyst surface, not on
  the hot path. We tune for correctness, not p99.
- **Throughput beyond 1k events/s on the SQLite backend.** That's the
  documented ceiling; if you need more, switch to Postgres.
- **TLS termination.** honeymcp runs behind a reverse proxy; the
  proxy's TLS SLO is the operator's problem, not the binary's.
- **Geographic distribution.** Single-region by design. Multi-region
  would mean replicating the corpus, which is a separate product
  decision.

## When an SLO is missed

1. Open an incident issue with the SLI graph attached.
2. Compute the impact on the error budget (in human-friendly time
   units, not percentages).
3. Land a fix or compensating control before the budget is exhausted.
4. Once the incident is closed, write a brief post-mortem in
   `docs/incidents/YYYY-MM-DD-<slug>.md` (no template — write what
   actually mattered).

## Review cadence

These SLOs are reviewed once per release. If your operational
experience suggests a number is wrong (too tight, too loose), open a
PR against this file with the data to support the change.
