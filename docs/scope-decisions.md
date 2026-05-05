# Scope decisions

This file records what is in scope on the active honeymcp line and what is
intentionally out, plus the reasoning. The format is loose ADR (architecture
decision record): one section per decision, dated, with a context block, the
choice, and the consequence I'm willing to live with.

I write these down so that the README roadmap stays honest, contributors do
not pick up an issue for a feature I have already decided to cut, and a
future reader of the repo can understand why a piece of scaffolding (e.g.
the pgvector migration) exists even though no code currently uses it.

---

## SD-1 — Cut Terraform module set from `v0.6` line

**Date:** 2026-04-24
**Status:** Active.

**Context.** The flagship 28-day plan called for an opinionated Terraform
module that stood the honeypot up across multiple cloud providers from one
`terraform apply`. Justification at the time: lower the bar for operators
to run their own sensor.

**Decision.** Cut. Single-region deploy is documented in
[`DEPLOYMENT.md`](DEPLOYMENT.md) as a 5-minute `docker compose up -d` flow.
For the operators we can realistically reach right now (security
researchers running one VPS), a Terraform module is heavier than the
deploy it replaces.

**Consequence.** The repo has zero `*.tf` files. If a multi-tenant or
managed offering ever materialises, the work starts from a clean slate
rather than maintaining IaC nobody is using.

---

## SD-2 — Cut multi-region (EKS central + k3s edges) from `v0.6` line

**Date:** 2026-04-24
**Status:** Active. Re-evaluate after first solo-region 200+ event corpus
drop.

**Context.** The flagship plan placed sensors in 5+ regions and aggregated
events through an EKS-hosted ingestion service. Real cost on the cheapest
region/instance combinations was $300+/mo before traffic.

**Decision.** Cut. Run one Lightsail box in Singapore at $7/mo until either
(a) the single-region corpus is too small to be useful and adding regions
clearly fixes it, or (b) a sponsor or grant makes the burn rate non-personal.

**Consequence.** The first published corpus is single-region. That is
acknowledged honestly in
[`docs/blog/2026-04-24-first-week.md`](blog/2026-04-24-first-week.md) —
an unindexed Singapore IP gets exactly the kind of traffic an unindexed
Singapore IP gets. The data is geographically biased. That is fine for
methodology validation; it is not fine for marketing claims, and we
don't make those marketing claims.

---

## SD-3 — Postgres + pgvector backend stays scaffold until corpus
demands it

**Date:** 2026-04-24 (scaffold landed), 2026-05-05 (status confirmed).
**Status:** Active.

**Context.** The `--features postgres` build flag, the `sqlx` dependency,
the `migrations/` directory with the events / detections / personas tables
and a `pgvector` HNSW index — all of that is in `main`. The recorder side
in `src/logger/postgres.rs` is a stub that bails with `not implemented yet`.

The reason scaffolding shipped before the recorder is that the schema
shape is the part I want fixed early: an operator running honeymcp on a
fork should not be locked out of Postgres because the migration set
doesn't exist. The recorder is mechanical work once the schema is stable.

**Decision.** Hold the recorder until either (a) SQLite shows lock
contention or query latency on real corpus, or (b) someone wants to run
two sensors writing to the same database for cross-region aggregation.
At ~5 events/day, neither is happening.

**Consequence.** A `--features postgres` build succeeds today but does
not record anything to Postgres. The README labels this clearly. The
work is tracked in #81 and will land in a `v0.7` release if and only
if the trigger conditions above are met.

---

## SD-4 — Observability code ships, production wiring deferred

**Date:** 2026-04-25 (code), 2026-05-05 (deferral confirmed).
**Status:** Active. Wire OTLP to a free tier collector in `v0.7`.

**Context.** `--features otel` builds the full OpenTelemetry exporter
chain (`opentelemetry`, `opentelemetry-otlp`, `opentelemetry_sdk`,
`tracing-opentelemetry`) at the 0.31 / 0.32 versions. `HONEYMCP_LOG_FORMAT=json`
gives ndjson stderr for log shipping. `Dispatcher::handle_request` carries
an `#[instrument]` span with `method` / `session_id` / `transport` /
`persona` / `remote_addr` / `user_agent` fields.

**Decision.** Land the code, defer the production wiring. The next step
is pointing `OTEL_EXPORTER_OTLP_ENDPOINT` at a free-tier collector
(Grafana Cloud or Honeycomb) on the production VPS, then publishing a
screenshot of real spans. That is one PR plus a deploy, not new code.

**Consequence.** A reviewer who reads "observability" on the roadmap
sees code present and runtime wiring pending, in that order. Rebuilding
with `--features otel` and setting one env var is the entire delta when
we're ready.

---

## SD-5 — ML classifier and HDBSCAN clustering stay cut

**Date:** 2026-04-24
**Status:** Active. Re-evaluate when corpus reaches ≥1000 external events.

**Context.** The flagship plan included an embeddings pipeline that
clustered captured payloads with HDBSCAN and an LLM classifier mapping
each cluster onto OWASP T1-T15.

**Decision.** Cut for the `v0.6` line. The seven rule-based detectors
already in `src/detect/` cover the categories we have evidence for in
the first-week corpus. ML on a 5-event-per-day corpus would learn
nothing useful and would import a non-trivial dependency surface (a
local embedding model, vector store, evaluation harness) for output
that humans can produce more accurately by reading the JSONL tail.

**Consequence.** The pgvector HNSW index in `migrations/` still
exists. It is there so that when the ML track returns, a schema
migration is not also a data migration. The index costs a few KB of
empty disk on a fresh deploy.

---

## SD-6 — Honest counts are a load-bearing decision, not a feature

**Date:** 2026-04-25
**Status:** Active.

**Context.** The first week of operating the sensor produced a corpus
of 150 events. Of those, 145 were operator validation traffic
(`honeymcp-probes` audits, `curl` smoke tests). I almost shipped a
blog post citing 146 external events as attacker behaviour.

**Decision.** Operator traffic gets tagged at write time
(`is_operator` column, populated by `OperatorClassifier`). Every
`/stats` aggregation excludes operator-tagged rows by default; a
caller who wants the mixed corpus passes `?include_operator=true` and
the response surfaces an `operator_traffic_included` flag so a third
party reading the JSON cannot mistake one corpus for the other. The
dashboard surfaces the toggle in the URL, not just in JS state.

**Consequence.** Public numbers are smaller. They are also actually
attacker behaviour. Future contributors and forks inherit a default
that is honest by construction; you have to opt in to the mixed corpus
to misread it.

---

## SD-7 — `v0.7` line is observability + Postgres recorder + corpus growth

**Date:** 2026-05-05
**Status:** Plan, not commitment.

**Intent for `v0.7`:**

- Wire `OTEL_EXPORTER_OTLP_ENDPOINT` to a free-tier collector on
  production. Publish at least one screenshot of real session spans.
- Implement the Postgres recorder in `src/logger/postgres.rs` — same
  query parity as SQLite, integration test against a Postgres test
  container.
- Comparison page at `docs/comparison.md` covering MintMCP, Aembit,
  CloneGuard, T-Pot, MHN — what each does, what gap honeymcp fills.
- First responsibly-disclosed CVE on an MCP-ecosystem target,
  referencing the audit pattern in
  [`docs/threat-model.md`](threat-model.md).

**Out for `v0.7`** (still cut from SD-1, SD-2, SD-5): Terraform,
multi-region orchestrator, ML classifier.

The goal of writing this section ahead of time is so a reader who picks
up this repo six weeks from now can see what was promised, what shipped
under that promise, and what shifted.
