# Baseline metrics (as of 2026-04-24)

Captured at the start of the v3 minimal plan so deltas over the next
4 weeks are measurable.

## Code

- Rust source LoC (src/): 4591
- Workspace binaries: 2 (`honeymcp`, `honeymcp-probes`)
- Direct Cargo dependencies: 25
- Total dependency graph: 325 crates
- Workspace test count: 58 (52 unit + 6 integration in `tests/probes_cli.rs`)
- Clippy warnings under `-D warnings`: 0
- `cargo audit` vulnerabilities: 0
- `cargo deny` advisories / bans / licenses / sources: all ok
- MSRV: Rust 1.88.0 (repo pins 1.89.0 via `rust-toolchain.toml` for tool compat)

## Repo

- Total commits to `main`: 48
- Stars: 0
- Forks: 0
- Watchers: 0
- Open issues: 0
- Contributors: 1
- Signed releases (cosign keyless): 0 (release.yml exists, first tag pending)

## CI

- Required checks on `main`: fmt, clippy, test (ubuntu + macos), audit, deny, coverage
- Pass rate on last 10 pushes: 9/10 (one fail on `b212e21` fixed in `ed1b3f6`)

## Live deployment

- Region: Singapore (AWS Lightsail)
- Uptime: 483917 s (about 5.6 days since last restart)
- Persona active: `github-admin` v2.14.3
- Protocol version advertised: 2024-11-05

### Captured traffic (cumulative since last DB reset)

- Total events: 146
- Total detections: 162 (events can match multiple detectors)
- Events by method:
  - `tools/list`: 79
  - `tools/call`: 59
  - `initialize`: 8
- Detections by category:
  - `recon`: 103
  - `secret_exfil`: 25
  - `command_injection`: 13
  - `prompt_injection`: 9
  - (others below cutoff)

## Content

- Blog posts (honeymcp-specific): 1 (Day-3 retrospective, under `docs/blog/`)
- External references (HN, Lobsters, newsletters): 0
- Conference talks submitted: 0
- LinkedIn / X posts linking to repo: not yet counted

## Deltas to watch

At end of week 4 of v3 (2026-05-22) the numbers that matter:

| Metric | Baseline | Week-4 target |
|---|---|---|
| Signed releases | 0 | >= 2 (v0.6.0-rc.1, v1.0.0-rc.1) |
| Blog posts with real data | 0 | 2 |
| Captured events (cumulative) | 146 | >= 500 |
| Unique source /24 blocks seen | not tracked yet | measured |
| Stars | 0 | realistic ceiling ~20, floor 1 |
| Applications sent citing the project | 0 | 5 |
| Test count | 58 | >= 65 |

Stars are the metric most sensitive to luck and least load-bearing for
the job story; tracked for honesty, not optimised for.
