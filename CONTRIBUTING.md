# Contributing to honeymcp

Thanks for your interest. honeymcp is an active open-source security research project; contributions that improve detection quality, transport conformance, or operator usability are very welcome.

## Ground rules

- **Security issues**: please **do not** open a public issue. See [SECURITY.md](SECURITY.md) for the private disclosure channel.
- **Behaviour**: this project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
- **License**: by submitting a contribution you agree to license it under Apache-2.0 (matching the project).

## Workflow

1. Fork the repo and create a feature branch off `main`:
   ```
   git checkout -b fix/short-description
   ```
2. Make changes, keeping scope tight (one PR = one concern).
3. Run the local CI preview:
   ```
   make ci
   ```
   This runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`, `cargo deny check`.
4. Update `CHANGELOG.md` under `## [Unreleased]` with a short user-visible summary.
5. Push your branch and open a PR against `main`.

## What makes a PR easier to merge

- A clear description of the **observed behaviour** and the **expected behaviour**, with a minimal repro when possible.
- Tests that would have caught the regression or prove the new behaviour.
- No drive-by reformatting outside the lines you touched.
- No new dependencies without a sentence explaining why an existing crate is insufficient.

## Areas where help is most useful

- **Detectors** (`src/detect/`): new anomaly patterns for MCP abuse. Pair with test fixtures under `tests/detectors/`.
- **Personas** (`personas/*.yaml`): realistic tool sets and canned responses for specific server personas (e.g. kubectl, AWS, linear).
- **Transport conformance**: MCP spec drift tracking (`spec.modelcontextprotocol.io`).
- **Operator ergonomics**: dashboard UX, query/filter improvements.

## Things that will not be merged

- Live exploit payloads targeting real third parties.
- Credential-bearing fixtures (use `[REDACTED]` envelopes).
- Mass stylistic rewrites without discussion.
- Features that turn honeymcp into an attack tool rather than a sensor.

## Development environment

- Rust `1.83.0` (pinned via `rust-toolchain.toml`).
- Docker (for `docker-compose` local stack).
- Optional: `cargo install cargo-audit cargo-deny cargo-llvm-cov`.

## Release process

Maintainers cut releases via git tags (`vX.Y.Z-rc.N` → `vX.Y.Z`). Release workflow produces signed container images (cosign keyless) and an SBOM (Syft). Non-maintainers should not tag releases.

## Questions

Open a [Discussion](../../discussions) or reach the maintainer listed in `SECURITY.md`.
