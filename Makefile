.PHONY: help fmt fmt-check lint lint-fix test test-all audit deny coverage build release docker clean ci db-up db-down db-migrate

help:
	@echo "honeymcp - developer make targets"
	@echo ""
	@echo "  make fmt          - cargo fmt"
	@echo "  make fmt-check    - cargo fmt --check"
	@echo "  make lint         - cargo clippy (workspace, all features)"
	@echo "  make lint-fix     - cargo clippy --fix"
	@echo "  make test         - cargo test (default features)"
	@echo "  make test-all     - cargo test --all-features"
	@echo "  make audit        - cargo audit"
	@echo "  make deny         - cargo deny check"
	@echo "  make coverage     - cargo llvm-cov"
	@echo "  make build        - cargo build --release"
	@echo "  make docker       - docker build -t honeymcp:dev ."
	@echo "  make ci           - fmt-check + lint + test + audit + deny (local CI preview)"
	@echo "  make clean        - cargo clean"
	@echo ""
	@echo "Postgres (only when using --features postgres):"
	@echo "  make db-up        - docker compose up -d postgres"
	@echo "  make db-down      - docker compose down postgres"
	@echo "  make db-migrate   - apply migrations/*.sql against DATABASE_URL"

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

lint-fix:
	cargo clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged

test:
	cargo test --workspace

test-all:
	cargo test --workspace --all-features

audit:
	cargo audit

deny:
	cargo deny check

coverage:
	cargo llvm-cov --workspace --lcov --output-path lcov.info

build:
	cargo build --release --workspace

release: ci build

docker:
	docker build -t honeymcp:dev .

ci: fmt-check lint test audit deny
	@echo "local CI preview passed"

clean:
	cargo clean
	rm -f lcov.info

# --------------------------------------------------------------------------
# Postgres dev environment
# --------------------------------------------------------------------------

# DATABASE_URL can be overridden from the environment. Default matches the
# docker-compose `postgres` service.
DATABASE_URL ?= postgres://honeymcp:honeymcp_dev@127.0.0.1:5432/honeymcp

db-up:
	docker compose up -d postgres

db-down:
	docker compose down postgres

# Apply every file in migrations/ in lexical order. sqlx-cli is nice to have
# but adding it as a required dev dep is overkill for a 2-file migration set,
# so we shell out to psql. Requires the `psql` client on PATH.
db-migrate:
	@if ! command -v psql >/dev/null 2>&1; then \
		echo "error: psql not on PATH. brew install libpq && brew link --force libpq"; \
		exit 1; \
	fi
	@for f in migrations/*.sql; do \
		echo "==> $$f"; \
		psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -f "$$f" || exit 1; \
	done
	@echo "migrations applied"
