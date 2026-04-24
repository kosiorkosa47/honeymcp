.PHONY: help fmt fmt-check lint lint-fix test test-all audit deny coverage build release docker clean ci

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
