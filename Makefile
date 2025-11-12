# ClamReef Agent Makefile

.PHONY: help build build-dev build-release test test-unit test-e2e test-doc lint fmt fmt-check clean coverage coverage-check install run dev check ci ci-test bench audit pre-commit release-prep docker-build docker-run

# Default target
help:
	@echo "ClamReef Agent - Available targets:"
	@echo "  build       - Build with all features (CI-style)"
	@echo "  build-release - Build release binary"
	@echo "  test        - Run all tests (CI-style)"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-e2e    - Run end-to-end tests"
	@echo "  test-doc    - Run documentation tests"
	@echo "  lint        - Run clippy linter (CI-style)"
	@echo "  fmt         - Format code with rustfmt"
	@echo "  coverage    - Generate test coverage report"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary to /usr/local/bin"
	@echo "  run         - Run the agent with default config"
	@echo "  dev         - Run in development mode"
	@echo "  check       - Check code without building"
	@echo "  ci          - Run all CI checks (fmt, lint, build, test, coverage, audit)"

# Build targets
build:
	cargo build --verbose --all-features

build-dev:
	cargo build

build-release:
	cargo build --release

# Test targets
test:
	cargo test --verbose --all-features

test-unit:
	cargo test --lib

test-e2e:
	cargo test --test '*' -- --test-threads=1

test-doc:
	cargo test --doc

# Code quality
lint:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

check:
	cargo check

# Coverage
coverage:
	cargo tarpaulin --out Html --output-dir target/coverage

coverage-check:
	cargo tarpaulin --lib --fail-under 75

# Development
dev:
	RUST_LOG=debug cargo run -- --log-level debug

run:
	cargo run --release

# Cleanup
clean:
	cargo clean
	rm -rf target/coverage

# Installation
install: build-release
	sudo cp target/release/clamreef-agent /usr/local/bin/
	@echo "Installed clamreef-agent to /usr/local/bin/"

# Docker targets
docker-build:
	docker build -t clamreef-agent .

docker-run:
	docker run --rm -it \
		-v /var/run/clamav:/var/run/clamav \
		-v $(PWD)/examples:/etc/clamreef \
		clamreef-agent

# CI targets - matches GitHub Actions workflow
ci: fmt-check lint build test test-doc coverage-check audit
	@echo "✅ All CI checks passed!"

ci-test: lint fmt-check test coverage-check

# Benchmark
bench:
	cargo bench

# Security audit
audit:
	cargo audit

# Full check before commit
pre-commit: fmt lint test
	@echo "All checks passed!"

# Release preparation
release-prep: clean fmt lint test coverage-check audit
	@echo "Release preparation complete!"