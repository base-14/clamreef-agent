# ClamReef Agent Makefile

.PHONY: help build test lint fmt clean coverage install run dev check

# Default target
help:
	@echo "ClamReef Agent - Available targets:"
	@echo "  build     - Build release binary"
	@echo "  test      - Run all tests"
	@echo "  test-unit - Run unit tests only"
	@echo "  test-e2e  - Run end-to-end tests"
	@echo "  lint      - Run clippy linter"
	@echo "  fmt       - Format code with rustfmt"
	@echo "  coverage  - Generate test coverage report"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install binary to /usr/local/bin"
	@echo "  run       - Run the agent with default config"
	@echo "  dev       - Run in development mode"
	@echo "  check     - Check code without building"

# Build targets
build:
	cargo build --release

build-dev:
	cargo build

# Test targets
test:
	cargo test

test-unit:
	cargo test --lib

test-e2e:
	cargo test --test '*' -- --test-threads=1

# Code quality
lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

check:
	cargo check

# Coverage
coverage:
	cargo tarpaulin --out Html --output-dir target/coverage

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
install: build
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

# CI targets
ci-test: lint fmt-check test coverage

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
release-prep: clean fmt lint test coverage audit
	@echo "Release preparation complete!"