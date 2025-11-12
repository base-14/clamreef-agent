# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ClamReef Agent is a Rust-based control plane agent for ClamAV antivirus. It acts as a lightweight, cross-platform monitoring and configuration agent that reports telemetry data via OpenTelemetry and fetches centralized configuration from ClamReef Server.

## Technology Stack

- **Language**: Rust
- **Build System**: Cargo with Makefile wrapper
- **Testing**: Built-in Rust unit tests + E2E tests
- **Dependencies**: ClamAV (must be installed on the system)
- **Telemetry**: OpenTelemetry for metrics reporting
- **Configuration**: Local TOML/YAML for v1, remote config in future versions

## Common Commands

```bash
# Build
make build
cargo build --release

# Run tests
make test
cargo test

# Run unit tests only
cargo test --lib

# Run E2E tests
make test-e2e
cargo test --test '*' -- --test-threads=1

# Check code coverage
make coverage
cargo tarpaulin --out Html

# Lint and format
make lint
cargo clippy -- -D warnings
cargo fmt --check

# Run the agent
make run
cargo run --release

# Clean build artifacts
make clean
cargo clean
```

## Architecture

### Core Components

1. **ClamAV Interface** (`src/clamav/`)
   - Interacts with ClamAV daemon or CLI
   - Parses STATS output for metrics
   - Manages scan operations and results
   - Automatic database updates via freshclam with configurable scheduling

2. **Authentication Module** (`src/auth/`)
   - OAuth2 client credentials flow implementation
   - Token caching with automatic refresh (60 second buffer before expiration)
   - Pluggable authentication provider trait for future auth methods

3. **Telemetry Module** (`src/telemetry/`)
   - OpenTelemetry integration for metrics export
   - Custom metrics for ClamAV stats (scan count, virus detections, database version)
   - System metrics (version, machine name)
   - Implements OTLP exporter with optional OAuth2 authentication

4. **Configuration Management** (`src/config/`)
   - Local config loader (TOML/YAML) for v1
   - Rule structure: scan paths, patterns, exclusions
   - Cron-like scheduling for each rule
   - Future: Remote config fetcher from ClamReef Server

5. **Scheduler** (`src/scheduler/`)
   - Cron expression parser and executor
   - Rule-based scan scheduling
   - Async task management using tokio

6. **Main Agent Loop** (`src/main.rs`)
   - Initializes OpenTelemetry pipeline
   - Loads configuration
   - Starts scheduler
   - Periodic telemetry reporting

### Key Design Decisions

- **Small Footprint**: Use minimal dependencies, prefer std library where possible
- **Cross-Platform**: Abstract OS-specific code behind traits
- **Async Runtime**: Use tokio for concurrent operations
- **Error Handling**: Use `anyhow` for application errors, `thiserror` for library errors
- **Configuration Format**: TOML for human-readable config with serde

### Data Flow

1. Agent starts → Load local config
2. Initialize OpenTelemetry with OTLP endpoint
3. Start scheduler with rules from config
4. For each scheduled scan:
   - Execute ClamAV scan
   - Parse results
   - Send metrics via OpenTelemetry
5. Periodically report system metrics

### Configuration Schema (v1)

```toml
[agent]
version = "1.0.0"
machine_name = "hostname"  # Optional, auto-detected if not set

[telemetry]
endpoint = "http://localhost:4317"  # OTLP gRPC endpoint
interval_seconds = 60

# Optional: OAuth2 authentication for telemetry endpoint
[telemetry.auth]
authenticator = "oauth2client"

# OAuth2 client credentials (required if telemetry.auth.authenticator = "oauth2client")
[oauth2client]
client_id = "your-client-id"
client_secret = "your-client-secret"
token_url = "https://auth.example.com/oauth/token"

[oauth2client.endpoint_params]
audience = "your-audience"  # Optional additional parameters

[clamav]
socket_path = "/var/run/clamav/clamd.ctl"  # Unix socket
# OR
tcp_host = "127.0.0.1"
tcp_port = 3310

# Optional: Freshclam configuration for automatic database updates
[freshclam]
enabled = true  # Set to false to disable automatic updates (default: true)
schedule = "0 0 0 * * SUN"  # Cron schedule (default: once a week on Sunday at midnight)
reload_after_update = true  # Reload ClamAV daemon after successful update (default: true)

[[rules]]
name = "system_scan"
paths = ["/usr/local/bin", "/opt"]
schedule = "0 */6 * * *"  # Every 6 hours
exclude_patterns = ["*.log", "*.tmp"]
```

See `examples/agent-oauth2.toml` for a complete OAuth2 configuration example.

## Testing Strategy

- **Unit Tests**: Test individual modules in isolation (clamav parser, config loader, scheduler)
- **Integration Tests**: Test component interactions (telemetry export, ClamAV communication)
- **E2E Tests**: Full agent lifecycle with mock ClamAV and OTLP collector
- **Coverage Target**: Minimum 80% code coverage

## Development Notes

- Use `cargo-tarpaulin` for coverage reports
- Run `cargo clippy` before commits
- Use `cargo fmt` for consistent formatting
- Cross-platform testing required for Windows, Linux, macOS
- Mock ClamAV responses for testing to avoid dependency on installed ClamAV