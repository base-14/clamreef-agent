# ClamReef Agent - Implementation Plan

## Project Goals

Build a production-ready, cross-platform control plane agent for ClamAV that provides:
- Centralized monitoring through OpenTelemetry
- Scheduled scanning with flexible rules
- Future support for remote configuration management
- Minimal resource footprint
- Comprehensive test coverage

## Implementation Sequence

### 1. Project Foundation

- [ ] Initialize Rust project with Cargo.toml
- [ ] Create basic module structure
  - [ ] `src/main.rs` - Entry point
  - [ ] `src/lib.rs` - Library root
  - [ ] `src/config/mod.rs` - Configuration management
  - [ ] `src/clamav/mod.rs` - ClamAV interface
  - [ ] `src/telemetry/mod.rs` - OpenTelemetry integration
  - [ ] `src/scheduler/mod.rs` - Cron scheduler
  - [ ] `src/metrics/mod.rs` - Metric definitions
- [ ] Set up error handling
  - [ ] Add `anyhow` for application errors
  - [ ] Add `thiserror` for library errors
  - [ ] Create custom error types
- [ ] Implement logging
  - [ ] Add `tracing` and `tracing-subscriber`
  - [ ] Set up log levels and formatting
  - [ ] Add file logging option
- [ ] Create Makefile with commands
  - [ ] `make build` - Build release binary
  - [ ] `make test` - Run all tests
  - [ ] `make coverage` - Generate coverage report
  - [ ] `make lint` - Run clippy
  - [ ] `make fmt` - Format code
  - [ ] `make clean` - Clean artifacts
- [ ] Set up GitHub Actions CI
  - [ ] Test matrix for OS (Linux, macOS, Windows)
  - [ ] Rust version matrix (stable, beta)
  - [ ] Coverage reporting to codecov
  - [ ] Security audit with cargo-audit
  - [ ] Release workflow for tags

### 2. ClamAV Integration

- [ ] Design ClamAV abstraction layer
  - [ ] Define `ClamAVClient` trait
  - [ ] Create error types for ClamAV operations
  - [ ] Design scan result structures
- [ ] Implement Unix socket communication
  - [ ] Connect to ClamAV socket
  - [ ] Send commands (PING, VERSION, STATS, SCAN)
  - [ ] Parse responses
  - [ ] Handle connection errors
- [ ] Implement TCP communication
  - [ ] TCP connection with configurable host/port
  - [ ] Command protocol implementation
  - [ ] Connection pooling for efficiency
- [ ] Parse ClamAV outputs
  - [ ] STATS command parser
  - [ ] SCAN result parser
  - [ ] VERSION info parser
  - [ ] Error response handling
- [ ] Create mock implementation
  - [ ] Mock client for testing
  - [ ] Configurable responses
  - [ ] Error simulation
- [ ] Write tests
  - [ ] Unit tests for parsers
  - [ ] Integration tests with mock
  - [ ] Connection retry logic tests

### 3. Configuration System

- [ ] Define configuration structures
  ```rust
  struct Config {
      agent: AgentConfig,
      telemetry: TelemetryConfig,
      clamav: ClamAVConfig,
      rules: Vec<ScanRule>,
  }
  ```
- [ ] Implement TOML parsing
  - [ ] Add `serde` and `toml` dependencies
  - [ ] Derive Serialize/Deserialize
  - [ ] Custom deserializers for complex types
- [ ] Add validation logic
  - [ ] Validate cron expressions
  - [ ] Validate paths exist
  - [ ] Validate network endpoints
  - [ ] Check for conflicting rules
- [ ] Support environment variables
  - [ ] Override config with env vars
  - [ ] Document env var names
  - [ ] Precedence rules
- [ ] Implement config loading
  - [ ] Search standard locations
  - [ ] Support custom path via CLI
  - [ ] Load and merge configs
- [ ] Add hot-reload capability
  - [ ] File watcher for config changes
  - [ ] Graceful reload without restart
  - [ ] Validation before applying
- [ ] Create example configs
  - [ ] Minimal configuration
  - [ ] Full-featured example
  - [ ] Platform-specific examples

### 4. Scheduler Implementation

- [ ] Integrate cron parser
  - [ ] Add `cron` and `chrono` dependencies
  - [ ] Parse and validate expressions
  - [ ] Calculate next run times
- [ ] Build async scheduler
  - [ ] Use tokio for async runtime
  - [ ] Schedule registry
  - [ ] Task queue implementation
- [ ] Implement scan executor
  - [ ] Path traversal logic
  - [ ] Exclusion pattern matching
  - [ ] File size limits
  - [ ] Symlink handling
- [ ] Add concurrency control
  - [ ] Limit parallel scans
  - [ ] Queue management
  - [ ] Priority handling
- [ ] Implement result handling
  - [ ] Result aggregation
  - [ ] Error recovery
  - [ ] Retry logic
- [ ] Create scheduler tests
  - [ ] Time mocking with `tokio::time`
  - [ ] Concurrent execution tests
  - [ ] Error handling tests

### 5. OpenTelemetry Integration

- [ ] Set up OpenTelemetry SDK
  - [ ] Add OpenTelemetry dependencies
  - [ ] Initialize tracer and meter providers
  - [ ] Configure resource attributes
- [ ] Configure OTLP exporter
  - [ ] gRPC endpoint configuration
  - [ ] TLS support
  - [ ] Authentication headers
  - [ ] Retry and timeout settings
- [ ] Define metrics
  - [ ] Counter: `clamav_scans_total`
  - [ ] Counter: `clamav_threats_detected_total`
  - [ ] Histogram: `clamav_scan_duration_seconds`
  - [ ] Gauge: `clamav_database_version`
  - [ ] Gauge: `clamreef_agent_info`
- [ ] Implement collection logic
  - [ ] Periodic stats collection
  - [ ] Scan result metrics
  - [ ] System metrics
  - [ ] Custom attributes/labels
- [ ] Add batching and buffering
  - [ ] Batch metrics for efficiency
  - [ ] Local buffering on failure
  - [ ] Backpressure handling
- [ ] Handle failures
  - [ ] Exponential backoff
  - [ ] Circuit breaker pattern
  - [ ] Fallback to local storage
- [ ] Test with collectors
  - [ ] Local OTLP collector setup
  - [ ] Docker compose for testing
  - [ ] Metric verification

### 6. Main Agent Implementation

- [ ] Create CLI interface
  - [ ] Use `clap` for argument parsing
  - [ ] Define command-line options
  - [ ] Help text and examples
- [ ] Implement agent lifecycle
  - [ ] Initialization sequence
  - [ ] Component startup order
  - [ ] Health check endpoint
  - [ ] Graceful shutdown
- [ ] Build main event loop
  - [ ] Component orchestration
  - [ ] Error handling
  - [ ] State management
- [ ] Add signal handling
  - [ ] SIGTERM/SIGINT for shutdown
  - [ ] SIGHUP for reload
  - [ ] Platform-specific handling
- [ ] Implement dry-run mode
  - [ ] Config validation only
  - [ ] No actual scanning
  - [ ] Report what would run

### 7. Testing & Quality

- [ ] Unit test coverage
  - [ ] Achieve 80%+ coverage
  - [ ] Test error paths
  - [ ] Property-based tests
- [ ] Integration tests
  - [ ] Component interaction tests
  - [ ] Configuration loading tests
  - [ ] Scheduler integration tests
- [ ] End-to-end tests
  - [ ] Full agent lifecycle
  - [ ] Multi-rule scenarios
  - [ ] Failure recovery tests
- [ ] Performance testing
  - [ ] Benchmark critical paths
  - [ ] Memory profiling
  - [ ] Load testing with many rules
- [ ] Cross-platform testing
  - [ ] Linux (Ubuntu, RHEL)
  - [ ] macOS (Intel, ARM)
  - [ ] Windows (Server 2019+)
- [ ] Security audit
  - [ ] Dependency scanning
  - [ ] SAST analysis
  - [ ] Permission checks

### 8. Deployment & Packaging

- [ ] Create systemd service
  - [ ] Service file template
  - [ ] Installation script
  - [ ] Log rotation config
- [ ] Build Docker image
  - [ ] Multi-stage Dockerfile
  - [ ] Minimal base image
  - [ ] Health check included
- [ ] Set up releases
  - [ ] GitHub Actions release workflow
  - [ ] Binary builds for platforms
  - [ ] Checksums and signatures
- [ ] Package for distributions
  - [ ] DEB package for Debian/Ubuntu
  - [ ] RPM package for RHEL/Fedora
  - [ ] Homebrew formula for macOS
  - [ ] Cargo crate publication

### 9. Documentation

- [ ] API documentation
  - [ ] Rustdoc for all public APIs
  - [ ] Examples in doc comments
  - [ ] Generate with `cargo doc`
- [ ] User guide
  - [ ] Installation instructions
  - [ ] Configuration guide
  - [ ] Troubleshooting section
- [ ] Development docs
  - [ ] Architecture overview
  - [ ] Contributing guidelines
  - [ ] Code style guide
- [ ] Example configurations
  - [ ] Common use cases
  - [ ] Platform-specific examples
  - [ ] Performance tuning
- [ ] Monitoring setup
  - [ ] Grafana dashboard templates
  - [ ] Prometheus queries
  - [ ] Alert rule examples

## Version 1.0 Checklist

### Must Have
- [x] Core ClamAV integration
- [x] Local configuration support
- [x] Cron-based scheduling
- [x] OpenTelemetry metrics
- [x] Cross-platform support
- [x] 80%+ test coverage
- [x] Complete documentation

### Nice to Have
- [ ] Configuration hot-reload
- [ ] Health check endpoint
- [ ] Grafana dashboards
- [ ] Package manager support

## Future Roadmap

### Version 1.1 - Stability
- [ ] Performance optimizations
- [ ] Enhanced error messages
- [ ] Improved logging
- [ ] Bug fixes from v1.0

### Version 2.0 - Remote Configuration
- [ ] ClamReef Server integration
- [ ] Remote config fetching
- [ ] Config versioning
- [ ] Centralized rule management

### Version 2.1 - Enhanced Observability
- [ ] Distributed tracing
- [ ] Log aggregation
- [ ] Custom dashboards
- [ ] Alert management

### Version 3.0 - Advanced Features
- [ ] Real-time monitoring
- [ ] Threat intelligence
- [ ] Auto-remediation
- [ ] Cloud storage support

## Technical Stack

### Core Dependencies
```toml
[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# CLI
clap = { version = "4.4", features = ["derive"] }

# OpenTelemetry
opentelemetry = "0.21"
opentelemetry-otlp = { version = "0.14", features = ["tls"] }
opentelemetry_sdk = { version = "0.21", features = ["rt-tokio"] }

# Scheduling
cron = "0.12"
chrono = "0.4"

# Utilities
regex = "1.10"
glob = "0.3"

[dev-dependencies]
mockall = "0.12"
tempfile = "3.8"
pretty_assertions = "1.4"
tokio-test = "0.4"
```

## Performance Requirements

- Memory: < 50MB RSS
- CPU: < 1% idle
- Startup: < 1 second
- Config reload: < 500ms
- Scan throughput: > 100MB/s

## Security Considerations

- Run as non-privileged user
- Config file permissions (600)
- TLS for telemetry transport
- Input validation on all inputs
- Resource limits to prevent DoS
- No secrets in logs or metrics

## Contributing

This is an open-source project. Contributions are welcome!

1. Check existing issues or create new ones
2. Fork and create feature branch
3. Write tests for new features
4. Ensure all tests pass
5. Submit PR with clear description

## License

MIT License - See LICENSE file for details