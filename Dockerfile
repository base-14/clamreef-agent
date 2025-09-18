# Multi-stage build for ClamReef Agent
FROM rust:1.75-slim-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1001 clamreef

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target-dir /tmp/target
RUN rm -rf src

# Copy source code
COPY src/ ./src/

# Build the actual application
RUN cargo build --release --target-dir /tmp/target

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app user and directories
RUN useradd -m -u 1001 clamreef \
    && mkdir -p /etc/clamreef /var/log/clamreef \
    && chown -R clamreef:clamreef /etc/clamreef /var/log/clamreef

# Copy binary from builder stage
COPY --from=builder /tmp/target/release/clamreef-agent /usr/local/bin/clamreef-agent

# Copy default configuration
COPY examples/agent.toml /etc/clamreef/agent.toml.example

# Set permissions
RUN chmod +x /usr/local/bin/clamreef-agent \
    && chown clamreef:clamreef /etc/clamreef/agent.toml.example

# Create entrypoint script
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Update ClamAV database if needed
echo "Updating ClamAV database..."
freshclam --quiet || echo "Database update failed, continuing with existing database"

# Start ClamAV daemon in background
echo "Starting ClamAV daemon..."
clamd &

# Wait for ClamAV socket to be available
echo "Waiting for ClamAV daemon to start..."
timeout 60 bash -c 'until [ -S /var/run/clamav/clamd.ctl ]; do sleep 1; done' || {
    echo "ClamAV daemon failed to start"
    exit 1
}

echo "ClamAV daemon started successfully"

# Start ClamReef Agent
echo "Starting ClamReef Agent..."
exec /usr/local/bin/clamreef-agent "$@"
EOF

RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER clamreef

# Expose health check port (if implemented)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/clamreef-agent --version > /dev/null || exit 1

# Set default command
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "/etc/clamreef/agent.toml"]

# Metadata
ARG VERSION=unknown
LABEL org.opencontainers.image.title="ClamReef Agent"
LABEL org.opencontainers.image.description="Lightweight control plane agent for ClamAV with OpenTelemetry support"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.authors="ClamReef Contributors"
LABEL org.opencontainers.image.source="https://github.com/yourusername/clamreef-agent"
LABEL org.opencontainers.image.documentation="https://github.com/yourusername/clamreef-agent/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"