# Testing OAuth2 Authentication

This guide shows you how to test the ClamReef Agent with OAuth2 authentication.

## Setup

1. **Copy the example configuration:**
   ```bash
   cp test-oauth2.toml.example test-oauth2.toml
   ```

2. **Edit `test-oauth2.toml` with your actual credentials:**
   - Set `telemetry.endpoint` to your OTLP collector URL
   - Set `oauth2client.client_id` to your OAuth2 client ID
   - Set `oauth2client.client_secret` to your OAuth2 client secret
   - Set `oauth2client.token_url` to your identity provider's token endpoint
   - Set `oauth2client.endpoint_params.audience` to your required audience

   **Note:** The `test-oauth2.toml` file is gitignored, so your credentials won't be committed.

3. **Ensure ClamAV is running:**
   ```bash
   # On macOS with Homebrew
   brew services start clamav

   # Verify it's running
   ls -l /opt/homebrew/var/run/clamav/clamd.sock
   ```

4. **Create test directory:**
   ```bash
   mkdir -p /tmp/clamav-test
   echo "Test file" > /tmp/clamav-test/test.txt
   ```

## Running the Test

1. **Build the agent:**
   ```bash
   cargo build --release
   ```

2. **Validate the configuration:**
   ```bash
   ./target/release/clamreef-agent --config test-oauth2.toml --dry-run
   ```

3. **Run the agent with debug logging:**
   ```bash
   RUST_LOG=clamreef_agent=debug ./target/release/clamreef-agent --config test-oauth2.toml
   ```

## What to Look For

When the agent starts with OAuth2 configured, you should see:

1. **Token Fetch Logs:**
   ```
   INFO Successfully obtained OAuth2 token (expires in 3600 seconds)
   ```

2. **Telemetry Export Logs:**
   ```
   INFO Successfully obtained auth token for telemetry export
   ```

3. **Service Name:**
   The agent will report metrics with `service_name = "clamreef"` (or whatever you set in the config).

## Configuration Details

### Service Name
The `service_name` field in the telemetry configuration controls what service name is sent to OpenTelemetry. It defaults to `"clamreef"` if not specified.

### OAuth2 Token Caching
The agent caches OAuth2 tokens and automatically refreshes them 60 seconds before expiration, so you should only see periodic token fetch requests.

### Troubleshooting

- **"oauth2client authenticator specified but oauth2client configuration is missing"**
  - Make sure you have the `[oauth2client]` section in your config

- **"Failed to get auth token"**
  - Check your client_id, client_secret, and token_url are correct
  - Verify network connectivity to the identity provider

- **ClamAV connection errors**
  - Ensure ClamAV daemon is running: `brew services list | grep clamav`
  - Check the socket path is correct for your system
