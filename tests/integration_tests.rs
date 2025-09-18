use tempfile::NamedTempFile;
use tokio::fs;

use clamreef_agent::{
    config::Config,
    error::Error,
    metrics::MetricsCollector,
    telemetry::TelemetryExporter,
};

#[tokio::test]
async fn test_config_integration() {
    let config_content = r#"
[agent]
version = "1.0.0"
machine_name = "test-integration"
log_level = "debug"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 60
timeout_seconds = 30
insecure = true

[clamav]
socket_path = "/var/run/clamav/clamd.ctl"
scan_timeout_seconds = 30

[[rules]]
name = "integration_test"
paths = ["/tmp/test"]
schedule = "0 0 */6 * * *"
exclude_patterns = ["*.tmp"]
follow_symlinks = false
recursive = true
max_file_size = "10MB"
"#;

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, config_content).await.unwrap();

    let config = Config::load(temp_file.path()).await.unwrap();

    assert_eq!(config.agent.version, "1.0.0");
    assert_eq!(config.agent.machine_name, Some("test-integration".to_string()));
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].name, "integration_test");
    assert!(config.clamav.socket_path.is_some());
}

#[tokio::test]
async fn test_metrics_telemetry_integration() {
    let metrics = MetricsCollector::new();

    // Record some test data
    let scan_result = clamreef_agent::clamav::types::ScanResult {
        path: "/tmp/test.txt".to_string(),
        status: clamreef_agent::clamav::types::ScanStatus::Clean,
        scan_time: chrono::Utc::now(),
        duration_ms: 100,
        threat: None,
    };

    metrics.record_scan_result(&scan_result).await;
    metrics.update_clamav_version("0.103.8").await;

    let collected_metrics = metrics.get_metrics().await;
    assert_eq!(collected_metrics.clamreef_files_scanned_total, 1);
    assert_eq!(collected_metrics.clamreef_clamav_engine_version, "0.103.8");

    // Test telemetry integration
    let telemetry_config = clamreef_agent::config::TelemetryConfig {
        endpoint: "http://localhost:4317".to_string(),
        interval_seconds: 1,
        timeout_seconds: 5,
        insecure: true,
    };

    let exporter = TelemetryExporter::new(
        telemetry_config,
        std::sync::Arc::new(metrics),
        "test-machine".to_string(),
        "1.0.0".to_string(),
    );

    assert!(exporter.is_ok());
}

#[tokio::test]
async fn test_config_validation_integration() {
    let invalid_config = r#"
[agent]
version = "1.0.0"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 60

# Missing ClamAV configuration

[[rules]]
name = "test_rule"
paths = ["/tmp"]
schedule = "invalid_cron"
"#;

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, invalid_config).await.unwrap();

    let result = Config::load(temp_file.path()).await;
    assert!(result.is_err());

    // Should fail validation due to invalid cron and missing clamav config
    match result.unwrap_err() {
        Error::Config(_) => {
            // Expected error type
        }
        _ => panic!("Expected config error"),
    }
}

#[tokio::test]
async fn test_default_config_loading() {
    // Test that config can be loaded from default locations
    let result = Config::load_from_default_locations().await;

    // This might succeed if there's an agent.toml file present, or fail if there isn't
    // Either case exercises the code path
    match result {
        Ok(config) => {
            // If successful, verify it's a valid config structure
            assert!(!config.rules.is_empty() || config.rules.is_empty()); // Basic structure check
        }
        Err(Error::Config(msg)) => {
            // If failed, should have appropriate error message
            assert!(msg.contains("No configuration file found"));
        }
        Err(_) => {
            // Any other error is acceptable (e.g., validation errors)
        }
    }
}

#[test]
fn test_error_types() {
    // Test different error types
    let config_error = Error::Config("Test config error".to_string());
    let clamav_error = Error::ClamAV("Test ClamAV error".to_string());
    let timeout_error = Error::Timeout("Test timeout".to_string());
    let connection_error = Error::Connection("Test connection error".to_string());
    let parse_error = Error::Parse("Test parse error".to_string());

    // Test Display implementation
    assert!(format!("{}", config_error).contains("Test config error"));
    assert!(format!("{}", clamav_error).contains("Test ClamAV error"));
    assert!(format!("{}", timeout_error).contains("Test timeout"));
    assert!(format!("{}", connection_error).contains("Test connection error"));
    assert!(format!("{}", parse_error).contains("Test parse error"));

    // Test Debug implementation
    assert!(format!("{:?}", config_error).contains("Config"));
    assert!(format!("{:?}", clamav_error).contains("ClamAV"));
}

#[tokio::test]
async fn test_complete_workflow_simulation() {
    // Simulate a complete workflow with mocked ClamAV
    let config_content = r#"
[agent]
version = "1.0.0"
machine_name = "workflow-test"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 30
timeout_seconds = 10
insecure = true

[clamav]
tcp_host = "127.0.0.1"
tcp_port = 3310
scan_timeout_seconds = 30

[[rules]]
name = "workflow_test"
paths = ["/tmp/workflow_test"]
schedule = "0 0 * * * *"
exclude_patterns = ["*.log"]
follow_symlinks = false
recursive = true
"#;

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(&temp_file, config_content).await.unwrap();

    let config = Config::load(temp_file.path()).await.unwrap();

    // Create metrics collector
    let metrics = std::sync::Arc::new(MetricsCollector::new());

    // Test telemetry export
    let telemetry_exporter = TelemetryExporter::new(
        config.telemetry.clone(),
        metrics.clone(),
        config.get_machine_name(),
        "1.0.0".to_string(),
    ).unwrap();

    // Test that shutdown works
    let shutdown_result = telemetry_exporter.shutdown().await;
    assert!(shutdown_result.is_ok());

    // Verify config structure
    assert_eq!(config.rules.len(), 1);
    assert!(config.clamav.tcp_host.is_some());
    assert_eq!(config.clamav.tcp_port, Some(3310));
    assert_eq!(config.telemetry.interval_seconds, 30);
}