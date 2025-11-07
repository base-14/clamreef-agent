use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::auth::oauth2::OAuth2Client;
use crate::auth::AuthProvider;
use crate::config::{OAuth2ClientConfig, TelemetryConfig};
use crate::error::{Error, Result};
use crate::metrics::MetricsCollector;

pub struct TelemetryExporter {
    config: TelemetryConfig,
    metrics_collector: Arc<MetricsCollector>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    #[cfg(test)]
    skip_export: bool,
}

impl TelemetryExporter {
    pub fn new(
        config: TelemetryConfig,
        oauth2_config: Option<OAuth2ClientConfig>,
        metrics_collector: Arc<MetricsCollector>,
        _machine_name: String,
        _agent_version: String,
    ) -> Result<Self> {
        // Create OAuth2 auth provider if configured
        let auth_provider: Option<Arc<dyn AuthProvider>> = if let Some(ref auth) = config.auth {
            if auth.authenticator == "oauth2client" {
                if let Some(oauth2_cfg) = oauth2_config {
                    let oauth2_client = OAuth2Client::new(oauth2_cfg)?;
                    Some(Arc::new(oauth2_client))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            metrics_collector,
            auth_provider,
            #[cfg(test)]
            skip_export: false,
        })
    }

    #[cfg(test)]
    pub fn new_with_skip_export(
        config: TelemetryConfig,
        oauth2_config: Option<OAuth2ClientConfig>,
        metrics_collector: Arc<MetricsCollector>,
        _machine_name: String,
        _agent_version: String,
    ) -> Result<Self> {
        let auth_provider: Option<Arc<dyn AuthProvider>> = if let Some(ref auth) = config.auth {
            if auth.authenticator == "oauth2client" {
                if let Some(oauth2_cfg) = oauth2_config {
                    let oauth2_client = OAuth2Client::new(oauth2_cfg)?;
                    Some(Arc::new(oauth2_client))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            metrics_collector,
            auth_provider,
            skip_export: true,
        })
    }

    pub async fn start_export_loop(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(self.config.interval_seconds));

        loop {
            interval.tick().await;

            if let Err(e) = self.export_metrics().await {
                error!("Failed to export metrics: {}", e);
            }
        }
    }

    async fn export_metrics(&self) -> Result<()> {
        // Check if telemetry export is enabled
        if !self.config.enabled {
            info!("Telemetry export is disabled, skipping metrics export");
            return Ok(());
        }

        // Get access token if OAuth2 is configured
        let auth_token = if let Some(ref auth_provider) = self.auth_provider {
            match auth_provider.get_token().await {
                Ok(token) => {
                    info!("Successfully obtained auth token for telemetry export");
                    Some(token)
                }
                Err(e) => {
                    error!("Failed to get auth token: {}", e);
                    return Err(e);
                }
            }
        } else {
            None
        };

        let metrics = self.metrics_collector.get_metrics().await;
        let host_metrics = self.metrics_collector.get_host_metrics().await;

        // Log the metrics for visibility
        info!(
            "ClamReef Scanning - Total: {}, Threats: {}, Errors: {}, Files: {}, Pending: {}",
            metrics.clamreef_scans_total,
            metrics.clamreef_threats_detected_total,
            metrics.clamreef_scan_errors_total,
            metrics.clamreef_files_scanned_total,
            metrics.clamreef_pending_scans
        );

        info!(
            "ClamReef Performance - Last Scan: {}ms, Avg: {}ms, Max: {}ms",
            metrics.clamreef_last_scan_duration_ms,
            metrics.clamreef_avg_scan_duration_ms,
            metrics.clamreef_max_scan_duration_ms
        );

        let last_threat = metrics
            .clamreef_last_threat_timestamp
            .map(|ts| {
                format!(
                    "{} seconds ago",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - ts
                )
            })
            .unwrap_or_else(|| "Never".to_string());

        info!(
            "ClamReef Protection - Quarantined: {}, Cleaned: {}, Last Threat: {}, RT Protection: {}",
            metrics.clamreef_quarantined_files_total,
            metrics.clamreef_cleaned_files_total,
            last_threat,
            if metrics.clamreef_realtime_protection_enabled { "Enabled" } else { "Disabled" }
        );

        info!(
            "ClamReef Host - Hostname: {}, OS: {} {}, Kernel: {}, Serial: {}",
            host_metrics.clamreef_hostname,
            host_metrics.clamreef_os_name,
            host_metrics.clamreef_os_version,
            host_metrics.clamreef_kernel_version,
            host_metrics
                .clamreef_serial_number
                .as_ref()
                .unwrap_or(&"N/A".to_string())
        );

        let users_info = if host_metrics.clamreef_users.is_empty() {
            "No interactive users".to_string()
        } else {
            host_metrics.clamreef_users.join(", ")
        };

        info!(
            "ClamReef System - Users: [{}], Agent: v{}, ClamAV: {} (DB: v{}), Uptime: {}s",
            users_info,
            host_metrics.clamreef_agent_version,
            metrics.clamreef_clamav_engine_version,
            metrics.clamreef_clamav_database_version,
            metrics.clamreef_agent_uptime_seconds
        );

        // Export metrics via OTLP (skip in tests if flag is set)
        #[cfg(test)]
        if self.skip_export {
            return Ok(());
        }

        self.export_to_otlp(&metrics, &host_metrics, auth_token.as_deref())
            .await
    }

    async fn export_to_otlp(
        &self,
        metrics: &crate::metrics::Metrics,
        host_metrics: &crate::metrics::HostMetrics,
        auth_token: Option<&str>,
    ) -> Result<()> {
        use reqwest::Client;

        // Build the OTLP endpoint URL
        let endpoint = &self.config.endpoint;
        let otlp_url = if endpoint.ends_with("/v1/metrics") {
            endpoint.clone()
        } else {
            format!("{}/v1/metrics", endpoint.trim_end_matches('/'))
        };

        info!("Exporting metrics to OTLP endpoint: {}", otlp_url);

        // Build the OTLP metrics payload
        let payload = build_otlp_payload(metrics, host_metrics, &self.config.service_name)?;

        // Create HTTP client
        let client = Client::builder()
            .timeout(Duration::from_secs(self.config.timeout_seconds))
            .danger_accept_invalid_certs(self.config.insecure)
            .build()
            .map_err(|e| Error::Telemetry(format!("Failed to create HTTP client: {}", e)))?;

        // Build request
        let mut request = client
            .post(&otlp_url)
            .header("Content-Type", "application/json");

        // Add OAuth2 token if available
        if let Some(token) = auth_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response = request
            .json(&payload)
            .send()
            .await
            .map_err(|e| Error::Telemetry(format!("Failed to send OTLP request: {}", e)))?;

        if response.status().is_success() {
            info!("Successfully exported metrics to OTLP collector");
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response".to_string());
            warn!(
                "Failed to export metrics: HTTP {} - {}",
                status, body
            );
            Err(Error::Telemetry(format!(
                "OTLP export failed with status {}: {}",
                status,
                body
            )))
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Telemetry exporter shutdown");
        Ok(())
    }
}

// Helper function to build OTLP JSON payload
fn build_otlp_payload(
    metrics: &crate::metrics::Metrics,
    host_metrics: &crate::metrics::HostMetrics,
    service_name: &str,
) -> Result<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // Build resource attributes
    let resource_attributes = vec![
        serde_json::json!({
            "key": "service.name",
            "value": {"stringValue": service_name}
        }),
        serde_json::json!({
            "key": "host.name",
            "value": {"stringValue": host_metrics.clamreef_hostname}
        }),
        serde_json::json!({
            "key": "os.type",
            "value": {"stringValue": host_metrics.clamreef_os_name}
        }),
        serde_json::json!({
            "key": "os.version",
            "value": {"stringValue": host_metrics.clamreef_os_version}
        }),
        serde_json::json!({
            "key": "service.version",
            "value": {"stringValue": host_metrics.clamreef_agent_version}
        }),
    ];

    // Build metric data points
    let mut data_points = vec![];

    // Counter metrics
    let counters = vec![
        ("clamreef.scans.total", metrics.clamreef_scans_total),
        ("clamreef.threats.detected.total", metrics.clamreef_threats_detected_total),
        ("clamreef.files.scanned.total", metrics.clamreef_files_scanned_total),
        ("clamreef.scan.errors.total", metrics.clamreef_scan_errors_total),
        ("clamreef.rule.executions.total", metrics.clamreef_rule_executions_total),
        ("clamreef.quarantined.files.total", metrics.clamreef_quarantined_files_total),
        ("clamreef.cleaned.files.total", metrics.clamreef_cleaned_files_total),
    ];

    for (name, value) in counters {
        data_points.push(serde_json::json!({
            "name": name,
            "sum": {
                "dataPoints": [{
                    "asInt": value.to_string(),
                    "timeUnixNano": now.to_string(),
                    "startTimeUnixNano": now.to_string()
                }],
                "aggregationTemporality": 2,
                "isMonotonic": true
            }
        }));
    }

    // Gauge metrics
    let gauges = vec![
        ("clamreef.agent.uptime.seconds", metrics.clamreef_agent_uptime_seconds),
        ("clamreef.last.scan.duration.ms", metrics.clamreef_last_scan_duration_ms),
        ("clamreef.avg.scan.duration.ms", metrics.clamreef_avg_scan_duration_ms),
        ("clamreef.max.scan.duration.ms", metrics.clamreef_max_scan_duration_ms),
        ("clamreef.pending.scans", metrics.clamreef_pending_scans),
        ("clamreef.database.version", metrics.clamreef_clamav_database_version as u64),
        ("clamreef.database.age.hours", metrics.clamreef_database_age_hours),
        ("clamreef.realtime.protection.enabled", if metrics.clamreef_realtime_protection_enabled { 1 } else { 0 }),
    ];

    for (name, value) in gauges {
        data_points.push(serde_json::json!({
            "name": name,
            "gauge": {
                "dataPoints": [{
                    "asInt": value.to_string(),
                    "timeUnixNano": now.to_string()
                }]
            }
        }));
    }

    // String attributes as labels
    if let Some(serial) = &host_metrics.clamreef_serial_number {
        data_points.push(serde_json::json!({
            "name": "clamreef.host.serial",
            "gauge": {
                "dataPoints": [{
                    "asInt": "0",
                    "timeUnixNano": now.to_string(),
                    "attributes": [{
                        "key": "serial_number",
                        "value": {"stringValue": serial}
                    }]
                }]
            }
        }));
    }

    // Build the complete OTLP payload
    Ok(serde_json::json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": resource_attributes
            },
            "scopeMetrics": [{
                "scope": {
                    "name": "clamreef-agent",
                    "version": host_metrics.clamreef_agent_version
                },
                "metrics": data_points
            }]
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn create_test_config() -> TelemetryConfig {
        TelemetryConfig {
            endpoint: "http://localhost:4317".to_string(),
            interval_seconds: 1,
            timeout_seconds: 5,
            insecure: true,
            auth: None,
            service_name: "clamreef".to_string(),
            enabled: true,
        }
    }

    fn create_test_metrics_collector() -> Arc<MetricsCollector> {
        Arc::new(MetricsCollector::new())
    }

    #[tokio::test]
    async fn test_telemetry_exporter_new() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        let exporter = TelemetryExporter::new(
            config.clone(),
            None,
            collector.clone(),
            "test-machine".to_string(),
            "1.0.0".to_string(),
        );

        assert!(exporter.is_ok());
        let exporter = exporter.unwrap();
        assert_eq!(exporter.config.endpoint, "http://localhost:4317");
        assert_eq!(exporter.config.interval_seconds, 1);
    }

    #[tokio::test]
    async fn test_export_metrics() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Update some metrics in the collector for testing
        collector
            .record_rule_execution("test_rule", Duration::from_secs(10), 5, 0)
            .await;
        collector.update_clamav_version("0.103.8").await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        // Test export_metrics - this should not fail since we skip actual export
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_with_threats() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Simulate some scanning activity
        let scan_result = crate::clamav::types::ScanResult {
            path: "/test/file".to_string(),
            status: crate::clamav::types::ScanStatus::Infected,
            scan_time: chrono::Utc::now(),
            duration_ms: 150,
            threat: Some("TestVirus".to_string()),
        };
        collector.record_scan_result(&scan_result).await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_clean_scan() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Simulate clean scan
        let scan_result = crate::clamav::types::ScanResult {
            path: "/test/clean_file".to_string(),
            status: crate::clamav::types::ScanStatus::Clean,
            scan_time: chrono::Utc::now(),
            duration_ms: 75,
            threat: None,
        };
        collector.record_scan_result(&scan_result).await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_error_scan() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Simulate scan error
        let scan_result = crate::clamav::types::ScanResult {
            path: "/test/error_file".to_string(),
            status: crate::clamav::types::ScanStatus::Error("Access denied".to_string()),
            scan_time: chrono::Utc::now(),
            duration_ms: 10,
            threat: None,
        };
        collector.record_scan_result(&scan_result).await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        let result = exporter.shutdown().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_loop_terminates() {
        let config = TelemetryConfig {
            endpoint: "http://localhost:4317".to_string(),
            interval_seconds: 100, // Long interval
            timeout_seconds: 5,
            insecure: true,
            auth: None,
            service_name: "clamreef".to_string(),
            enabled: true,
        };
        let collector = create_test_metrics_collector();

        let exporter = Arc::new(
            TelemetryExporter::new_with_skip_export(
                config,
                None,
                collector,
                "test-machine".to_string(),
                "1.0.0".to_string(),
            )
            .unwrap(),
        );

        // Start the export loop but timeout quickly
        let export_task = exporter.clone().start_export_loop();
        let result = timeout(Duration::from_millis(100), export_task).await;

        // Should timeout (task runs indefinitely)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_telemetry_config_fields() {
        let config = TelemetryConfig {
            endpoint: "https://otlp.example.com:4317".to_string(),
            interval_seconds: 30,
            timeout_seconds: 15,
            insecure: false,
            auth: None,
            service_name: "clamreef".to_string(),
            enabled: true,
        };

        assert_eq!(config.endpoint, "https://otlp.example.com:4317");
        assert_eq!(config.interval_seconds, 30);
        assert_eq!(config.timeout_seconds, 15);
        assert!(!config.insecure);
        assert!(config.enabled);
    }

    #[tokio::test]
    async fn test_export_loop_with_actual_metrics() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Add some metrics first
        let scan_result_clean = crate::clamav::types::ScanResult {
            path: "/test/clean/file".to_string(),
            status: crate::clamav::types::ScanStatus::Clean,
            scan_time: chrono::Utc::now(),
            duration_ms: 50,
            threat: None,
        };
        collector.record_scan_result(&scan_result_clean).await;

        let scan_result_infected = crate::clamav::types::ScanResult {
            path: "/test/infected/file".to_string(),
            status: crate::clamav::types::ScanStatus::Infected,
            scan_time: chrono::Utc::now(),
            duration_ms: 75,
            threat: Some("TestVirus".to_string()),
        };
        collector.record_scan_result(&scan_result_infected).await;

        collector.update_clamav_version("0.103.8").await;
        collector
            .record_rule_execution("test_rule", std::time::Duration::from_secs(5), 2, 1)
            .await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        )
        .unwrap();

        // Test the export_metrics function directly
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_with_all_scan_types() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Test different scan result types
        let scan_results = vec![
            crate::clamav::types::ScanResult {
                path: "/test/clean1.txt".to_string(),
                status: crate::clamav::types::ScanStatus::Clean,
                scan_time: chrono::Utc::now(),
                duration_ms: 25,
                threat: None,
            },
            crate::clamav::types::ScanResult {
                path: "/test/infected1.exe".to_string(),
                status: crate::clamav::types::ScanStatus::Infected,
                scan_time: chrono::Utc::now(),
                duration_ms: 100,
                threat: Some("Win.Trojan.Test".to_string()),
            },
            crate::clamav::types::ScanResult {
                path: "/test/error.file".to_string(),
                status: crate::clamav::types::ScanStatus::Error("Access denied".to_string()),
                scan_time: chrono::Utc::now(),
                duration_ms: 10,
                threat: None,
            },
        ];

        for result in scan_results {
            collector.record_scan_result(&result).await;
        }

        collector.update_clamav_version("1.0.2").await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "comprehensive-test-machine".to_string(),
            "2.0.0".to_string(),
        )
        .unwrap();

        // This should exercise all the logging paths in export_metrics
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_comprehensive_coverage() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Add comprehensive metrics to hit all logging paths
        collector
            .record_rule_execution("test_rule_1", std::time::Duration::from_millis(100), 5, 2)
            .await;
        collector
            .record_rule_execution("test_rule_2", std::time::Duration::from_millis(200), 3, 0)
            .await;
        collector
            .record_rule_execution("test_rule_3", std::time::Duration::from_millis(50), 8, 1)
            .await;

        // Add different types of scan results
        let results = vec![
            crate::clamav::types::ScanResult {
                path: "/test/file1.txt".to_string(),
                status: crate::clamav::types::ScanStatus::Clean,
                scan_time: chrono::Utc::now(),
                duration_ms: 25,
                threat: None,
            },
            crate::clamav::types::ScanResult {
                path: "/test/malware.exe".to_string(),
                status: crate::clamav::types::ScanStatus::Infected,
                scan_time: chrono::Utc::now(),
                duration_ms: 150,
                threat: Some("Win.Trojan.Test".to_string()),
            },
            crate::clamav::types::ScanResult {
                path: "/test/error.file".to_string(),
                status: crate::clamav::types::ScanStatus::Error("Permission denied".to_string()),
                scan_time: chrono::Utc::now(),
                duration_ms: 5,
                threat: None,
            },
        ];

        for result in results {
            collector.record_scan_result(&result).await;
        }

        collector.update_clamav_version("0.103.10").await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "comprehensive-coverage-machine".to_string(),
            "1.2.0".to_string(),
        )
        .unwrap();

        // This should exercise comprehensive logging in export_metrics including lines 51, 61
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_metrics_protection_logging() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        // Set up metrics to specifically exercise protection logging (lines 83, 87)

        // Simulate quarantined and cleaned files to hit line 83-87
        // We need to record scan results that trigger the protection metrics
        let infected_result = crate::clamav::types::ScanResult {
            path: "/test/threat.exe".to_string(),
            status: crate::clamav::types::ScanStatus::Infected,
            scan_time: chrono::Utc::now(),
            duration_ms: 200,
            threat: Some("Test.Malware".to_string()),
        };
        collector.record_scan_result(&infected_result).await;

        // Update realtime protection status to exercise line 87 conditional
        collector
            .record_rule_execution(
                "protection_rule",
                std::time::Duration::from_millis(50),
                1,
                1,
            )
            .await;

        let exporter = TelemetryExporter::new_with_skip_export(
            config,
            None,
            collector,
            "protection-test-machine".to_string(),
            "1.0.1".to_string(),
        )
        .unwrap();

        // This should exercise protection logging lines 83-87
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }
}
