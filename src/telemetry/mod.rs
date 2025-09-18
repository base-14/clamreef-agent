use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

use crate::config::TelemetryConfig;
use crate::error::Result;
use crate::metrics::MetricsCollector;

// Simplified telemetry exporter for now
// TODO: Implement full OpenTelemetry integration once we get the basic version working
pub struct TelemetryExporter {
    config: TelemetryConfig,
    metrics_collector: Arc<MetricsCollector>,
}

impl TelemetryExporter {
    pub fn new(
        config: TelemetryConfig,
        metrics_collector: Arc<MetricsCollector>,
        _machine_name: String,
        _agent_version: String,
    ) -> Result<Self> {
        Ok(Self {
            config,
            metrics_collector,
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
        let metrics = self.metrics_collector.get_metrics().await;
        let host_metrics = self.metrics_collector.get_host_metrics().await;

        // For now, just log the metrics
        // TODO: Implement OTLP export

        // Core scanning metrics
        info!(
            "ClamReef Scanning - Total: {}, Threats: {}, Errors: {}, Files: {}, Pending: {}",
            metrics.clamreef_scans_total,
            metrics.clamreef_threats_detected_total,
            metrics.clamreef_scan_errors_total,
            metrics.clamreef_files_scanned_total,
            metrics.clamreef_pending_scans
        );

        // Performance metrics
        info!(
            "ClamReef Performance - Last Scan: {}ms, Avg: {}ms, Max: {}ms",
            metrics.clamreef_last_scan_duration_ms,
            metrics.clamreef_avg_scan_duration_ms,
            metrics.clamreef_max_scan_duration_ms
        );

        // Threat response metrics
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

        // Host information
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

        // User and agent info
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

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("Telemetry exporter shutdown");
        Ok(())
    }
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
        collector.record_rule_execution("test_rule", Duration::from_secs(10), 5, 0).await;
        collector.update_clamav_version("0.103.8").await;

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

        // Test export_metrics - this should not fail even though it just logs
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

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

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

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

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

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown() {
        let config = create_test_config();
        let collector = create_test_metrics_collector();

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

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
        };
        let collector = create_test_metrics_collector();

        let exporter = Arc::new(TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap());

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
        };

        assert_eq!(config.endpoint, "https://otlp.example.com:4317");
        assert_eq!(config.interval_seconds, 30);
        assert_eq!(config.timeout_seconds, 15);
        assert_eq!(config.insecure, false);
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
        collector.record_rule_execution("test_rule", std::time::Duration::from_secs(5), 2, 1).await;

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "test-machine".to_string(),
            "1.0.0".to_string(),
        ).unwrap();

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

        let exporter = TelemetryExporter::new(
            config,
            collector,
            "comprehensive-test-machine".to_string(),
            "2.0.0".to_string(),
        ).unwrap();

        // This should exercise all the logging paths in export_metrics
        let result = exporter.export_metrics().await;
        assert!(result.is_ok());
    }
}
