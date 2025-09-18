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
