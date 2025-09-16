use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::clamav::{ScanResult, ScanStatus, Stats};

#[derive(Debug, Clone)]
pub struct Metrics {
    pub scans_total: u64,
    pub threats_detected_total: u64,
    pub files_scanned_total: u64,
    pub scan_errors_total: u64,
    pub rule_executions_total: u64,
    pub agent_uptime_seconds: u64,
    pub clamav_database_version: u32,
    pub clamav_engine_version: String,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            scans_total: 0,
            threats_detected_total: 0,
            files_scanned_total: 0,
            scan_errors_total: 0,
            rule_executions_total: 0,
            agent_uptime_seconds: 0,
            clamav_database_version: 0,
            clamav_engine_version: String::new(),
        }
    }
}

pub struct MetricsCollector {
    metrics: Arc<RwLock<Metrics>>,
    start_time: std::time::Instant,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Metrics::default())),
            start_time: std::time::Instant::now(),
        }
    }

    pub async fn record_scan_result(&self, result: &ScanResult) {
        let mut metrics = self.metrics.write().await;
        metrics.files_scanned_total += 1;

        match &result.status {
            ScanStatus::Clean => {
                metrics.scans_total += 1;
            }
            ScanStatus::Infected => {
                metrics.scans_total += 1;
                metrics.threats_detected_total += 1;
            }
            ScanStatus::Error(_) => {
                metrics.scan_errors_total += 1;
            }
        }
    }

    pub async fn record_rule_execution(
        &self,
        _rule_name: &str,
        _duration: Duration,
        files_scanned: u64,
        threats_found: u64,
    ) {
        let mut metrics = self.metrics.write().await;
        metrics.rule_executions_total += 1;
        metrics.files_scanned_total += files_scanned;
        metrics.threats_detected_total += threats_found;
    }

    pub async fn update_clamav_stats(&self, stats: &Stats) {
        let mut metrics = self.metrics.write().await;
        metrics.clamav_database_version = stats.database.version;
    }

    pub async fn update_clamav_version(&self, version: &str) {
        let mut metrics = self.metrics.write().await;
        metrics.clamav_engine_version = version.to_string();
    }

    pub async fn get_metrics(&self) -> Metrics {
        let mut metrics = self.metrics.read().await.clone();
        metrics.agent_uptime_seconds = self.start_time.elapsed().as_secs();
        metrics
    }

    pub async fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}