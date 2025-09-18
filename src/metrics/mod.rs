use serde_json;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{System, Users};
use tokio::sync::RwLock;

use crate::clamav::{ScanResult, ScanStatus, Stats};

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub clamreef_scans_total: u64,
    pub clamreef_threats_detected_total: u64,
    pub clamreef_files_scanned_total: u64,
    pub clamreef_scan_errors_total: u64,
    pub clamreef_rule_executions_total: u64,
    pub clamreef_agent_uptime_seconds: u64,
    pub clamreef_clamav_database_version: u32,
    pub clamreef_clamav_engine_version: String,
    // Scan performance metrics
    pub clamreef_last_scan_duration_ms: u64,
    pub clamreef_avg_scan_duration_ms: u64,
    pub clamreef_max_scan_duration_ms: u64,
    // Endpoint protection metrics
    pub clamreef_quarantined_files_total: u64,
    pub clamreef_cleaned_files_total: u64,
    pub clamreef_last_threat_timestamp: Option<u64>,
    pub clamreef_database_age_hours: u64,
    pub clamreef_realtime_protection_enabled: bool,
    pub clamreef_last_full_scan_timestamp: Option<u64>,
    pub clamreef_pending_scans: u64,
}

#[derive(Debug, Clone)]
pub struct HostMetrics {
    pub clamreef_hostname: String,
    pub clamreef_os_name: String,
    pub clamreef_os_version: String,
    pub clamreef_kernel_version: String,
    pub clamreef_users: Vec<String>,
    pub clamreef_serial_number: Option<String>,
    pub clamreef_agent_version: String,
}

impl HostMetrics {
    pub fn collect() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
        let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
        let kernel_version = System::kernel_version().unwrap_or_else(|| "Unknown".to_string());

        // System users to filter out
        const SYSTEM_USERS: &[&str] = &[
            "root",
            "_mbsetupuser",
            "daemon",
            "nobody",
            "_spotlight",
            "_locationd",
            "_windowserver",
        ];

        let users_manager = Users::new_with_refreshed_list();
        let users: Vec<String> = users_manager
            .iter()
            .filter(|user| {
                let username = user.name();
                !SYSTEM_USERS.contains(&username) && !username.starts_with('_')
            })
            .map(|user| user.name().to_string())
            .collect();

        let serial_number = get_serial_number();
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        Self {
            clamreef_hostname: hostname,
            clamreef_os_name: os_name,
            clamreef_os_version: os_version,
            clamreef_kernel_version: kernel_version,
            clamreef_users: users,
            clamreef_serial_number: serial_number,
            clamreef_agent_version: agent_version,
        }
    }
}

#[cfg(target_os = "macos")]
fn get_serial_number() -> Option<String> {
    use std::process::Command;

    let output = Command::new("system_profiler")
        .args(["SPHardwareDataType", "-json"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            return json["SPHardwareDataType"][0]["serial_number"]
                .as_str()
                .map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_serial_number() -> Option<String> {
    use std::fs;

    fs::read_to_string("/sys/class/dmi/id/product_serial")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "None")
}

#[cfg(target_os = "windows")]
fn get_serial_number() -> Option<String> {
    use std::process::Command;

    let output = Command::new("wmic")
        .args(&["bios", "get", "serialnumber", "/value"])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(serial) = line.strip_prefix("SerialNumber=") {
                let serial = serial.trim();
                if !serial.is_empty() {
                    return Some(serial.to_string());
                }
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn get_serial_number() -> Option<String> {
    None
}

pub struct MetricsCollector {
    metrics: Arc<RwLock<Metrics>>,
    host_metrics: Arc<RwLock<HostMetrics>>,
    start_time: std::time::Instant,
    scan_durations: Arc<RwLock<Vec<u64>>>, // Store last N scan durations for averaging
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Metrics::default())),
            host_metrics: Arc::new(RwLock::new(HostMetrics::collect())),
            start_time: std::time::Instant::now(),
            scan_durations: Arc::new(RwLock::new(Vec::with_capacity(100))),
        }
    }

    pub async fn record_scan_result(&self, result: &ScanResult) {
        let mut metrics = self.metrics.write().await;
        metrics.clamreef_files_scanned_total += 1;

        match &result.status {
            ScanStatus::Clean => {
                metrics.clamreef_scans_total += 1;
            }
            ScanStatus::Infected => {
                metrics.clamreef_scans_total += 1;
                metrics.clamreef_threats_detected_total += 1;
            }
            ScanStatus::Error(_) => {
                metrics.clamreef_scan_errors_total += 1;
            }
        }
    }

    pub async fn record_rule_execution(
        &self,
        _rule_name: &str,
        duration: Duration,
        files_scanned: u64,
        threats_found: u64,
    ) {
        let duration_ms = duration.as_millis() as u64;

        let mut metrics = self.metrics.write().await;
        metrics.clamreef_rule_executions_total += 1;
        metrics.clamreef_files_scanned_total += files_scanned;
        metrics.clamreef_threats_detected_total += threats_found;
        metrics.clamreef_last_scan_duration_ms = duration_ms;

        // Update max duration
        if duration_ms > metrics.clamreef_max_scan_duration_ms {
            metrics.clamreef_max_scan_duration_ms = duration_ms;
        }

        // If threats were found, update timestamp
        if threats_found > 0 {
            metrics.clamreef_last_threat_timestamp = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
        }

        drop(metrics); // Release lock before next await

        // Update running average
        let mut durations = self.scan_durations.write().await;
        durations.push(duration_ms);
        if durations.len() > 100 {
            durations.remove(0);
        }
        let avg = durations.iter().sum::<u64>() / durations.len() as u64;
        drop(durations);

        let mut metrics = self.metrics.write().await;
        metrics.clamreef_avg_scan_duration_ms = avg;
    }

    pub async fn update_clamav_stats(&self, stats: &Stats) {
        let mut metrics = self.metrics.write().await;
        metrics.clamreef_clamav_database_version = stats.database.version;
    }

    pub async fn update_clamav_version(&self, version: &str) {
        let mut metrics = self.metrics.write().await;
        metrics.clamreef_clamav_engine_version = version.to_string();
    }

    pub async fn get_metrics(&self) -> Metrics {
        let mut metrics = self.metrics.read().await.clone();
        metrics.clamreef_agent_uptime_seconds = self.start_time.elapsed().as_secs();
        metrics
    }

    pub async fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub async fn get_host_metrics(&self) -> HostMetrics {
        self.host_metrics.read().await.clone()
    }

    pub async fn refresh_host_metrics(&self) {
        let new_metrics = HostMetrics::collect();
        *self.host_metrics.write().await = new_metrics;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clamav::types::{DatabaseInfo, MemoryStats, QueueStats, ThreadStats};
    use crate::clamav::{ScanResult, ScanStatus, Stats};
    use chrono::Utc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_default() {
        let metrics = Metrics::default();
        assert_eq!(metrics.clamreef_scans_total, 0);
        assert_eq!(metrics.clamreef_threats_detected_total, 0);
        assert_eq!(metrics.clamreef_files_scanned_total, 0);
        assert_eq!(metrics.clamreef_scan_errors_total, 0);
        assert_eq!(metrics.clamreef_rule_executions_total, 0);
        assert_eq!(metrics.clamreef_agent_uptime_seconds, 0);
        assert_eq!(metrics.clamreef_clamav_database_version, 0);
        assert_eq!(metrics.clamreef_clamav_engine_version, String::new());
        assert_eq!(metrics.clamreef_last_scan_duration_ms, 0);
        assert_eq!(metrics.clamreef_avg_scan_duration_ms, 0);
        assert_eq!(metrics.clamreef_max_scan_duration_ms, 0);
        assert_eq!(metrics.clamreef_quarantined_files_total, 0);
        assert_eq!(metrics.clamreef_cleaned_files_total, 0);
        assert_eq!(metrics.clamreef_last_threat_timestamp, None);
        assert_eq!(metrics.clamreef_database_age_hours, 0);
        assert!(!metrics.clamreef_realtime_protection_enabled);
        assert_eq!(metrics.clamreef_last_full_scan_timestamp, None);
        assert_eq!(metrics.clamreef_pending_scans, 0);
    }

    #[tokio::test]
    async fn test_metrics_collector_new() {
        let collector = MetricsCollector::new();
        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_scans_total, 0);
        assert!(collector.get_uptime().await.as_secs() < 1);
    }

    #[tokio::test]
    async fn test_record_scan_result_clean() {
        let collector = MetricsCollector::new();

        let scan_result = ScanResult {
            path: "/test/file.txt".to_string(),
            status: ScanStatus::Clean,
            scan_time: Utc::now(),
            duration_ms: 100,
            threat: None,
        };

        collector.record_scan_result(&scan_result).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_scans_total, 1);
        assert_eq!(metrics.clamreef_threats_detected_total, 0);
        assert_eq!(metrics.clamreef_files_scanned_total, 1);
        assert_eq!(metrics.clamreef_scan_errors_total, 0);
    }

    #[tokio::test]
    async fn test_record_scan_result_infected() {
        let collector = MetricsCollector::new();

        let scan_result = ScanResult {
            path: "/test/virus.exe".to_string(),
            status: ScanStatus::Infected,
            scan_time: Utc::now(),
            duration_ms: 200,
            threat: Some("Win.Trojan.Test".to_string()),
        };

        collector.record_scan_result(&scan_result).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_scans_total, 1);
        assert_eq!(metrics.clamreef_threats_detected_total, 1);
        assert_eq!(metrics.clamreef_files_scanned_total, 1);
        assert_eq!(metrics.clamreef_scan_errors_total, 0);
    }

    #[tokio::test]
    async fn test_record_scan_result_error() {
        let collector = MetricsCollector::new();

        let scan_result = ScanResult {
            path: "/test/notfound.txt".to_string(),
            status: ScanStatus::Error("File not found".to_string()),
            scan_time: Utc::now(),
            duration_ms: 50,
            threat: None,
        };

        collector.record_scan_result(&scan_result).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_scans_total, 0);
        assert_eq!(metrics.clamreef_threats_detected_total, 0);
        assert_eq!(metrics.clamreef_files_scanned_total, 1);
        assert_eq!(metrics.clamreef_scan_errors_total, 1);
    }

    #[tokio::test]
    async fn test_record_rule_execution() {
        let collector = MetricsCollector::new();

        collector
            .record_rule_execution("test_rule", Duration::from_millis(500), 10, 2)
            .await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_rule_executions_total, 1);
        assert_eq!(metrics.clamreef_files_scanned_total, 10);
        assert_eq!(metrics.clamreef_threats_detected_total, 2);
        assert_eq!(metrics.clamreef_last_scan_duration_ms, 500);
        assert_eq!(metrics.clamreef_avg_scan_duration_ms, 500);
        assert_eq!(metrics.clamreef_max_scan_duration_ms, 500);
        assert!(metrics.clamreef_last_threat_timestamp.is_some());
    }

    #[tokio::test]
    async fn test_scan_duration_tracking() {
        let collector = MetricsCollector::new();

        // Record multiple scans with different durations
        collector
            .record_rule_execution("rule1", Duration::from_millis(100), 5, 0)
            .await;
        collector
            .record_rule_execution("rule2", Duration::from_millis(200), 3, 0)
            .await;
        collector
            .record_rule_execution("rule3", Duration::from_millis(300), 2, 0)
            .await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_last_scan_duration_ms, 300);
        assert_eq!(metrics.clamreef_avg_scan_duration_ms, 200); // (100+200+300)/3
        assert_eq!(metrics.clamreef_max_scan_duration_ms, 300);
        assert_eq!(metrics.clamreef_rule_executions_total, 3);
    }

    #[tokio::test]
    async fn test_update_clamav_stats() {
        let collector = MetricsCollector::new();

        let stats = Stats {
            pools: 1,
            state: "READY".to_string(),
            threads: ThreadStats {
                live: 1,
                idle: 0,
                max: 10,
            },
            queue: QueueStats { items: 0, max: 100 },
            mem_stats: MemoryStats {
                heap: 1.5,
                mmap: 0.0,
                used: 1.5,
            },
            database: DatabaseInfo {
                version: 27763,
                sigs: 8654321,
                build_time: "Mon Mar 13 08:20:48 2023".to_string(),
                md5: "abcd1234".to_string(),
            },
        };

        collector.update_clamav_stats(&stats).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_clamav_database_version, 27763);
    }

    #[tokio::test]
    async fn test_update_clamav_version() {
        let collector = MetricsCollector::new();

        collector.update_clamav_version("1.4.3").await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.clamreef_clamav_engine_version, "1.4.3");
    }

    #[test]
    fn test_host_metrics_collect() {
        let host_metrics = HostMetrics::collect();

        // Check that basic fields are populated
        assert!(!host_metrics.clamreef_hostname.is_empty());
        assert!(!host_metrics.clamreef_os_name.is_empty());
        assert!(!host_metrics.clamreef_os_version.is_empty());
        assert!(!host_metrics.clamreef_kernel_version.is_empty());
        assert!(!host_metrics.clamreef_agent_version.is_empty());

        // Check that system users are filtered out
        assert!(!host_metrics.clamreef_users.contains(&"root".to_string()));
        assert!(!host_metrics
            .clamreef_users
            .contains(&"_mbsetupuser".to_string()));
        assert!(!host_metrics
            .clamreef_users
            .iter()
            .any(|u| u.starts_with('_')));
    }

    #[tokio::test]
    async fn test_get_host_metrics() {
        let collector = MetricsCollector::new();
        let host_metrics = collector.get_host_metrics().await;

        assert!(!host_metrics.clamreef_hostname.is_empty());
        assert!(!host_metrics.clamreef_agent_version.is_empty());
    }

    #[tokio::test]
    async fn test_refresh_host_metrics() {
        let collector = MetricsCollector::new();

        // Get initial metrics
        let initial = collector.get_host_metrics().await;

        // Refresh metrics
        collector.refresh_host_metrics().await;

        // Get updated metrics
        let refreshed = collector.get_host_metrics().await;

        // Should be the same for static host info
        assert_eq!(initial.clamreef_hostname, refreshed.clamreef_hostname);
        assert_eq!(initial.clamreef_os_name, refreshed.clamreef_os_name);
    }

    #[tokio::test]
    async fn test_uptime_tracking() {
        let collector = MetricsCollector::new();

        // Wait a small amount of time
        tokio::time::sleep(Duration::from_millis(10)).await;

        let uptime = collector.get_uptime().await;
        assert!(uptime.as_millis() >= 10);

        let metrics = collector.get_metrics().await;
        // Just check that uptime is a valid number
        let _ = metrics.clamreef_agent_uptime_seconds;
    }
}
