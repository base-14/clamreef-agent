use chrono::{DateTime, Utc};
use cron::Schedule;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::clamav::{ClamAVClient, ScanResult, ScanStatus};
use crate::config::ScanRule;
use crate::error::{Error, Result};
use crate::metrics::MetricsCollector;

pub struct Scheduler {
    rules: Vec<ScanRule>,
    clamav_client: Arc<dyn ClamAVClient>,
    metrics: Arc<MetricsCollector>,
    active_scans: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
    max_concurrent_scans: usize,
}

impl Scheduler {
    pub fn new(
        rules: Vec<ScanRule>,
        clamav_client: Arc<dyn ClamAVClient>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            rules,
            clamav_client,
            metrics,
            active_scans: Arc::new(Mutex::new(HashMap::new())),
            max_concurrent_scans: 3,
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Starting scheduler with {} rules", self.rules.len());

        let mut handles = Vec::new();

        for rule in &self.rules {
            let schedule = Schedule::from_str(&rule.schedule)
                .map_err(|e| Error::Scheduler(format!("Invalid cron expression: {}", e)))?;

            let rule = rule.clone();
            let scheduler = Arc::clone(&self);

            let handle = tokio::spawn(async move {
                scheduler.run_rule_schedule(rule, schedule).await;
            });

            handles.push(handle);
        }

        // Wait for all schedulers
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    async fn run_rule_schedule(self: Arc<Self>, rule: ScanRule, schedule: Schedule) {
        let mut interval = interval(Duration::from_secs(60)); // Check every minute

        loop {
            interval.tick().await;

            let now = Utc::now();
            let next = schedule.upcoming(Utc).next();

            if let Some(next_time) = next {
                if next_time.timestamp() - now.timestamp() < 60 {
                    info!("Executing scheduled scan for rule: {}", rule.name);

                    let scheduler = Arc::clone(&self);
                    let rule_clone = rule.clone();

                    tokio::spawn(async move {
                        if let Err(e) = scheduler.execute_rule(&rule_clone).await {
                            error!("Failed to execute rule '{}': {}", rule_clone.name, e);
                        }
                    });
                }
            }
        }
    }

    pub async fn execute_rule(&self, rule: &ScanRule) -> Result<()> {
        // Check if rule is already running
        {
            let active = self.active_scans.lock().await;
            if active.contains_key(&rule.name) {
                warn!("Rule '{}' is already running, skipping", rule.name);
                return Ok(());
            }
        }

        // Wait if too many concurrent scans
        while self.active_scans.lock().await.len() >= self.max_concurrent_scans {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        // Mark as active
        {
            let mut active = self.active_scans.lock().await;
            active.insert(rule.name.clone(), Utc::now());
        }

        let mut total_scanned = 0;
        let mut threats_found = 0;
        let start_time = std::time::Instant::now();

        for path in &rule.paths {
            let expanded = shellexpand::tilde(path);
            let path = Path::new(expanded.as_ref());

            if !path.exists() {
                warn!("Path does not exist: {:?}", path);
                continue;
            }

            match self.scan_path(path, rule).await {
                Ok(results) => {
                    for result in results {
                        total_scanned += 1;
                        if let ScanStatus::Infected = result.status {
                            threats_found += 1;
                            warn!(
                                "Threat found: {} in {}",
                                result.threat.as_ref().unwrap_or(&"Unknown".to_string()),
                                result.path
                            );
                        }

                        // Record metrics
                        self.metrics.record_scan_result(&result).await;
                    }
                }
                Err(e) => {
                    error!("Failed to scan path {:?}: {}", path, e);
                }
            }
        }

        let duration = start_time.elapsed();
        info!(
            "Rule '{}' completed: {} files scanned, {} threats found in {:?}",
            rule.name, total_scanned, threats_found, duration
        );

        // Record rule execution metrics
        self.metrics
            .record_rule_execution(&rule.name, duration, total_scanned, threats_found)
            .await;

        // Remove from active scans
        {
            let mut active = self.active_scans.lock().await;
            active.remove(&rule.name);
        }

        Ok(())
    }

    async fn scan_path(&self, path: &Path, rule: &ScanRule) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();

        if path.is_file() {
            if self.should_scan_file(path, rule)? {
                let result = self.clamav_client.scan(path).await?;
                results.push(result);
            }
        } else if path.is_dir() && rule.recursive {
            results.extend(self.scan_directory(path, rule).await?);
        }

        Ok(results)
    }

    async fn scan_directory(&self, dir: &Path, rule: &ScanRule) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Check symlinks
            if entry.file_type().await?.is_symlink() && !rule.follow_symlinks {
                continue;
            }

            // Check exclusions
            if self.is_excluded(&path, rule) {
                continue;
            }

            if path.is_dir() && rule.recursive {
                results.extend(Box::pin(self.scan_directory(&path, rule)).await?);
            } else if path.is_file() && self.should_scan_file(&path, rule)? {
                match self.clamav_client.scan(&path).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to scan file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(results)
    }

    fn should_scan_file(&self, path: &Path, rule: &ScanRule) -> Result<bool> {
        // Check file size
        if let Some(max_size_str) = &rule.max_file_size {
            let metadata = std::fs::metadata(path)?;
            let max_size = parse_size(max_size_str)?;
            if metadata.len() > max_size {
                debug!("Skipping file {:?}: exceeds max size", path);
                return Ok(false);
            }
        }

        // Check exclusion patterns
        if self.is_excluded(path, rule) {
            return Ok(false);
        }

        Ok(true)
    }

    fn is_excluded(&self, path: &Path, rule: &ScanRule) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &rule.exclude_patterns {
            if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                if glob_pattern.matches(&path_str) {
                    debug!("Path {:?} excluded by pattern: {}", path, pattern);
                    return true;
                }
            }
        }

        false
    }
}

fn parse_size(size: &str) -> Result<u64> {
    let size = size.to_uppercase();
    let (num_str, unit) = if size.ends_with("GB") {
        (&size[..size.len() - 2], 1_073_741_824)
    } else if size.ends_with("MB") {
        (&size[..size.len() - 2], 1_048_576)
    } else if size.ends_with("KB") {
        (&size[..size.len() - 2], 1_024)
    } else if size.ends_with("B") {
        (&size[..size.len() - 1], 1)
    } else {
        return Err(Error::Config(format!("Invalid size format: {}", size)));
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| Error::Config(format!("Invalid number in size: {}", size)))?;

    Ok(num * unit)
}

// Temporary shellexpand module (same as in config)
mod shellexpand {
    use std::borrow::Cow;

    pub fn tilde(s: &str) -> Cow<'_, str> {
        if s.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return Cow::Owned(s.replacen("~", &home, 1));
            }
        }
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clamav::types::{ScanResult, ScanStatus};
    use crate::config::ScanRule;
    use async_trait::async_trait;
    use mockall::mock;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::fs;

    mock! {
        pub ClamAVClient {}

        #[async_trait]
        impl ClamAVClient for ClamAVClient {
            async fn ping(&self) -> Result<bool>;
            async fn version(&self) -> Result<crate::clamav::types::Version>;
            async fn stats(&self) -> Result<crate::clamav::types::Stats>;
            async fn scan(&self, path: &Path) -> Result<ScanResult>;
            async fn reload(&self) -> Result<()>;
        }
    }

    fn create_test_rule() -> ScanRule {
        ScanRule {
            name: "test_rule".to_string(),
            paths: vec!["/tmp/test".to_string()],
            schedule: "0 0 */6 * * *".to_string(),
            exclude_patterns: vec!["*.tmp".to_string()],
            follow_symlinks: false,
            recursive: true,
            max_file_size: Some("10MB".to_string()),
        }
    }

    fn create_test_metrics() -> Arc<MetricsCollector> {
        Arc::new(MetricsCollector::new())
    }

    fn create_clean_scan_result(path: &str) -> ScanResult {
        ScanResult {
            path: path.to_string(),
            status: ScanStatus::Clean,
            scan_time: chrono::Utc::now(),
            duration_ms: 50,
            threat: None,
        }
    }

    fn create_infected_scan_result(path: &str) -> ScanResult {
        ScanResult {
            path: path.to_string(),
            status: ScanStatus::Infected,
            scan_time: chrono::Utc::now(),
            duration_ms: 100,
            threat: Some("TestVirus".to_string()),
        }
    }

    #[tokio::test]
    async fn test_scheduler_new() {
        let rules = vec![create_test_rule()];
        let mut mock_client = MockClamAVClient::new();
        mock_client.expect_ping().times(0);
        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();

        let scheduler = Scheduler::new(rules, client, metrics);

        assert_eq!(scheduler.rules.len(), 1);
        assert_eq!(scheduler.rules[0].name, "test_rule");
        assert_eq!(scheduler.max_concurrent_scans, 3);
    }

    #[tokio::test]
    async fn test_execute_rule_file_scan() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").await.unwrap();

        let mut rule = create_test_rule();
        rule.paths = vec![test_file.to_string_lossy().to_string()];
        rule.recursive = false;

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(1)
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let result = scheduler.execute_rule(&rule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_rule_directory_scan() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).await.unwrap();

        let file1 = temp_dir.path().join("file1.txt");
        let file2 = subdir.join("file2.txt");
        fs::write(&file1, "content1").await.unwrap();
        fs::write(&file2, "content2").await.unwrap();

        let mut rule = create_test_rule();
        rule.paths = vec![temp_dir.path().to_string_lossy().to_string()];

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(2)
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let result = scheduler.execute_rule(&rule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_rule_with_threats() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("infected.txt");
        fs::write(&test_file, "malicious content").await.unwrap();

        let mut rule = create_test_rule();
        rule.paths = vec![test_file.to_string_lossy().to_string()];
        rule.recursive = false;

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(1)
            .returning(|path| Ok(create_infected_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let result = scheduler.execute_rule(&rule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_rule_concurrent_limit() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").await.unwrap();

        let mut rule = create_test_rule();
        rule.paths = vec![test_file.to_string_lossy().to_string()];
        rule.recursive = false;

        let mut mock_client = MockClamAVClient::new();
        // No scan expectation since rule should be skipped
        mock_client.expect_scan().times(0);

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Arc::new(Scheduler::new(vec![rule.clone()], client, metrics));

        // Mark rule as already running
        {
            let mut active = scheduler.active_scans.lock().await;
            active.insert(rule.name.clone(), Utc::now());
        }

        // This should skip execution
        let result = scheduler.execute_rule(&rule).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_scan_file_max_size() {
        let temp_dir = TempDir::new().unwrap();
        let small_file = temp_dir.path().join("small.txt");
        let large_file = temp_dir.path().join("large.txt");

        fs::write(&small_file, "small").await.unwrap();
        fs::write(&large_file, "x".repeat(50 * 1024 * 1024))
            .await
            .unwrap(); // 50MB

        let mut rule = create_test_rule();
        rule.max_file_size = Some("10MB".to_string());

        let mock_client = MockClamAVClient::new();
        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let small_result = scheduler.should_scan_file(&small_file, &rule);
        let large_result = scheduler.should_scan_file(&large_file, &rule);

        assert!(small_result.unwrap());
        assert!(!large_result.unwrap());
    }

    #[tokio::test]
    async fn test_is_excluded() {
        let rule = create_test_rule(); // Has "*.tmp" exclusion pattern

        let mock_client = MockClamAVClient::new();
        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let tmp_file = PathBuf::from("/test/file.tmp");
        let txt_file = PathBuf::from("/test/file.txt");

        assert!(scheduler.is_excluded(&tmp_file, &rule));
        assert!(!scheduler.is_excluded(&txt_file, &rule));
    }

    #[tokio::test]
    async fn test_scan_path_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "test content").await.unwrap();

        let mut rule = create_test_rule();
        rule.recursive = false;

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(1)
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let results = scheduler.scan_path(&test_file, &rule).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Clean);
    }

    #[tokio::test]
    async fn test_scan_path_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        fs::write(&file1, "content1").await.unwrap();
        fs::write(&file2, "content2").await.unwrap();

        let rule = create_test_rule();

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(2)
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let results = scheduler.scan_path(temp_dir.path(), &rule).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_scan_directory_with_exclusions() {
        let temp_dir = TempDir::new().unwrap();
        let good_file = temp_dir.path().join("good.txt");
        let tmp_file = temp_dir.path().join("excluded.tmp");
        fs::write(&good_file, "good content").await.unwrap();
        fs::write(&tmp_file, "temp content").await.unwrap();

        let rule = create_test_rule(); // Has "*.tmp" exclusion

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(1) // Only good.txt should be scanned
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let results = scheduler
            .scan_directory(temp_dir.path(), &rule)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].path.ends_with("good.txt"));
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024B").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1_048_576);
        assert_eq!(parse_size("1GB").unwrap(), 1_073_741_824);
        assert_eq!(parse_size("10mb").unwrap(), 10_485_760);

        assert!(parse_size("invalid").is_err());
        assert!(parse_size("1XB").is_err());
    }

    #[test]
    fn test_shellexpand_tilde() {
        let original_home = std::env::var("HOME");

        std::env::set_var("HOME", "/home/test");

        let expanded = shellexpand::tilde("~/Documents");
        assert_eq!(expanded, "/home/test/Documents");

        let no_tilde = shellexpand::tilde("/absolute/path");
        assert_eq!(no_tilde, "/absolute/path");

        // Restore original HOME environment variable
        match original_home {
            Ok(home) => std::env::set_var("HOME", home),
            Err(_) => std::env::remove_var("HOME"),
        }
    }

    #[tokio::test]
    async fn test_execute_rule_nonexistent_path() {
        let mut rule = create_test_rule();
        rule.paths = vec!["/nonexistent/path".to_string()];

        let mock_client = MockClamAVClient::new();
        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let result = scheduler.execute_rule(&rule).await;
        // Should not fail even with nonexistent path
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_directory_with_symlinks() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        fs::write(&file1, "content1").await.unwrap();

        // Create subdirectory (not symlink, but test that we recursively scan directories)
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).await.unwrap();
        let target_file = subdir.join("target.txt");
        fs::write(&target_file, "target content").await.unwrap();

        let mut rule = create_test_rule();
        rule.follow_symlinks = false;

        let mut mock_client = MockClamAVClient::new();
        mock_client
            .expect_scan()
            .times(2) // Both files should be scanned (recursive=true)
            .returning(|path| Ok(create_clean_scan_result(&path.to_string_lossy())));

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();
        let scheduler = Scheduler::new(vec![rule.clone()], client, metrics);

        let results = scheduler
            .scan_directory(temp_dir.path(), &rule)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_scheduler_start_with_invalid_cron() {
        let mut rule = create_test_rule();
        rule.schedule = "invalid cron".to_string(); // Invalid schedule

        let mock_client = MockClamAVClient::new();
        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();

        let scheduler = Arc::new(Scheduler::new(vec![rule], client, metrics));

        // This should return an error due to invalid cron expression
        let result = scheduler.start().await;
        assert!(result.is_err());

        // Check that it's specifically a scheduler error about cron
        match result.unwrap_err() {
            crate::error::Error::Scheduler(msg) => {
                assert!(msg.contains("Invalid cron expression"));
            }
            _ => panic!("Expected scheduler error"),
        }
    }

    #[tokio::test]
    async fn test_scheduler_task_spawn_and_handle_collection() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Create a rule with a very frequent schedule for testing
        let rule = ScanRule {
            name: "test_spawn_rule".to_string(),
            paths: vec!["/tmp".to_string()],
            schedule: "0 0 */1 * * *".to_string(), // Every hour
            exclude_patterns: vec![],
            max_file_size: None,
            recursive: true,
            follow_symlinks: false,
        };

        let mut mock_client = MockClamAVClient::new();
        mock_client.expect_scan().returning(|_| {
            Ok(crate::clamav::types::ScanResult {
                path: "/tmp/test".to_string(),
                status: crate::clamav::types::ScanStatus::Clean,
                scan_time: chrono::Utc::now(),
                duration_ms: 10,
                threat: None,
            })
        });

        let client = Arc::new(mock_client);
        let metrics = create_test_metrics();

        let scheduler = Arc::new(Scheduler::new(vec![rule], client, metrics));

        // Start the scheduler and timeout quickly to avoid infinite loop
        // This should exercise lines 51-63 (task spawning and handle collection)
        let start_task = scheduler.start();
        let result = timeout(Duration::from_millis(100), start_task).await;

        // Should timeout since scheduler runs indefinitely
        assert!(result.is_err());
    }
}
