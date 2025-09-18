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
            } else if path.is_file()
                && self.should_scan_file(&path, rule)? {
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
