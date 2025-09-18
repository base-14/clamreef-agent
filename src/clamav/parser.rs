use chrono::Utc;
use regex::Regex;

use super::types::{
    DatabaseInfo, MemoryStats, QueueStats, ScanResult, ScanStatus, Stats, ThreadStats, Version,
};
use crate::error::{Error, Result};

pub struct Parser;

impl Parser {
    pub fn parse_version(response: &str) -> Result<Version> {
        // Example: ClamAV 0.103.8/26827/Mon Mar 13 08:20:48 2023
        let parts: Vec<&str> = response.trim().split('/').collect();
        if parts.len() < 3 {
            return Err(Error::Parse(format!(
                "Invalid version response: {}",
                response
            )));
        }

        let clamav = parts[0].replace("ClamAV ", "");
        let database = parts[1]
            .parse::<u32>()
            .map_err(|_| Error::Parse(format!("Invalid database version: {}", parts[1])))?;
        let database_date = parts[2].to_string();

        Ok(Version {
            clamav,
            database,
            database_date,
        })
    }

    pub fn parse_stats(response: &str) -> Result<Stats> {
        let mut pools = 0;
        let mut state = String::new();
        let mut threads = ThreadStats {
            live: 0,
            idle: 0,
            max: 0,
        };
        let mut queue = QueueStats { items: 0, max: 0 };
        let mut mem_stats = MemoryStats {
            heap: 0.0,
            mmap: 0.0,
            used: 0.0,
        };
        let mut database = DatabaseInfo {
            version: 0,
            sigs: 0,
            build_time: String::new(),
            md5: String::new(),
        };

        // Pre-compile regexes outside the loop
        let threads_re = Regex::new(r"live (\d+) idle (\d+) max (\d+)").unwrap();
        let queue_re = Regex::new(r"(\d+) items.*max (\d+)").unwrap();
        let memstats_re = Regex::new(r"heap ([\d.]+)M mmap ([\d.]+)M used ([\d.]+)M").unwrap();

        for line in response.lines() {
            let line = line.trim();
            if line.is_empty() || line == "STATS" {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "POOLS" => pools = value.parse().unwrap_or(0),
                "STATE" => state = value.to_string(),
                "THREADS" => {
                    // Format: live 1 idle 0 max 10
                    if let Some(caps) = threads_re.captures(value) {
                        threads.live = caps[1].parse().unwrap_or(0);
                        threads.idle = caps[2].parse().unwrap_or(0);
                        threads.max = caps[3].parse().unwrap_or(0);
                    }
                }
                "QUEUE" => {
                    // Format: 0 items, max 100
                    if let Some(caps) = queue_re.captures(value) {
                        queue.items = caps[1].parse().unwrap_or(0);
                        queue.max = caps[2].parse().unwrap_or(0);
                    }
                }
                "MEMSTATS" => {
                    // Format: heap 1.234M mmap 0.000M used 1.234M
                    if let Some(caps) = memstats_re.captures(value) {
                        mem_stats.heap = caps[1].parse().unwrap_or(0.0);
                        mem_stats.mmap = caps[2].parse().unwrap_or(0.0);
                        mem_stats.used = caps[3].parse().unwrap_or(0.0);
                    }
                }
                "DBVERSION" => database.version = value.parse().unwrap_or(0),
                "DBSIGS" => database.sigs = value.parse().unwrap_or(0),
                "DBBUILDTIME" => database.build_time = value.to_string(),
                "DBMD5" => database.md5 = value.to_string(),
                _ => {}
            }
        }

        if state == "END" {
            state = "READY".to_string();
        }

        Ok(Stats {
            pools,
            state,
            threads,
            queue,
            mem_stats,
            database,
        })
    }

    pub fn parse_scan_result(response: &str, path: String, duration_ms: u64) -> Result<ScanResult> {
        let response = response.trim();

        let (status, threat) = if response.ends_with("OK") {
            (ScanStatus::Clean, None)
        } else if response.contains("FOUND") {
            // Extract virus name
            let parts: Vec<&str> = response.split(':').collect();
            if parts.len() >= 2 {
                let threat_part = parts[1].trim().replace(" FOUND", "");
                (ScanStatus::Infected, Some(threat_part))
            } else {
                (ScanStatus::Infected, Some("Unknown threat".to_string()))
            }
        } else if response.contains("ERROR") {
            let error_msg = response.replace("ERROR: ", "");
            (ScanStatus::Error(error_msg.clone()), None)
        } else {
            (
                ScanStatus::Error(format!("Unexpected response: {}", response)),
                None,
            )
        };

        Ok(ScanResult {
            path,
            status,
            scan_time: Utc::now(),
            duration_ms,
            threat,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        let response = "ClamAV 0.103.8/26827/Mon Mar 13 08:20:48 2023";
        let version = Parser::parse_version(response).unwrap();
        assert_eq!(version.clamav, "0.103.8");
        assert_eq!(version.database, 26827);
        assert_eq!(version.database_date, "Mon Mar 13 08:20:48 2023");
    }

    #[test]
    fn test_parse_scan_clean() {
        let response = "/path/to/file: OK";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 100).unwrap();
        assert_eq!(result.status, ScanStatus::Clean);
        assert_eq!(result.threat, None);
    }

    #[test]
    fn test_parse_scan_infected() {
        let response = "/path/to/file: Win.Trojan.Generic FOUND";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 100).unwrap();
        assert_eq!(result.status, ScanStatus::Infected);
        assert_eq!(result.threat, Some("Win.Trojan.Generic".to_string()));
    }
}
