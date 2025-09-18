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
    fn test_parse_version_invalid_format() {
        let response = "Invalid format";
        let result = Parser::parse_version(response);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Parse(msg) => assert!(msg.contains("Invalid version response")),
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn test_parse_version_invalid_database_number() {
        let response = "ClamAV 0.103.8/invalid/Mon Mar 13 08:20:48 2023";
        let result = Parser::parse_version(response);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Parse(msg) => assert!(msg.contains("Invalid database version")),
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn test_parse_version_fewer_parts() {
        let response = "ClamAV 0.103.8/26827";
        let result = Parser::parse_version(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scan_clean() {
        let response = "/path/to/file: OK";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 100).unwrap();
        assert_eq!(result.status, ScanStatus::Clean);
        assert_eq!(result.threat, None);
        assert_eq!(result.path, "/path/to/file");
        assert_eq!(result.duration_ms, 100);
    }

    #[test]
    fn test_parse_scan_infected() {
        let response = "/path/to/file: Win.Trojan.Generic FOUND";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 100).unwrap();
        assert_eq!(result.status, ScanStatus::Infected);
        assert_eq!(result.threat, Some("Win.Trojan.Generic".to_string()));
    }

    #[test]
    fn test_parse_scan_infected_no_colon() {
        let response = "Win.Trojan.Generic FOUND";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 50).unwrap();
        assert_eq!(result.status, ScanStatus::Infected);
        assert_eq!(result.threat, Some("Unknown threat".to_string()));
    }

    #[test]
    fn test_parse_scan_error() {
        let response = "ERROR: Access denied";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 10).unwrap();
        match result.status {
            ScanStatus::Error(msg) => assert_eq!(msg, "Access denied"),
            _ => panic!("Expected error status"),
        }
        assert_eq!(result.threat, None);
    }

    #[test]
    fn test_parse_scan_unexpected_response() {
        let response = "Some unexpected response";
        let result = Parser::parse_scan_result(response, "/path/to/file".to_string(), 5).unwrap();
        match result.status {
            ScanStatus::Error(msg) => assert!(msg.contains("Unexpected response")),
            _ => panic!("Expected error status"),
        }
    }

    #[test]
    fn test_parse_stats_complete() {
        let response = r#"STATS
POOLS: 1
STATE: ACTIVE
THREADS: live 2 idle 8 max 10
QUEUE: 0 items, max 100
MEMSTATS: heap 1.5M mmap 0.0M used 1.5M
DBVERSION: 26827
DBSIGS: 8645122
DBBUILDTIME: Mon Mar 13 08:20:48 2023
DBMD5: abc123def456
END"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 1);
        assert_eq!(stats.state, "ACTIVE"); // State remains as set, END line doesn't affect it
        assert_eq!(stats.threads.live, 2);
        assert_eq!(stats.threads.idle, 8);
        assert_eq!(stats.threads.max, 10);
        assert_eq!(stats.queue.items, 0);
        assert_eq!(stats.queue.max, 100);
        assert_eq!(stats.mem_stats.heap, 1.5);
        assert_eq!(stats.mem_stats.mmap, 0.0);
        assert_eq!(stats.mem_stats.used, 1.5);
        assert_eq!(stats.database.version, 26827);
        assert_eq!(stats.database.sigs, 8645122);
        assert_eq!(stats.database.build_time, "Mon Mar 13 08:20:48 2023");
        assert_eq!(stats.database.md5, "abc123def456");
    }

    #[test]
    fn test_parse_stats_minimal() {
        let response = r#"STATS
POOLS: 2
STATE: IDLE
END"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 2);
        assert_eq!(stats.state, "IDLE");
        // Check defaults for unspecified fields
        assert_eq!(stats.threads.live, 0);
        assert_eq!(stats.threads.idle, 0);
        assert_eq!(stats.threads.max, 0);
        assert_eq!(stats.queue.items, 0);
        assert_eq!(stats.queue.max, 0);
        assert_eq!(stats.mem_stats.heap, 0.0);
        assert_eq!(stats.database.version, 0);
        assert_eq!(stats.database.sigs, 0);
    }

    #[test]
    fn test_parse_stats_invalid_numbers() {
        let response = r#"STATS
POOLS: invalid
STATE: ACTIVE
THREADS: live invalid idle 2 max 5
QUEUE: invalid items, max invalid
MEMSTATS: heap invalid mmap invalid used invalid
DBVERSION: invalid
DBSIGS: invalid
END"#;

        let stats = Parser::parse_stats(response).unwrap();
        // Should gracefully handle invalid numbers with defaults
        assert_eq!(stats.pools, 0);
        assert_eq!(stats.state, "ACTIVE");
        assert_eq!(stats.threads.live, 0);
        assert_eq!(stats.threads.idle, 0); // Regex doesn't match when live is invalid
        assert_eq!(stats.threads.max, 0);
        assert_eq!(stats.queue.items, 0);
        assert_eq!(stats.queue.max, 0);
        assert_eq!(stats.mem_stats.heap, 0.0);
        assert_eq!(stats.database.version, 0);
        assert_eq!(stats.database.sigs, 0);
    }

    #[test]
    fn test_parse_stats_malformed_lines() {
        let response = r#"STATS
POOLS 1
no_colon_line
: empty_key
key_only:
POOLS: 3
STATE: RUNNING
END"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 3); // Last valid POOLS line wins
        assert_eq!(stats.state, "RUNNING");
    }

    #[test]
    fn test_parse_stats_empty_response() {
        let response = "";
        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 0);
        assert_eq!(stats.state, "");
        assert_eq!(stats.threads.live, 0);
        assert_eq!(stats.queue.items, 0);
    }

    #[test]
    fn test_parse_stats_state_variations() {
        let response1 = "STATE: SCANNING\nEND";
        let stats1 = Parser::parse_stats(response1).unwrap();
        assert_eq!(stats1.state, "SCANNING"); // State remains as set

        let response2 = "STATE: ACTIVE";
        let stats2 = Parser::parse_stats(response2).unwrap();
        assert_eq!(stats2.state, "ACTIVE"); // No END, keeps original state
    }

    #[test]
    fn test_parse_stats_whitespace_handling() {
        let response = r#"
STATS
  POOLS  :  2
  STATE:ACTIVE
  THREADS  : live 1 idle 0 max 5

END
"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 2);
        assert_eq!(stats.state, "ACTIVE");
        assert_eq!(stats.threads.live, 1);
        assert_eq!(stats.threads.idle, 0);
        assert_eq!(stats.threads.max, 5);
    }

    #[test]
    fn test_parse_stats_unknown_fields() {
        let response = r#"STATS
POOLS: 1
UNKNOWN_FIELD: some_value
RANDOM: 123
STATE: ACTIVE
END"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 1);
        assert_eq!(stats.state, "ACTIVE");
        // Unknown fields should be ignored gracefully
    }

    #[test]
    fn test_parse_stats_end_state_conversion() {
        // Test the specific case where STATE field is set to "END"
        let response = r#"STATS
POOLS: 1
STATE: END
"#;

        let stats = Parser::parse_stats(response).unwrap();
        assert_eq!(stats.pools, 1);
        assert_eq!(stats.state, "READY"); // "END" state gets converted to "READY"
    }
}
