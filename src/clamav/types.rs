use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub status: ScanStatus,
    pub scan_time: DateTime<Utc>,
    pub duration_ms: u64,
    pub threat: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Clean,
    Infected,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub pools: u32,
    pub state: String,
    pub threads: ThreadStats,
    pub queue: QueueStats,
    pub mem_stats: MemoryStats,
    pub database: DatabaseInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadStats {
    pub live: u32,
    pub idle: u32,
    pub max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub items: u32,
    pub max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub heap: f64,
    pub mmap: f64,
    pub used: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub version: u32,
    pub sigs: u32,
    pub build_time: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub clamav: String,
    pub database: u32,
    pub database_date: String,
}