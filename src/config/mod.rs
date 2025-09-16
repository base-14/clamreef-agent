use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub telemetry: TelemetryConfig,
    pub clamav: ClamAVConfig,
    pub rules: Vec<ScanRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub version: String,
    pub machine_name: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    pub endpoint: String,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClamAVConfig {
    pub socket_path: Option<String>,
    pub tcp_host: Option<String>,
    pub tcp_port: Option<u16>,
    #[serde(default = "default_scan_timeout")]
    pub scan_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanRule {
    pub name: String,
    pub paths: Vec<String>,
    pub schedule: String,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    pub max_file_size: Option<String>,
    #[serde(default = "default_recursive")]
    pub recursive: bool,
    #[serde(default)]
    pub follow_symlinks: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_interval() -> u64 {
    60
}

fn default_timeout() -> u64 {
    10
}

fn default_scan_timeout() -> u64 {
    300
}

fn default_recursive() -> bool {
    true
}

impl Config {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .await
            .map_err(|e| Error::Config(format!("Failed to read config file: {}", e)))?;

        let config: Config = toml::from_str(&contents)
            .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        Ok(config)
    }

    pub async fn load_from_default_locations() -> Result<Self> {
        let locations = vec![
            PathBuf::from("/etc/clamreef/agent.toml"),
            dirs::config_dir()
                .map(|d| d.join("clamreef/agent.toml"))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|d| d.join(".clamreef/agent.toml"))
                .unwrap_or_default(),
            PathBuf::from("./agent.toml"),
        ];

        for path in locations {
            if path.exists() {
                tracing::info!("Loading config from: {:?}", path);
                return Self::load(path).await;
            }
        }

        Err(Error::Config(
            "No configuration file found in default locations".to_string(),
        ))
    }

    pub fn validate(&self) -> Result<()> {
        // Validate ClamAV connection
        if self.clamav.socket_path.is_none()
            && (self.clamav.tcp_host.is_none() || self.clamav.tcp_port.is_none()) {
            return Err(Error::Config(
                "Either socket_path or tcp_host/tcp_port must be configured".to_string(),
            ));
        }

        // Validate rules
        for rule in &self.rules {
            // Validate cron expression
            cron::Schedule::from_str(&rule.schedule)
                .map_err(|e| Error::Config(format!("Invalid cron expression '{}': {}", rule.schedule, e)))?;

            // Validate paths exist
            for path in &rule.paths {
                let expanded = shellexpand::tilde(path);
                let path = Path::new(expanded.as_ref());
                if !path.exists() {
                    tracing::warn!("Path in rule '{}' does not exist: {:?}", rule.name, path);
                }
            }

            // Validate max_file_size format
            if let Some(size) = &rule.max_file_size {
                parse_size(size)
                    .map_err(|_| Error::Config(format!("Invalid max_file_size '{}' in rule '{}'", size, rule.name)))?;
            }
        }

        Ok(())
    }

    pub fn get_machine_name(&self) -> String {
        self.agent
            .machine_name
            .clone()
            .unwrap_or_else(|| {
                hostname::get()
                    .ok()
                    .and_then(|s| s.into_string().ok())
                    .unwrap_or_else(|| "unknown".to_string())
            })
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

    let num: u64 = num_str.parse()
        .map_err(|_| Error::Config(format!("Invalid number in size: {}", size)))?;

    Ok(num * unit)
}

use std::str::FromStr;

// Temporary module while we add the dirs dependency
mod dirs {
    use std::path::PathBuf;

    pub fn config_dir() -> Option<PathBuf> {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".config")))
    }

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(PathBuf::from)
    }
}

// Temporary module for shellexpand
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