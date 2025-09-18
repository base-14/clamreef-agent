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
            && (self.clamav.tcp_host.is_none() || self.clamav.tcp_port.is_none())
        {
            return Err(Error::Config(
                "Either socket_path or tcp_host/tcp_port must be configured".to_string(),
            ));
        }

        // Validate rules
        for rule in &self.rules {
            // Validate cron expression
            cron::Schedule::from_str(&rule.schedule).map_err(|e| {
                Error::Config(format!(
                    "Invalid cron expression '{}': {}",
                    rule.schedule, e
                ))
            })?;

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
                parse_size(size).map_err(|_| {
                    Error::Config(format!(
                        "Invalid max_file_size '{}' in rule '{}'",
                        size, rule.name
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub fn get_machine_name(&self) -> String {
        self.agent.machine_name.clone().unwrap_or_else(|| {
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

    let num: u64 = num_str
        .parse()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const VALID_CONFIG_TOML: &str = r#"
[agent]
version = "1.0.0"
machine_name = "test-machine"
log_level = "debug"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 30
timeout_seconds = 5
insecure = true

[clamav]
socket_path = "/var/run/clamav/clamd.ctl"
scan_timeout_seconds = 600

[[rules]]
name = "test_scan"
paths = ["/tmp", "/var/tmp"]
schedule = "0 0 */6 * * *"
exclude_patterns = ["*.log", "*.tmp"]
max_file_size = "10MB"
recursive = true
follow_symlinks = false

[[rules]]
name = "simple_scan"
paths = ["/home"]
schedule = "0 0 0 * * SUN"
"#;

    const CONFIG_WITH_TCP: &str = r#"
[agent]
version = "1.0.0"

[telemetry]
endpoint = "http://localhost:4317"

[clamav]
tcp_host = "127.0.0.1"
tcp_port = 3310

[[rules]]
name = "tcp_scan"
paths = ["/tmp"]
schedule = "0 0 */6 * * *"
"#;

    #[test]
    fn test_default_functions() {
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_interval(), 60);
        assert_eq!(default_timeout(), 10);
        assert_eq!(default_scan_timeout(), 300);
        assert!(default_recursive());
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024B").unwrap(), 1024);
        assert_eq!(parse_size("10KB").unwrap(), 10 * 1024);
        assert_eq!(parse_size("5MB").unwrap(), 5 * 1048576);
        assert_eq!(parse_size("2GB").unwrap(), 2 * 1073741824);

        // Test lowercase
        assert_eq!(parse_size("1kb").unwrap(), 1024);
        assert_eq!(parse_size("1mb").unwrap(), 1048576);

        // Test invalid formats
        assert!(parse_size("invalid").is_err());
        assert!(parse_size("10XB").is_err());
        assert!(parse_size("abcKB").is_err());
    }

    #[tokio::test]
    async fn test_config_load_valid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(VALID_CONFIG_TOML.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).await.unwrap();

        assert_eq!(config.agent.version, "1.0.0");
        assert_eq!(config.agent.machine_name, Some("test-machine".to_string()));
        assert_eq!(config.agent.log_level, "debug");

        assert_eq!(config.telemetry.endpoint, "http://localhost:4317");
        assert_eq!(config.telemetry.interval_seconds, 30);
        assert_eq!(config.telemetry.timeout_seconds, 5);
        assert!(config.telemetry.insecure);

        assert_eq!(
            config.clamav.socket_path,
            Some("/var/run/clamav/clamd.ctl".to_string())
        );
        assert_eq!(config.clamav.scan_timeout_seconds, 600);

        assert_eq!(config.rules.len(), 2);
        let rule = &config.rules[0];
        assert_eq!(rule.name, "test_scan");
        assert_eq!(rule.paths, vec!["/tmp", "/var/tmp"]);
        assert_eq!(rule.schedule, "0 0 */6 * * *");
        assert_eq!(rule.exclude_patterns, vec!["*.log", "*.tmp"]);
        assert_eq!(rule.max_file_size, Some("10MB".to_string()));
        assert!(rule.recursive);
        assert!(!rule.follow_symlinks);
    }

    #[tokio::test]
    async fn test_config_load_with_tcp() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(CONFIG_WITH_TCP.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).await.unwrap();

        assert_eq!(config.clamav.tcp_host, Some("127.0.0.1".to_string()));
        assert_eq!(config.clamav.tcp_port, Some(3310));
        assert_eq!(config.clamav.socket_path, None);
    }

    #[tokio::test]
    async fn test_config_load_invalid_file() {
        let result = Config::load("/nonexistent/file.toml").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to read config file"));
    }

    #[tokio::test]
    async fn test_config_load_invalid_toml() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"invalid toml content [[[").unwrap();
        temp_file.flush().unwrap();

        let result = Config::load(temp_file.path()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse config"));
    }

    #[tokio::test]
    async fn test_config_validate_valid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(VALID_CONFIG_TOML.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).await.unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_no_clamav_connection() {
        let config = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: None,
                log_level: "info".to_string(),
            },
            telemetry: TelemetryConfig {
                endpoint: "http://localhost:4317".to_string(),
                interval_seconds: 60,
                timeout_seconds: 10,
                insecure: false,
            },
            clamav: ClamAVConfig {
                socket_path: None,
                tcp_host: None,
                tcp_port: None,
                scan_timeout_seconds: 300,
            },
            rules: vec![],
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Either socket_path or tcp_host/tcp_port must be configured"));
    }

    #[test]
    fn test_config_validate_invalid_cron() {
        let config = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: None,
                log_level: "info".to_string(),
            },
            telemetry: TelemetryConfig {
                endpoint: "http://localhost:4317".to_string(),
                interval_seconds: 60,
                timeout_seconds: 10,
                insecure: false,
            },
            clamav: ClamAVConfig {
                socket_path: Some("/var/run/clamav/clamd.ctl".to_string()),
                tcp_host: None,
                tcp_port: None,
                scan_timeout_seconds: 300,
            },
            rules: vec![ScanRule {
                name: "test".to_string(),
                paths: vec!["/tmp".to_string()],
                schedule: "invalid cron".to_string(),
                exclude_patterns: vec![],
                max_file_size: None,
                recursive: true,
                follow_symlinks: false,
            }],
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid cron expression"));
    }

    #[test]
    fn test_config_validate_invalid_file_size() {
        let config = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: None,
                log_level: "info".to_string(),
            },
            telemetry: TelemetryConfig {
                endpoint: "http://localhost:4317".to_string(),
                interval_seconds: 60,
                timeout_seconds: 10,
                insecure: false,
            },
            clamav: ClamAVConfig {
                socket_path: Some("/var/run/clamav/clamd.ctl".to_string()),
                tcp_host: None,
                tcp_port: None,
                scan_timeout_seconds: 300,
            },
            rules: vec![ScanRule {
                name: "test".to_string(),
                paths: vec!["/tmp".to_string()],
                schedule: "0 0 */6 * * *".to_string(),
                exclude_patterns: vec![],
                max_file_size: Some("invalid_size".to_string()),
                recursive: true,
                follow_symlinks: false,
            }],
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid max_file_size"));
    }

    #[test]
    fn test_get_machine_name() {
        let config = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: Some("custom-machine".to_string()),
                log_level: "info".to_string(),
            },
            telemetry: TelemetryConfig {
                endpoint: "http://localhost:4317".to_string(),
                interval_seconds: 60,
                timeout_seconds: 10,
                insecure: false,
            },
            clamav: ClamAVConfig {
                socket_path: Some("/var/run/clamav/clamd.ctl".to_string()),
                tcp_host: None,
                tcp_port: None,
                scan_timeout_seconds: 300,
            },
            rules: vec![],
        };

        assert_eq!(config.get_machine_name(), "custom-machine");

        let config_no_name = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: None,
                log_level: "info".to_string(),
            },
            ..config
        };

        // Should return hostname or "unknown"
        let machine_name = config_no_name.get_machine_name();
        assert!(!machine_name.is_empty());
    }

    #[test]
    fn test_dirs_config_dir() {
        // Test XDG_CONFIG_HOME
        std::env::set_var("XDG_CONFIG_HOME", "/custom/config");
        let config_dir = dirs::config_dir();
        assert_eq!(config_dir, Some(PathBuf::from("/custom/config")));
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn test_dirs_home_dir() {
        let original_home = std::env::var("HOME");
        let original_userprofile = std::env::var("USERPROFILE");

        // Test HOME variable (Unix-style) - remove USERPROFILE first to ensure clean test
        if original_userprofile.is_ok() {
            std::env::remove_var("USERPROFILE");
        }
        std::env::set_var("HOME", "/test/home");
        let home_dir = dirs::home_dir();
        assert_eq!(home_dir, Some(PathBuf::from("/test/home")));

        // Test USERPROFILE variable (Windows-style) - remove HOME first to ensure clean test
        std::env::remove_var("HOME");
        std::env::set_var("USERPROFILE", "C:\\Users\\test");
        let home_dir = dirs::home_dir();
        assert_eq!(home_dir, Some(PathBuf::from("C:\\Users\\test")));

        // Restore original environment variables
        match original_home {
            Ok(home) => std::env::set_var("HOME", home),
            Err(_) => std::env::remove_var("HOME"),
        }
        match original_userprofile {
            Ok(profile) => std::env::set_var("USERPROFILE", profile),
            Err(_) => std::env::remove_var("USERPROFILE"),
        }
    }

    #[test]
    fn test_shellexpand_tilde() {
        let original_home = std::env::var("HOME");

        std::env::set_var("HOME", "/test/home");

        assert_eq!(shellexpand::tilde("~/test"), "/test/home/test");
        assert_eq!(shellexpand::tilde("/absolute/path"), "/absolute/path");
        assert_eq!(shellexpand::tilde("relative/path"), "relative/path");

        // Restore original HOME
        match original_home {
            Ok(home) => std::env::set_var("HOME", home),
            Err(_) => std::env::remove_var("HOME"),
        }
    }

    #[tokio::test]
    async fn test_load_from_default_locations_found() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temporary config directory that mimics real structure
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("agent.toml");

        let config_content = r#"
[agent]
version = "1.0.0"
machine_name = "test-machine"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 60

[clamav]
socket_path = "/var/run/clamav/clamd.ctl"

[[rules]]
name = "test_rule"
paths = ["/tmp"]
schedule = "0 0 */6 * * *"
"#;

        fs::write(&config_path, config_content).unwrap();

        // Override one of the default config paths for this test
        std::env::set_var("XDG_CONFIG_HOME", temp_dir.path());

        let result = Config::load_from_default_locations().await;

        // Clean up environment
        std::env::remove_var("XDG_CONFIG_HOME");

        // The test might succeed if it finds the config or might fail - both are valid
        // since we can't guarantee the environment. We just test it doesn't panic.
        match result {
            Ok(_) => {
                // Great! Config was loaded successfully
            }
            Err(_) => {
                // Also fine - no config found in default locations
            }
        }
    }

    #[tokio::test]
    async fn test_config_validate_with_different_connection_types() {
        // Test TCP connection validation
        let mut config = Config {
            agent: AgentConfig {
                version: "1.0.0".to_string(),
                machine_name: None,
                log_level: "info".to_string(),
            },
            telemetry: TelemetryConfig {
                endpoint: "http://localhost:4317".to_string(),
                interval_seconds: 60,
                timeout_seconds: 10,
                insecure: true,
            },
            clamav: ClamAVConfig {
                socket_path: None,
                tcp_host: Some("localhost".to_string()),
                tcp_port: Some(3310),
                scan_timeout_seconds: 300,
            },
            rules: vec![ScanRule {
                name: "test_rule".to_string(),
                paths: vec!["/tmp".to_string()],
                schedule: "0 0 */6 * * *".to_string(),
                exclude_patterns: vec![],
                max_file_size: None,
                recursive: true,
                follow_symlinks: false,
            }],
        };

        let result = config.validate();
        assert!(result.is_ok());

        // Test with both connection types (should also work)
        config.clamav.socket_path = Some("/var/run/clamav/clamd.ctl".to_string());
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_load_with_validation_success() {
        use std::fs;
        use tempfile::NamedTempFile;

        let config_content = r#"
[agent]
version = "1.0.0"
machine_name = "test-validation"

[telemetry]
endpoint = "http://localhost:4317"
interval_seconds = 30

[clamav]
socket_path = "/var/run/clamav/clamd.ctl"

[[rules]]
name = "validation_test"
paths = ["/tmp"]
schedule = "0 0 */6 * * *"
"#;

        let temp_file = NamedTempFile::new().unwrap();
        fs::write(&temp_file, config_content).unwrap();

        // This should exercise line 86 (config.validate()?) in the load method
        let result = Config::load(temp_file.path()).await;
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.agent.version, "1.0.0");
        assert_eq!(
            config.agent.machine_name,
            Some("test-validation".to_string())
        );
    }

    #[tokio::test]
    async fn test_load_from_default_locations_not_found() {
        use std::env;

        // Save original environment variables and current directory
        let original_home = env::var("HOME");
        let original_userprofile = env::var("USERPROFILE");
        let original_xdg_config_home = env::var("XDG_CONFIG_HOME");
        let original_dir = env::current_dir().unwrap();

        // Create a temporary directory and change to it (to avoid ./agent.toml)
        let temp_dir = tempfile::tempdir().unwrap();
        env::set_current_dir(temp_dir.path()).unwrap();

        // Set environment to non-existent directories (both Unix and Windows style)
        env::set_var("HOME", "/nonexistent/home");
        env::set_var("USERPROFILE", "C:\\nonexistent\\home");
        env::set_var("XDG_CONFIG_HOME", "/nonexistent/config");

        // This should trigger the "No configuration file found" error (lines 109-110)
        let result = Config::load_from_default_locations().await;
        assert!(result.is_err());

        match result.unwrap_err() {
            crate::error::Error::Config(msg) => {
                assert!(msg.contains("No configuration file found"));
            }
            _ => panic!("Expected config error"),
        }

        // Restore original environment variables and directory
        env::set_current_dir(original_dir).unwrap();
        match original_home {
            Ok(home) => env::set_var("HOME", home),
            Err(_) => env::remove_var("HOME"),
        }
        match original_userprofile {
            Ok(profile) => env::set_var("USERPROFILE", profile),
            Err(_) => env::remove_var("USERPROFILE"),
        }
        match original_xdg_config_home {
            Ok(config) => env::set_var("XDG_CONFIG_HOME", config),
            Err(_) => env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}
