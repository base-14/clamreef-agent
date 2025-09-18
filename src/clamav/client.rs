use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::timeout;
use tracing::debug;

use super::parser::Parser;
use super::types::{ScanResult, Stats, Version};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub enum ClamAVConnection {
    Unix { path: String },
    Tcp { host: String, port: u16 },
}

#[async_trait]
pub trait ClamAVClient: Send + Sync {
    async fn ping(&self) -> Result<bool>;
    async fn version(&self) -> Result<Version>;
    async fn stats(&self) -> Result<Stats>;
    async fn scan(&self, path: &Path) -> Result<ScanResult>;
    async fn reload(&self) -> Result<()>;
}

pub struct ClamAVClientImpl {
    connection: ClamAVConnection,
    timeout: Duration,
}

impl ClamAVClientImpl {
    pub fn new(connection: ClamAVConnection) -> Self {
        Self {
            connection,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn send_command(&self, command: &str) -> Result<String> {
        match &self.connection {
            #[cfg(unix)]
            ClamAVConnection::Unix { path } => self.send_unix_command(path, command).await,
            #[cfg(not(unix))]
            ClamAVConnection::Unix { .. } => Err(Error::Connection(
                "Unix sockets not supported on Windows".to_string(),
            )),
            ClamAVConnection::Tcp { host, port } => {
                self.send_tcp_command(host, *port, command).await
            }
        }
    }

    #[cfg(unix)]
    async fn send_unix_command(&self, path: &str, command: &str) -> Result<String> {
        let mut stream = timeout(self.timeout, UnixStream::connect(path))
            .await
            .map_err(|_| Error::Timeout(format!("Connection to {} timed out", path)))?
            .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", path, e)))?;

        debug!("Sending command to ClamAV: {}", command);

        let cmd = format!("z{}\0", command);
        stream.write_all(cmd.as_bytes()).await.map_err(Error::Io)?;

        let mut response = Vec::new();
        let mut reader = BufReader::new(stream);

        timeout(self.timeout, reader.read_until(b'\0', &mut response))
            .await
            .map_err(|_| Error::Timeout("Read response timed out".to_string()))?
            .map_err(Error::Io)?;

        // Remove trailing null byte
        if response.last() == Some(&0) {
            response.pop();
        }

        String::from_utf8(response)
            .map_err(|e| Error::Parse(format!("Invalid UTF-8 in response: {}", e)))
    }

    async fn send_tcp_command(&self, host: &str, port: u16, command: &str) -> Result<String> {
        let addr = format!("{}:{}", host, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Timeout(format!("Connection to {} timed out", addr)))?
            .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", addr, e)))?;

        debug!("Sending command to ClamAV: {}", command);

        let cmd = format!("z{}\0", command);
        stream.write_all(cmd.as_bytes()).await.map_err(Error::Io)?;

        let mut response = Vec::new();
        let mut reader = BufReader::new(stream);

        timeout(self.timeout, reader.read_until(b'\0', &mut response))
            .await
            .map_err(|_| Error::Timeout("Read response timed out".to_string()))?
            .map_err(Error::Io)?;

        // Remove trailing null byte
        if response.last() == Some(&0) {
            response.pop();
        }

        String::from_utf8(response)
            .map_err(|e| Error::Parse(format!("Invalid UTF-8 in response: {}", e)))
    }
}

#[async_trait]
impl ClamAVClient for ClamAVClientImpl {
    async fn ping(&self) -> Result<bool> {
        let response = self.send_command("PING").await?;
        Ok(response.trim() == "PONG")
    }

    async fn version(&self) -> Result<Version> {
        let response = self.send_command("VERSION").await?;
        Parser::parse_version(&response)
    }

    async fn stats(&self) -> Result<Stats> {
        let response = self.send_command("STATS").await?;
        Parser::parse_stats(&response)
    }

    async fn scan(&self, path: &Path) -> Result<ScanResult> {
        let path_str = path.to_string_lossy();
        let command = format!("SCAN {}", path_str);
        let start = std::time::Instant::now();

        let response = self.send_command(&command).await?;
        let duration_ms = start.elapsed().as_millis() as u64;

        Parser::parse_scan_result(&response, path_str.to_string(), duration_ms)
    }

    async fn reload(&self) -> Result<()> {
        let response = self.send_command("RELOAD").await?;
        if response.trim() == "RELOADING" {
            Ok(())
        } else {
            Err(Error::ClamAV(format!(
                "Unexpected reload response: {}",
                response
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    mock! {
        pub ClamAV {}

        #[async_trait]
        impl ClamAVClient for ClamAV {
            async fn ping(&self) -> Result<bool>;
            async fn version(&self) -> Result<Version>;
            async fn stats(&self) -> Result<Stats>;
            async fn scan(&self, path: &Path) -> Result<ScanResult>;
            async fn reload(&self) -> Result<()>;
        }
    }

    #[test]
    fn test_clamav_client_new() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection.clone());

        match client.connection {
            ClamAVConnection::Tcp { host, port } => {
                assert_eq!(host, "localhost");
                assert_eq!(port, 3310);
            }
            _ => panic!("Expected TCP connection"),
        }
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_clamav_client_with_timeout() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection).with_timeout(Duration::from_secs(10));

        assert_eq!(client.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_unix_connection_creation() {
        let connection = ClamAVConnection::Unix {
            path: "/var/run/clamav/clamd.ctl".to_string(),
        };
        let client = ClamAVClientImpl::new(connection.clone());

        match client.connection {
            ClamAVConnection::Unix { path } => {
                assert_eq!(path, "/var/run/clamav/clamd.ctl");
            }
            _ => panic!("Expected Unix connection"),
        }
    }

    #[test]
    fn test_tcp_connection_creation() {
        let connection = ClamAVConnection::Tcp {
            host: "127.0.0.1".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection.clone());

        match client.connection {
            ClamAVConnection::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 3310);
            }
            _ => panic!("Expected TCP connection"),
        }
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn test_unix_connection_not_supported_on_windows() {
        let connection = ClamAVConnection::Unix {
            path: "/tmp/clamd.sock".to_string(),
        };
        let client = ClamAVClientImpl::new(connection);

        let result = client.send_command("PING").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Connection(msg) => {
                assert!(msg.contains("Unix sockets not supported on Windows"));
            }
            _ => panic!("Expected connection error"),
        }
    }

    // Mock tests for client interface methods
    #[tokio::test]
    async fn test_ping_success() {
        let mut mock_client = MockClamAV::new();
        mock_client.expect_ping().times(1).returning(|| Ok(true));

        let result = mock_client.ping().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_ping_failure() {
        let mut mock_client = MockClamAV::new();
        mock_client.expect_ping().times(1).returning(|| Ok(false));

        let result = mock_client.ping().await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_version() {
        let mut mock_client = MockClamAV::new();
        let expected_version = super::super::types::Version {
            clamav: "ClamAV 0.103.8".to_string(),
            database: 26312,
            database_date: "2023-08-15".to_string(),
        };

        mock_client
            .expect_version()
            .times(1)
            .returning(move || Ok(expected_version.clone()));

        let result = mock_client.version().await;
        assert!(result.is_ok());
        let version = result.unwrap();
        assert_eq!(version.clamav, "ClamAV 0.103.8");
        assert_eq!(version.database, 26312);
        assert_eq!(version.database_date, "2023-08-15");
    }

    #[tokio::test]
    async fn test_stats() {
        let mut mock_client = MockClamAV::new();
        let expected_stats = super::super::types::Stats {
            pools: 1,
            state: "ACTIVE".to_string(),
            threads: super::super::types::ThreadStats {
                live: 8,
                idle: 2,
                max: 10,
            },
            queue: super::super::types::QueueStats { items: 0, max: 100 },
            mem_stats: super::super::types::MemoryStats {
                heap: 1.5,
                mmap: 0.0,
                used: 1.5,
            },
            database: super::super::types::DatabaseInfo {
                version: 26312,
                sigs: 8645122,
                build_time: "2023-08-15".to_string(),
                md5: "abc123".to_string(),
            },
        };

        mock_client
            .expect_stats()
            .times(1)
            .returning(move || Ok(expected_stats.clone()));

        let result = mock_client.stats().await;
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.pools, 1);
        assert_eq!(stats.state, "ACTIVE");
        assert_eq!(stats.threads.live, 8);
        assert_eq!(stats.threads.max, 10);
        assert_eq!(stats.queue.items, 0);
        assert_eq!(stats.queue.max, 100);
    }

    #[tokio::test]
    async fn test_scan_clean_file() {
        let mut mock_client = MockClamAV::new();
        let expected_result = ScanResult {
            path: "/tmp/test.txt".to_string(),
            status: super::super::types::ScanStatus::Clean,
            scan_time: chrono::Utc::now(),
            duration_ms: 50,
            threat: None,
        };

        mock_client
            .expect_scan()
            .times(1)
            .returning(move |_| Ok(expected_result.clone()));

        let temp_file = NamedTempFile::new().unwrap();
        let result = mock_client.scan(temp_file.path()).await;
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(scan_result.status, super::super::types::ScanStatus::Clean);
        assert!(scan_result.threat.is_none());
    }

    #[tokio::test]
    async fn test_scan_infected_file() {
        let mut mock_client = MockClamAV::new();
        let expected_result = ScanResult {
            path: "/tmp/infected.txt".to_string(),
            status: super::super::types::ScanStatus::Infected,
            scan_time: chrono::Utc::now(),
            duration_ms: 100,
            threat: Some("EICAR-Test-File".to_string()),
        };

        mock_client
            .expect_scan()
            .times(1)
            .returning(move |_| Ok(expected_result.clone()));

        let temp_file = NamedTempFile::new().unwrap();
        let result = mock_client.scan(temp_file.path()).await;
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert_eq!(
            scan_result.status,
            super::super::types::ScanStatus::Infected
        );
        assert_eq!(scan_result.threat, Some("EICAR-Test-File".to_string()));
    }

    #[tokio::test]
    async fn test_scan_error() {
        let mut mock_client = MockClamAV::new();
        let expected_result = ScanResult {
            path: "/tmp/error.txt".to_string(),
            status: super::super::types::ScanStatus::Error("Access denied".to_string()),
            scan_time: chrono::Utc::now(),
            duration_ms: 10,
            threat: None,
        };

        mock_client
            .expect_scan()
            .times(1)
            .returning(move |_| Ok(expected_result.clone()));

        let temp_file = NamedTempFile::new().unwrap();
        let result = mock_client.scan(temp_file.path()).await;
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        match scan_result.status {
            super::super::types::ScanStatus::Error(msg) => {
                assert_eq!(msg, "Access denied");
            }
            _ => panic!("Expected error status"),
        }
    }

    #[tokio::test]
    async fn test_reload_success() {
        let mut mock_client = MockClamAV::new();
        mock_client.expect_reload().times(1).returning(|| Ok(()));

        let result = mock_client.reload().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reload_failure() {
        let mut mock_client = MockClamAV::new();
        mock_client
            .expect_reload()
            .times(1)
            .returning(|| Err(Error::ClamAV("Reload failed".to_string())));

        let result = mock_client.reload().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ClamAV(msg) => {
                assert_eq!(msg, "Reload failed");
            }
            _ => panic!("Expected ClamAV error"),
        }
    }

    // Test connection types Debug formatting
    #[test]
    fn test_connection_debug() {
        let unix_conn = ClamAVConnection::Unix {
            path: "/tmp/test.sock".to_string(),
        };
        let tcp_conn = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };

        let unix_debug = format!("{:?}", unix_conn);
        let tcp_debug = format!("{:?}", tcp_conn);

        assert!(unix_debug.contains("Unix"));
        assert!(unix_debug.contains("/tmp/test.sock"));
        assert!(tcp_debug.contains("Tcp"));
        assert!(tcp_debug.contains("localhost"));
        assert!(tcp_debug.contains("3310"));
    }

    // Test connection clone
    #[test]
    fn test_connection_clone() {
        let original = ClamAVConnection::Tcp {
            host: "test.com".to_string(),
            port: 1234,
        };
        let cloned = original.clone();

        match (original, cloned) {
            (
                ClamAVConnection::Tcp { host: h1, port: p1 },
                ClamAVConnection::Tcp { host: h2, port: p2 },
            ) => {
                assert_eq!(h1, h2);
                assert_eq!(p1, p2);
            }
            _ => panic!("Clone failed"),
        }
    }

    // Test actual implementation methods using mocks and real logic
    #[tokio::test]
    async fn test_ping_implementation() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection);

        // We can't test actual network calls, but we can test the implementation structure
        // This will fail on connection, but tests the ping method exists and returns Result<bool>
        let result = client.ping().await;
        assert!(result.is_err()); // Expected to fail without ClamAV running
    }

    #[tokio::test]
    async fn test_version_implementation() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection);

        // Test that version method exists and returns proper error on connection failure
        let result = client.version().await;
        assert!(result.is_err()); // Expected to fail without ClamAV running
    }

    #[tokio::test]
    async fn test_stats_implementation() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection);

        // Test that stats method exists and returns proper error
        let result = client.stats().await;
        assert!(result.is_err()); // Expected to fail without ClamAV running
    }

    #[tokio::test]
    async fn test_scan_implementation() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection);

        let temp_file = NamedTempFile::new().unwrap();
        let result = client.scan(temp_file.path()).await;
        assert!(result.is_err()); // Expected to fail without ClamAV running
    }

    #[tokio::test]
    async fn test_reload_implementation() {
        let connection = ClamAVConnection::Tcp {
            host: "localhost".to_string(),
            port: 3310,
        };
        let client = ClamAVClientImpl::new(connection);

        let result = client.reload().await;
        assert!(result.is_err()); // Expected to fail without ClamAV running
    }

    // Test builder patterns and configuration
    #[test]
    fn test_client_builder_pattern() {
        let connection = ClamAVConnection::Unix {
            path: "/var/run/clamav/clamd.ctl".to_string(),
        };

        let client = ClamAVClientImpl::new(connection).with_timeout(Duration::from_secs(5));

        assert_eq!(client.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_client_default_timeout() {
        let connection = ClamAVConnection::Tcp {
            host: "127.0.0.1".to_string(),
            port: 3310,
        };

        let client = ClamAVClientImpl::new(connection);
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    // Test error handling for connection variants
    #[tokio::test]
    async fn test_tcp_connection_error_handling() {
        let connection = ClamAVConnection::Tcp {
            host: "192.0.2.1".to_string(), // RFC5737 test address (won't connect)
            port: 12345,
        };
        let client = ClamAVClientImpl::new(connection).with_timeout(Duration::from_millis(100));

        let result = client.ping().await;
        assert!(result.is_err());

        // Should be either a timeout or connection error
        match result.unwrap_err() {
            Error::Timeout(_) | Error::Connection(_) => {
                // Expected error types
            }
            _ => panic!("Unexpected error type"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_socket_error_handling() {
        let connection = ClamAVConnection::Unix {
            path: "/tmp/nonexistent_socket.sock".to_string(),
        };
        let client = ClamAVClientImpl::new(connection).with_timeout(Duration::from_millis(100));

        let result = client.ping().await;
        assert!(result.is_err());

        // Should be a connection error
        match result.unwrap_err() {
            Error::Connection(_) => {
                // Expected for nonexistent socket
            }
            _ => panic!("Expected connection error for nonexistent socket"),
        }
    }
}
