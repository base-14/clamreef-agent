use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
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
            ClamAVConnection::Unix { path } => self.send_unix_command(path, command).await,
            ClamAVConnection::Tcp { host, port } => {
                self.send_tcp_command(host, *port, command).await
            }
        }
    }

    async fn send_unix_command(&self, path: &str, command: &str) -> Result<String> {
        let mut stream = timeout(self.timeout, UnixStream::connect(path))
            .await
            .map_err(|_| Error::Timeout(format!("Connection to {} timed out", path)))?
            .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", path, e)))?;

        debug!("Sending command to ClamAV: {}", command);

        let cmd = format!("z{}\0", command);
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(Error::Io)?;

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
        stream
            .write_all(cmd.as_bytes())
            .await
            .map_err(Error::Io)?;

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
}
