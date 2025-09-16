use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ClamAV error: {0}")]
    ClamAV(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] toml::de::Error),

    #[error("OpenTelemetry error: {0}")]
    Telemetry(String),

    #[error("Scheduler error: {0}")]
    Scheduler(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, Error>;