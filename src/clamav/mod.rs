pub mod client;
pub mod parser;
pub mod types;

pub use client::{ClamAVClient, ClamAVClientImpl, ClamAVConnection};
pub use types::{ScanResult, ScanStatus, Stats, Version};
