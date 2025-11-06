pub mod oauth2;

use crate::error::Result;
use async_trait::async_trait;

/// Trait for authentication providers that can fetch access tokens
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Fetch a new access token
    async fn get_token(&self) -> Result<String>;
}
