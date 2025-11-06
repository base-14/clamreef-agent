use crate::config::OAuth2ClientConfig;
use crate::error::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::AuthProvider;

/// OAuth2 token response from the authorization server
#[derive(Debug, Clone, Deserialize, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// Cached token with expiration tracking
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: SystemTime,
}

/// OAuth2 client credentials authentication provider
pub struct OAuth2Client {
    config: OAuth2ClientConfig,
    http_client: reqwest::Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl OAuth2Client {
    pub fn new(config: OAuth2ClientConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Config(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            http_client,
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Check if the cached token is still valid (with 60 second buffer)
    async fn is_token_valid(&self) -> bool {
        if let Some(ref token) = *self.cached_token.read().await {
            if let Ok(duration) = token.expires_at.duration_since(SystemTime::now()) {
                // Consider token invalid if it expires in less than 60 seconds
                return duration.as_secs() > 60;
            }
        }
        false
    }

    /// Fetch a new access token from the OAuth2 authorization server
    async fn fetch_new_token(&self) -> Result<CachedToken> {
        debug!("Fetching new OAuth2 token from {}", self.config.token_url);

        // Build form parameters
        let mut params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", self.config.client_id.clone()),
            ("client_secret", self.config.client_secret.clone()),
        ];

        // Add any additional endpoint parameters (like audience)
        for (key, value) in &self.config.endpoint_params {
            params.push((key.as_str(), value.clone()));
        }

        // Make the token request
        let response = self
            .http_client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| Error::Telemetry(format!("Failed to request OAuth2 token: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            return Err(Error::Telemetry(format!(
                "OAuth2 token request failed with status {}: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            Error::Telemetry(format!("Failed to parse OAuth2 token response: {}", e))
        })?;

        let expires_at = SystemTime::now() + Duration::from_secs(token_response.expires_in);

        info!(
            "Successfully obtained OAuth2 token (expires in {} seconds)",
            token_response.expires_in
        );

        Ok(CachedToken {
            access_token: token_response.access_token,
            expires_at,
        })
    }
}

#[async_trait]
impl AuthProvider for OAuth2Client {
    async fn get_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        if self.is_token_valid().await {
            debug!("Using cached OAuth2 token");
            let token = self.cached_token.read().await;
            if let Some(ref cached) = *token {
                return Ok(cached.access_token.clone());
            }
        }

        // Fetch a new token
        warn!("Cached token expired or invalid, fetching new token");
        let new_token = self.fetch_new_token().await?;
        let access_token = new_token.access_token.clone();

        // Update cache
        let mut cache = self.cached_token.write().await;
        *cache = Some(new_token);

        Ok(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_config(token_url: &str) -> OAuth2ClientConfig {
        let mut endpoint_params = HashMap::new();
        endpoint_params.insert("audience".to_string(), "test-audience".to_string());

        OAuth2ClientConfig {
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            token_url: token_url.to_string(),
            endpoint_params,
        }
    }

    #[tokio::test]
    async fn test_oauth2_client_new() {
        let config = create_test_config("https://auth.example.com/token");
        let client = OAuth2Client::new(config.clone());
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.config.client_id, "test-client-id");
        assert_eq!(client.config.client_secret, "test-client-secret");
    }

    #[tokio::test]
    async fn test_oauth2_fetch_token_success() {
        let mock_server = MockServer::start().await;

        let token_response = TokenResponse {
            access_token: "test-access-token-123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=test-client-id"))
            .and(body_string_contains("client_secret=test-client-secret"))
            .and(body_string_contains("audience=test-audience"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = create_test_config(&format!("{}/token", mock_server.uri()));
        let client = OAuth2Client::new(config).unwrap();

        let token = client.get_token().await;
        assert!(token.is_ok());
        assert_eq!(token.unwrap(), "test-access-token-123");
    }

    #[tokio::test]
    async fn test_oauth2_fetch_token_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "Invalid client credentials"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = create_test_config(&format!("{}/token", mock_server.uri()));
        let client = OAuth2Client::new(config).unwrap();

        let result = client.get_token().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn test_oauth2_token_caching() {
        let mock_server = MockServer::start().await;

        let token_response = TokenResponse {
            access_token: "cached-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
        };

        // Should only be called once because of caching
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = create_test_config(&format!("{}/token", mock_server.uri()));
        let client = OAuth2Client::new(config).unwrap();

        // First call - fetches new token
        let token1 = client.get_token().await.unwrap();
        assert_eq!(token1, "cached-token");

        // Second call - uses cached token
        let token2 = client.get_token().await.unwrap();
        assert_eq!(token2, "cached-token");

        // Third call - still uses cached token
        let token3 = client.get_token().await.unwrap();
        assert_eq!(token3, "cached-token");
    }

    #[tokio::test]
    async fn test_oauth2_token_expiration() {
        let mock_server = MockServer::start().await;

        // First token that expires quickly
        let short_lived_token = TokenResponse {
            access_token: "short-lived-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 1, // Expires in 1 second
            refresh_token: None,
        };

        // Second token with longer expiration
        let long_lived_token = TokenResponse {
            access_token: "long-lived-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: None,
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&short_lived_token)
                    .append_header("content-type", "application/json"),
            )
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(&long_lived_token)
                    .append_header("content-type", "application/json"),
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&format!("{}/token", mock_server.uri()));
        let client = OAuth2Client::new(config).unwrap();

        // First call - gets short-lived token
        let token1 = client.get_token().await.unwrap();
        assert_eq!(token1, "short-lived-token");

        // Wait for token to expire (plus buffer time)
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second call - token should be expired, fetches new one
        let token2 = client.get_token().await.unwrap();
        assert_eq!(token2, "long-lived-token");
    }

    #[tokio::test]
    async fn test_oauth2_is_token_valid() {
        let config = create_test_config("https://auth.example.com/token");
        let client = OAuth2Client::new(config).unwrap();

        // No token cached yet
        assert!(!client.is_token_valid().await);

        // Add a valid token
        let valid_token = CachedToken {
            access_token: "valid-token".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(300), // 5 minutes from now
        };
        {
            let mut cache = client.cached_token.write().await;
            *cache = Some(valid_token);
        }

        // Token should be valid
        assert!(client.is_token_valid().await);

        // Add an expired token
        let expired_token = CachedToken {
            access_token: "expired-token".to_string(),
            expires_at: SystemTime::now() - Duration::from_secs(10), // Expired 10 seconds ago
        };
        {
            let mut cache = client.cached_token.write().await;
            *cache = Some(expired_token);
        }

        // Token should be invalid
        assert!(!client.is_token_valid().await);

        // Add a token that expires soon (within buffer time)
        let expiring_soon_token = CachedToken {
            access_token: "expiring-soon".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(30), // 30 seconds from now
        };
        {
            let mut cache = client.cached_token.write().await;
            *cache = Some(expiring_soon_token);
        }

        // Token should be considered invalid due to 60 second buffer
        assert!(!client.is_token_valid().await);
    }

    #[tokio::test]
    async fn test_oauth2_minimal_config() {
        let minimal_config = OAuth2ClientConfig {
            client_id: "minimal-client".to_string(),
            client_secret: "minimal-secret".to_string(),
            token_url: "https://auth.example.com/oauth/token".to_string(),
            endpoint_params: HashMap::new(),
        };

        let client = OAuth2Client::new(minimal_config);
        assert!(client.is_ok());
    }
}
