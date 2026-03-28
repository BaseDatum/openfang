//! OpenBao MCP authentication — per-user Vault token for MCP proxy auth.
//!
//! Agent pods authenticate to OpenBao using their per-user K8s ServiceAccount
//! token (projected volume) and receive a Vault token.  This token is sent
//! as `Authorization: Bearer <vault_token>` on every MCP request, replacing
//! the insecure `X-Dialogue-User-Id` header.
//!
//! The Vault token has a configurable TTL (default 24h) and is automatically
//! re-authenticated when it nears expiry or receives a 403 from an MCP proxy.

use openfang_types::config::McpAuthConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Token state
// ---------------------------------------------------------------------------

struct TokenState {
    /// The current Vault token (empty if not yet authenticated).
    token: String,
    /// When the token expires (monotonic clock).
    expires_at: Instant,
}

impl Default for TokenState {
    fn default() -> Self {
        Self {
            token: String::new(),
            expires_at: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// McpAuthProvider
// ---------------------------------------------------------------------------

/// Provides Vault tokens for MCP proxy authentication.
///
/// On first call (or when the token is near expiry), reads the projected
/// SA token from disk, authenticates to OpenBao K8s auth, and caches the
/// resulting Vault token.
///
/// Thread-safe via `RwLock<TokenState>`.
#[derive(Clone)]
pub struct McpAuthProvider {
    config: McpAuthConfig,
    state: Arc<RwLock<TokenState>>,
}

impl McpAuthProvider {
    /// Create a new provider from config.
    pub fn new(config: McpAuthConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(TokenState::default())),
        }
    }

    /// Get a valid Vault token, authenticating if necessary.
    ///
    /// Returns `None` if auth is disabled or authentication fails.
    pub async fn get_token(&self) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        // Fast path: return cached token if still valid.
        {
            let state = self.state.read().await;
            if !state.token.is_empty() && Instant::now() < state.expires_at - Duration::from_secs(60)
            {
                return Some(state.token.clone());
            }
        }

        // Slow path: re-authenticate.
        self.authenticate().await
    }

    /// Force re-authentication (e.g., after a 403 from an MCP proxy).
    pub async fn invalidate(&self) {
        let mut state = self.state.write().await;
        state.token.clear();
        state.expires_at = Instant::now();
        debug!("MCP auth token invalidated — will re-authenticate on next request");
    }

    /// Authenticate to OpenBao using K8s auth and cache the Vault token.
    async fn authenticate(&self) -> Option<String> {
        let mut state = self.state.write().await;

        // Double-check after acquiring write lock (another task may have
        // authenticated while we were waiting).
        if !state.token.is_empty() && Instant::now() < state.expires_at - Duration::from_secs(60) {
            return Some(state.token.clone());
        }

        // Read the projected SA token from disk.
        let jwt = match tokio::fs::read_to_string(&self.config.sa_token_path).await {
            Ok(contents) => contents.trim().to_string(),
            Err(e) => {
                error!(
                    path = %self.config.sa_token_path,
                    error = %e,
                    "Failed to read SA token for MCP auth"
                );
                return None;
            }
        };

        // Build a vaultrs client.
        let mut client_builder = vaultrs::client::VaultClientSettingsBuilder::default();
        client_builder.address(&self.config.bao_addr);

        // Configure CA cert if it exists and is valid.
        let ca_path = std::path::Path::new(&self.config.bao_ca_cert);
        if ca_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(ca_path) {
                if contents.trim().starts_with("-----BEGIN CERTIFICATE") {
                    client_builder.ca_certs(vec![self.config.bao_ca_cert.clone()]);
                }
            }
        }

        let client_settings = match client_builder.build() {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to build Vault client settings");
                return None;
            }
        };

        let client = match vaultrs::client::VaultClient::new(client_settings) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to create Vault client");
                return None;
            }
        };

        // Authenticate via K8s auth method.
        match vaultrs::auth::kubernetes::login(
            &client,
            &self.config.bao_auth_mount,
            &self.config.bao_auth_role,
            &jwt,
        )
        .await
        {
            Ok(auth_info) => {
                let token = auth_info.client_token.clone();
                let ttl = auth_info.lease_duration;

                state.token = token.clone();
                state.expires_at = Instant::now() + Duration::from_secs(ttl);

                info!(
                    role = %self.config.bao_auth_role,
                    ttl_secs = ttl,
                    "MCP auth: authenticated to OpenBao"
                );

                Some(token)
            }
            Err(e) => {
                warn!(
                    role = %self.config.bao_auth_role,
                    mount = %self.config.bao_auth_mount,
                    error = %e,
                    "MCP auth: OpenBao K8s login failed"
                );
                None
            }
        }
    }
}
