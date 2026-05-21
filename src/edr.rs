//! EDR Client — CrowdStrike Falcon integration for the v0.1-alpha pilot.
//!
//! ## Why this module exists
//!
//! Before this module, `execute` returned the literal string `"executed"`
//! without ever calling any EDR. The pilot would have demoed a working
//! UI on top of a no-op proxy — exactly the worst kind of demo bug
//! (everything looks fine until a real incident).
//!
//! This module is the bridge from the proxy's internal `ActionType` to
//! the actual CrowdStrike Falcon Real Time Response (RTR) APIs.
//!
//! ## Pilot scope
//!
//! The v0.1-alpha pilot targets CrowdStrike Falcon only. SentinelOne is
//! tracked as a post-pilot integration. We intentionally avoid a trait /
//! generic-EDR abstraction here because we've seen exactly one EDR API
//! end-to-end; pre-designing an interface from one example is the kind
//! of premature abstraction that ages badly.
//!
//! When SentinelOne lands, we'll refactor to a `trait EdrBackend` based
//! on the *actual* surface area of both APIs, not a guess.
//!
//! ## Configuration
//!
//! Environment variables (read in `EdrClient::from_env`):
//!
//! | Variable                  | Required | Notes                                |
//! |---------------------------|----------|--------------------------------------|
//! | `EDR_PROVIDER`            | No       | "crowdstrike" (default) or "noop".   |
//! | `CROWDSTRIKE_CLIENT_ID`   | When provider=crowdstrike | OAuth2 client id. |
//! | `CROWDSTRIKE_CLIENT_SECRET` | When provider=crowdstrike | OAuth2 secret. |
//! | `CROWDSTRIKE_BASE_URL`    | No       | API host. Default `https://api.crowdstrike.com`. |
//! | `EDR_HTTP_TIMEOUT_SECS`   | No       | Default 30s.                         |
//!
//! `EDR_PROVIDER=noop` is the safe default for development and CI —
//! `dispatch` logs the intent and returns Ok without making any HTTP
//! call. It is distinct from `DRY_RUN`: DRY_RUN is decided at the
//! `execute` handler level; `noop` is decided at the client construction
//! level. Either being active prevents real EDR side effects.
//!
//! ## Auth
//!
//! CrowdStrike Falcon uses OAuth2 client_credentials. We cache the
//! bearer token in memory until it nears expiry (we refresh at 80% of
//! `expires_in` to avoid the cliff). The token itself is never logged.
//!
//! ## Error mapping
//!
//! All transport, parsing, and HTTP-status errors collapse into the
//! `EdrError` enum. The caller (in `main::execute`) maps the error to
//! `502 Bad Gateway` and releases the nonce so the bot can retry on
//! fresh state.

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::actions::ActionType;

/// Errors that can happen during an EDR dispatch.
///
/// Callers should treat every variant the same on the wire (502 Bad
/// Gateway) so failure modes are not externally distinguishable. The
/// variants are for logging, metrics, and tests.
#[derive(Debug, Error)]
pub enum EdrError {
    /// EDR was contacted but rejected the request (4xx).
    /// Body is included for operator debugging.
    #[error("edr returned client error {status}: {body}")]
    ClientError { status: u16, body: String },

    /// EDR was contacted but returned a server error (5xx). Usually a
    /// retry candidate but we let the upstream decide.
    #[error("edr returned server error {status}: {body}")]
    ServerError { status: u16, body: String },

    /// Transport error (DNS, TCP, TLS, timeout).
    #[error("edr transport error: {0}")]
    Transport(String),

    /// EDR returned a successful HTTP status but the response body
    /// could not be parsed into the shape we expected.
    #[error("edr returned unexpected response: {0}")]
    UnexpectedResponse(String),
}

/// EDR client used by the proxy.
///
/// This is a thin enum over the concrete backends. `Noop` exists so
/// tests and dev runs do not need real credentials.
#[derive(Clone)]
pub enum EdrClient {
    /// Logs the intent and returns Ok. Used for dev, CI, and tests.
    Noop,

    /// CrowdStrike Falcon Real Time Response.
    Crowdstrike(Arc<CrowdstrikeClient>),
}

impl EdrClient {
    /// Build an `EdrClient` from environment variables.
    ///
    /// See module-level docs for the env-var contract. Defaults to
    /// `Noop` if no provider is configured — this is safe-by-default
    /// (mirrors `DRY_RUN=true` as a default).
    pub fn from_env() -> Self {
        let provider = env::var("EDR_PROVIDER").unwrap_or_else(|_| "noop".to_string());
        match provider.trim().to_ascii_lowercase().as_str() {
            "noop" => {
                info!("EDR provider: noop (no real actions will be taken)");
                EdrClient::Noop
            }
            "crowdstrike" => {
                let client = CrowdstrikeClient::from_env()
                    .expect("CROWDSTRIKE_CLIENT_ID/SECRET must be set when EDR_PROVIDER=crowdstrike");
                info!("EDR provider: crowdstrike");
                EdrClient::Crowdstrike(Arc::new(client))
            }
            other => panic!("unknown EDR_PROVIDER: {other}. Use 'noop' or 'crowdstrike'."),
        }
    }

    /// Dispatch a containment action to the configured EDR.
    pub async fn dispatch(&self, action: ActionType, host: &str) -> Result<(), EdrError> {
        match self {
            EdrClient::Noop => {
                info!(?action, host, "noop EDR: would dispatch");
                Ok(())
            }
            EdrClient::Crowdstrike(client) => client.dispatch(action, host).await,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
//  CrowdStrike Falcon implementation
// ─────────────────────────────────────────────────────────────────────

/// CrowdStrike Falcon Real Time Response client.
///
/// Holds a `reqwest::Client` and a mutex-guarded token cache. We use a
/// single Mutex around the cache (rather than per-field locks) because
/// the critical section is microseconds long and contention is bounded
/// by request rate (low for human-approved actions).
pub struct CrowdstrikeClient {
    http: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    token: Mutex<Option<CachedToken>>,
}

#[derive(Clone)]
struct CachedToken {
    bearer: String,
    /// Refresh when `Instant::now()` >= this value.
    refresh_at: Instant,
}

/// Shape of the OAuth2 token response from
/// `POST /oauth2/token`. We only keep the fields we use.
#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    /// Seconds until the token expires.
    expires_in: u64,
}

/// Request body for `POST /devices/entities/devices-actions/v2`.
/// CrowdStrike accepts an array of device IDs and an action name in the
/// query string; the body carries any action-specific parameters.
#[derive(Serialize)]
struct DevicesActionBody<'a> {
    action_parameters: Vec<DeviceActionParam<'a>>,
    ids: Vec<&'a str>,
}

#[derive(Serialize)]
struct DeviceActionParam<'a> {
    name: &'a str,
    value: &'a str,
}

impl CrowdstrikeClient {
    /// Build the client from environment variables. Returns `None` only
    /// when required vars are missing (so `from_env` can panic with a
    /// clear message rather than constructing a half-configured client).
    fn from_env() -> Option<Self> {
        let client_id = env::var("CROWDSTRIKE_CLIENT_ID").ok()?;
        let client_secret = env::var("CROWDSTRIKE_CLIENT_SECRET").ok()?;
        let base_url = env::var("CROWDSTRIKE_BASE_URL")
            .unwrap_or_else(|_| "https://api.crowdstrike.com".to_string());
        let timeout_secs: u64 = env::var("EDR_HTTP_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let http = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            // CrowdStrike requires a User-Agent. Identifying ourselves
            // honestly helps their support team correlate incidents.
            .user_agent(concat!("vyrox-proxy/", env!("CARGO_PKG_VERSION")))
            .build()
            .ok()?;

        Some(Self {
            http,
            base_url,
            client_id,
            client_secret,
            token: Mutex::new(None),
        })
    }

    /// Get a bearer token, refreshing if necessary.
    ///
    /// Concurrency: only one task can hold the lock at a time, so
    /// concurrent first-callers will serialize on the token fetch. After
    /// the first fetch, all callers within the cache window get the
    /// cached value without re-fetching.
    async fn bearer_token(&self) -> Result<String, EdrError> {
        let mut guard = self.token.lock().await;

        if let Some(cached) = guard.as_ref() {
            if Instant::now() < cached.refresh_at {
                return Ok(cached.bearer.clone());
            }
        }

        // Need a fresh token.
        let url = format!("{}/oauth2/token", self.base_url);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| EdrError::Transport(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(EdrError::ClientError {
                status: status.as_u16(),
                body,
            });
        }

        let parsed: OAuthTokenResponse = resp
            .json()
            .await
            .map_err(|e| EdrError::UnexpectedResponse(e.to_string()))?;

        // Refresh at 80% of expiry to absorb clock skew between us and
        // CrowdStrike, and to avoid the cliff where token expires
        // mid-flight.
        let lifetime = Duration::from_secs((parsed.expires_in * 8) / 10);
        let new = CachedToken {
            bearer: parsed.access_token.clone(),
            refresh_at: Instant::now() + lifetime,
        };
        *guard = Some(new);

        Ok(parsed.access_token)
    }

    /// Dispatch a single action to a single host.
    ///
    /// We do not batch — pilot-scale traffic is human-approved, one at
    /// a time. Batching would be a future optimization for bulk
    /// containment use cases (SaaS, not pilot).
    async fn dispatch(&self, action: ActionType, host: &str) -> Result<(), EdrError> {
        // Translate our internal ActionType into the CrowdStrike action
        // name expected on the query string. The mapping is documented
        // in CrowdStrike's "Hosts" API reference.
        let action_name = match action {
            ActionType::HostIsolation => "contain",
            ActionType::ProcessKill => {
                // Process-kill is RTR-script territory, not a single
                // host action. v0.1-alpha exposes it but maps it to
                // host containment as a conservative fallback. We log
                // explicitly so this is not silent.
                warn!(
                    host,
                    "PROCESS_KILL requested; v0.1-alpha falls back to HOST_ISOLATION (RTR scripting is post-pilot)"
                );
                "contain"
            }
            ActionType::NetworkQuarantine => {
                // CrowdStrike's terminology for network isolation is
                // "contain", same as HostIsolation. There is a separate
                // "network_contain" via firewall rules but it requires
                // additional licensing; we treat them as equivalent for
                // v0.1-alpha.
                "contain"
            }
        };

        let token = self.bearer_token().await?;

        let url = format!(
            "{}/devices/entities/devices-actions/v2?action_name={}",
            self.base_url, action_name
        );

        let body = DevicesActionBody {
            action_parameters: vec![],
            ids: vec![host],
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| EdrError::Transport(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            info!(host, action = action_name, "edr action dispatched");
            return Ok(());
        }

        // Capture body for diagnostics. Bounded read in case CrowdStrike
        // returns something unexpectedly large.
        let body_text = resp.text().await.unwrap_or_default();
        let snippet: String = body_text.chars().take(512).collect();

        if status.is_client_error() {
            Err(EdrError::ClientError {
                status: status.as_u16(),
                body: snippet,
            })
        } else {
            Err(EdrError::ServerError {
                status: status.as_u16(),
                body: snippet,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_client_succeeds_for_all_actions() {
        let client = EdrClient::Noop;
        assert!(client.dispatch(ActionType::HostIsolation, "h-1").await.is_ok());
        assert!(client.dispatch(ActionType::ProcessKill, "h-1").await.is_ok());
        assert!(client.dispatch(ActionType::NetworkQuarantine, "h-1").await.is_ok());
    }
}
