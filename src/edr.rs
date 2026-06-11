//! EDR Client, CrowdStrike Falcon and SentinelOne integration for the pilot.
//!
//! ## Why this module exists
//!
//! Before this module, `execute` returned the literal string `"executed"`
//! without ever calling any EDR. The pilot would have demoed a working
//! UI on top of a no-op proxy, exactly the worst kind of demo bug
//! (everything looks fine until a real incident).
//!
//! This module is the bridge from the proxy's internal `ActionType` to
//! the actual CrowdStrike Falcon and SentinelOne containment APIs.
//!
//! ## Per-tenant credentials (E7)
//!
//! Vyrox runs ONE central proxy for all tenants (CONSOLE_PLATFORM 8b). The
//! proxy can no longer read a single global EDR credential from its env: an
//! action for tenant A must act in tenant A's EDR, with tenant A's API key.
//!
//! So the signed request now carries the tenant's decrypted EDR credentials
//! (`EdrCredentials`). The Python orchestrator decrypts them from
//! `TenantCredential.*_encrypted` just before the call and includes them in
//! the body. The proxy uses THOSE for the EDR call. The credentials travel
//! over TLS (the deploy terminates TLS at the proxy or a reverse proxy in
//! front of it) and inside the HMAC-signed body, so they are both encrypted
//! in transit and integrity-protected, a tampered credential blob fails the
//! signature check before it is ever read.
//!
//! The global env credential (`EdrClient::from_env`) stays as a dev/sandbox
//! fallback ONLY: it is used when the request carries no per-tenant
//! credentials, which is the local-dev and CI path. Production always sends
//! per-tenant creds.
//!
//! ## Provider scope
//!
//! CrowdStrike Falcon (Real Time Response contain/lift) and SentinelOne
//! (connect/disconnect) are both supported because the per-tenant credential
//! carries its own `provider` tag, the central proxy serves tenants on
//! different EDRs at the same time. `noop` remains the safe default when no
//! credential is configured at all.
//!
//! ## Auth
//!
//! CrowdStrike Falcon uses OAuth2 client_credentials. A per-request client
//! fetches its own bearer token (no shared cache across tenants, since the
//! credentials differ per tenant). SentinelOne uses a static API token passed
//! as `ApiToken` in the `Authorization` header. Tokens are never logged.
//!
//! ## Action mapping (honest by construction)
//!
//! Each `(ActionType, ActionDirection)` pair maps to exactly one vendor
//! call, or fails loudly with `EdrError::Unsupported`. The proxy NEVER
//! substitutes a different action for the one the operator approved. The
//! one mapping that looks like a merge is genuine vendor semantics:
//! CrowdStrike's `contain` and SentinelOne's `disconnect` are network
//! containment primitives, so HOST_ISOLATION and NETWORK_QUARANTINE both
//! map to them because that IS the vendor's isolation action, not a
//! stand-in for something else.
//!
//! PROCESS_KILL is unsupported on both providers today and fails loudly:
//! a true CrowdStrike kill needs a Real Time Response session plus a
//! process id, and a SentinelOne kill via threat mitigation needs an S1
//! threat id. The signed request carries neither (only the host / agent
//! identifier), so the proxy refuses rather than quietly quarantining a
//! whole host the operator never approved.
//!
//! ## Error mapping
//!
//! All transport, parsing, and HTTP-status errors collapse into the
//! `EdrError` enum. The caller (in `main`) maps `Unsupported` to `501 Not
//! Implemented` and every other variant to `502 Bad Gateway` (for
//! `/execute`) or pages a human (for `/rollback`), and releases the nonce
//! so a retry can run on fresh state.

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::info;

use crate::actions::{ActionDirection, ActionType};

/// Default HTTP timeout for EDR calls, in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Errors that can happen during an EDR dispatch.
///
/// Callers treat the transport-shaped variants the same on the wire (502
/// Bad Gateway) so EDR failure modes are not externally distinguishable.
/// `Unsupported` is the exception: it maps to 501 Not Implemented so the
/// caller can tell "the EDR is down, retry" apart from "this action does
/// not exist for this provider, do not retry".
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

    /// The request did not carry usable credentials and no fallback was
    /// configured. Surfaced rather than silently no-op so a misconfigured
    /// production call fails loudly.
    #[error("edr misconfigured: {0}")]
    Misconfigured(String),

    /// The approved action has no faithful implementation on this
    /// provider. Fails loudly INSTEAD of substituting a different action:
    /// the operator approved a specific containment, and quietly doing
    /// something broader (or narrower) would put an action nobody approved
    /// on a production host and a lie in the audit trail.
    #[error("{action:?} not supported for provider {provider} yet: {detail}. Refusing to substitute a different action")]
    Unsupported {
        action: ActionType,
        provider: &'static str,
        detail: &'static str,
    },
}

/// Which EDR a per-tenant credential targets.
///
/// Carried on `EdrCredentials` so the central proxy can serve tenants on
/// different EDRs at once: it dispatches on the credential's provider, not
/// on a single global setting.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EdrProvider {
    Crowdstrike,
    Sentinelone,
}

/// Per-tenant EDR credentials, decrypted by the Python orchestrator and
/// carried inside the signed request body.
///
/// Wire-stable: this is part of the contract with the Python side
/// (`shared/proxy_client.py`). The whole struct is optional on the request;
/// when absent the proxy falls back to its global env client (dev/sandbox).
///
/// The values are plaintext credentials. They are safe here ONLY because the
/// whole body is HMAC-signed (integrity) and the transport is TLS
/// (confidentiality). Never log any field of this struct.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EdrCredentials {
    /// Which EDR these credentials authenticate against.
    pub provider: EdrProvider,

    /// CrowdStrike OAuth2 client id, or the principal id for SentinelOne
    /// (unused there, kept for a uniform shape).
    pub api_key: String,

    /// CrowdStrike OAuth2 client secret, or the SentinelOne API token.
    /// Optional because a token-only vendor has no secret half, but at
    /// least one credential is always required.
    #[serde(default)]
    pub api_secret: Option<String>,

    /// Per-tenant EDR API base URL override. Lets the mock EDR (and a
    /// customer on a non-default CrowdStrike cloud, e.g. US-2 / EU-1) be
    /// targeted without a global env change. Falls back to the provider's
    /// default when absent.
    #[serde(default)]
    pub base_url: Option<String>,
}

impl EdrCredentials {
    /// True if the credentials carry enough to authenticate. A blank api_key
    /// (or, for token vendors, a blank token) is treated as "not configured"
    /// so an empty decrypt result falls back rather than failing mid-call.
    fn is_usable(&self) -> bool {
        match self.provider {
            EdrProvider::Crowdstrike => {
                !self.api_key.trim().is_empty()
                    && self
                        .api_secret
                        .as_ref()
                        .is_some_and(|s| !s.trim().is_empty())
            }
            EdrProvider::Sentinelone => self
                .api_secret
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty()),
        }
    }
}

/// EDR client used by the proxy as the dev/sandbox fallback.
///
/// This is a thin enum over the concrete backends. `Noop` exists so tests
/// and dev runs do not need real credentials. In production the per-request
/// `EdrCredentials` take precedence and this is never reached.
#[derive(Clone)]
pub enum EdrClient {
    /// Logs the intent and returns Ok. Used for dev, CI, and tests.
    Noop,

    /// CrowdStrike Falcon Real Time Response, configured from the global env.
    Crowdstrike(Arc<CrowdstrikeClient>),
}

impl EdrClient {
    /// Build an `EdrClient` from environment variables.
    ///
    /// See module-level docs for the env-var contract. Defaults to
    /// `Noop` if no provider is configured, which is safe-by-default
    /// (mirrors `DRY_RUN=true` as a default). This is the dev/sandbox
    /// fallback only; production routes per-tenant credentials instead.
    pub fn from_env() -> Self {
        let provider = env::var("EDR_PROVIDER").unwrap_or_else(|_| "noop".to_string());
        match provider.trim().to_ascii_lowercase().as_str() {
            "noop" => {
                info!("EDR provider: noop (no real actions will be taken)");
                EdrClient::Noop
            }
            "crowdstrike" => {
                let base_url = env::var("CROWDSTRIKE_BASE_URL")
                    .unwrap_or_else(|_| "https://api.crowdstrike.com".to_string());
                let client_id = env::var("CROWDSTRIKE_CLIENT_ID")
                    .expect("CROWDSTRIKE_CLIENT_ID must be set when EDR_PROVIDER=crowdstrike");
                let client_secret = env::var("CROWDSTRIKE_CLIENT_SECRET")
                    .expect("CROWDSTRIKE_CLIENT_SECRET must be set when EDR_PROVIDER=crowdstrike");
                let client = CrowdstrikeClient::new(base_url, client_id, client_secret)
                    .expect("failed to build CrowdStrike HTTP client");
                info!("EDR provider: crowdstrike (global env fallback)");
                EdrClient::Crowdstrike(Arc::new(client))
            }
            other => panic!("unknown EDR_PROVIDER: {other}. Use 'noop' or 'crowdstrike'."),
        }
    }

    /// Dispatch using the global fallback client.
    ///
    /// Only reached when the request carried no usable per-tenant credentials
    /// (dev/sandbox). `direction` selects contain vs lift.
    async fn dispatch_fallback(
        &self,
        action: ActionType,
        direction: ActionDirection,
        host: &str,
    ) -> Result<(), EdrError> {
        match self {
            EdrClient::Noop => {
                info!(?action, ?direction, host, "noop EDR: would dispatch");
                Ok(())
            }
            EdrClient::Crowdstrike(client) => client.dispatch(action, direction, host).await,
        }
    }
}

/// Read the per-call HTTP timeout from the env, defaulting to 30s.
fn http_timeout_secs() -> u64 {
    env::var("EDR_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

/// Dispatch a containment or rollback action, preferring per-tenant
/// credentials over the global env fallback.
///
/// This is the single entry point the request handler calls. The decision
/// tree:
///
/// 1. If the request carried usable `EdrCredentials`, build a one-shot
///    client for that tenant's EDR and dispatch with it. Tenant A's action
///    therefore always acts with tenant A's key, never the global env, never
///    another tenant's key (CONSOLE_PLATFORM 8b consequence #4).
/// 2. If no usable credentials were supplied, fall back to the global env
///    client. In production that is `noop` (no-op) or absent; in dev it lets
///    a single global CrowdStrike cred drive a sandbox.
///
/// `direction` selects whether we apply or reverse the action (contain vs
/// lift / un-isolate), so the same dispatch path serves `/execute` and
/// `/rollback`.
pub async fn dispatch(
    fallback: &EdrClient,
    creds: Option<&EdrCredentials>,
    action: ActionType,
    direction: ActionDirection,
    host: &str,
) -> Result<(), EdrError> {
    match creds {
        Some(c) if c.is_usable() => match c.provider {
            EdrProvider::Crowdstrike => {
                let base_url = c
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.crowdstrike.com".to_string());
                // is_usable guarantees both halves are present for CrowdStrike.
                let secret = c.api_secret.clone().unwrap_or_default();
                let client = CrowdstrikeClient::new(base_url, c.api_key.clone(), secret)?;
                client.dispatch(action, direction, host).await
            }
            EdrProvider::Sentinelone => {
                let base_url = c.base_url.clone().ok_or_else(|| {
                    EdrError::Misconfigured(
                        "SentinelOne credential is missing its base_url \
                             (the management console URL)"
                            .to_string(),
                    )
                })?;
                let token = c.api_secret.clone().unwrap_or_default();
                let client = SentinelOneClient::new(base_url, token)?;
                client.dispatch(action, direction, host).await
            }
        },
        // No usable per-tenant credential: dev/sandbox fallback.
        _ => {
            info!(
                host,
                ?action,
                ?direction,
                "no per-tenant EDR credential on request; using global env fallback"
            );
            fallback.dispatch_fallback(action, direction, host).await
        }
    }
}

/// Pure supportability check: would `dispatch` have a faithful mapping for
/// this action on the provider this request would target?
///
/// Mirrors `dispatch`'s provider selection (per-tenant credential first,
/// global env fallback otherwise) but only consults the pure action-name
/// mappers. It makes ZERO network calls and builds no HTTP client, so the
/// request handler can run it BEFORE the DRY_RUN short-circuit without
/// violating Rule #5. That ordering is the point: a dry-run rehearsal of an
/// action the provider cannot perform must predict the production 501, not
/// report dry-run success.
///
/// `Noop` supports everything by construction: it performs nothing, so there
/// is no mapping to be unfaithful to.
pub fn check_supported(
    fallback: &EdrClient,
    creds: Option<&EdrCredentials>,
    action: ActionType,
    direction: ActionDirection,
) -> Result<(), EdrError> {
    let provider = match creds {
        Some(c) if c.is_usable() => c.provider,
        _ => match fallback {
            EdrClient::Noop => return Ok(()),
            EdrClient::Crowdstrike(_) => EdrProvider::Crowdstrike,
        },
    };
    match provider {
        EdrProvider::Crowdstrike => crowdstrike_action_name(action, direction).map(|_| ()),
        EdrProvider::Sentinelone => sentinelone_action_path(action, direction).map(|_| ()),
    }
}

// ----------------------------------------------------------------------
//  CrowdStrike Falcon implementation
// ----------------------------------------------------------------------

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
    /// Build a client for a given base URL and credential pair.
    ///
    /// Used both by `from_env` (global fallback) and by `dispatch` for a
    /// per-tenant credential. Returns `Misconfigured` only if the HTTP
    /// client itself cannot be built, which is effectively unreachable but
    /// surfaced rather than `expect`-ed so it cannot DoS a request handler.
    fn new(base_url: String, client_id: String, client_secret: String) -> Result<Self, EdrError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(http_timeout_secs()))
            // CrowdStrike requires a User-Agent. Identifying ourselves
            // honestly helps their support team correlate incidents.
            .user_agent(concat!("vyrox-proxy/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| EdrError::Misconfigured(format!("http client build failed: {e}")))?;

        Ok(Self {
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
    /// concurrent first-callers serialize on the token fetch. After the
    /// first fetch, all callers within the cache window get the cached value
    /// without re-fetching. A per-request client (the per-tenant path) lives
    /// for one action, so it fetches once and is dropped.
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
        // CrowdStrike, and to avoid the cliff where the token expires
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
    /// `direction` chooses the CrowdStrike action name: contain vs lift.
    /// We do not batch, pilot-scale traffic is human-approved, one at a
    /// time.
    async fn dispatch(
        &self,
        action: ActionType,
        direction: ActionDirection,
        host: &str,
    ) -> Result<(), EdrError> {
        // Resolve the vendor action BEFORE any network traffic. An
        // unsupported action must fail here, with zero EDR calls made.
        let action_name = crowdstrike_action_name(action, direction)?;

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
            info!(
                host,
                action = action_name,
                ?direction,
                "edr action dispatched"
            );
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

/// Map our internal `(ActionType, ActionDirection)` to the CrowdStrike
/// action name on the query string, or fail loudly if there is none.
///
/// The mapping is documented in CrowdStrike's "Hosts" API reference.
/// `contain` is CrowdStrike's network containment primitive, so it is the
/// faithful vendor call for BOTH `HOST_ISOLATION` and `NETWORK_QUARANTINE`
/// (it is the same operation in Falcon, not a substitution).
///
/// `PROCESS_KILL` has no faithful mapping here: a real kill needs a Real
/// Time Response session plus a process id, and the signed request carries
/// neither. Until the wire contract grows a process identifier and an RTR
/// client lands, the action fails loudly. It previously downgraded to host
/// containment with only a log line, which executed an action the operator
/// never approved; that downgrade is exactly what this function now forbids.
fn crowdstrike_action_name(
    action: ActionType,
    direction: ActionDirection,
) -> Result<&'static str, EdrError> {
    match action {
        ActionType::HostIsolation | ActionType::NetworkQuarantine => Ok(match direction {
            ActionDirection::Apply => "contain",
            ActionDirection::Reverse => "lift_containment",
        }),
        ActionType::ProcessKill => Err(EdrError::Unsupported {
            action,
            provider: "crowdstrike",
            detail: "a true kill needs a Real Time Response session and a process id, \
                     and the signed request carries neither",
        }),
    }
}

// ----------------------------------------------------------------------
//  SentinelOne implementation
// ----------------------------------------------------------------------

/// SentinelOne client. Uses a static `ApiToken` in the Authorization header
/// and the agents connect/disconnect actions for network containment.
pub struct SentinelOneClient {
    http: Client,
    base_url: String,
    token: String,
}

/// SentinelOne action bodies target agents by a filter. We target a single
/// agent by its uuid (the `host` value the orchestrator supplies for an S1
/// tenant is the agent uuid, mirroring how CrowdStrike uses the AID).
#[derive(Serialize)]
struct S1ActionBody<'a> {
    filter: S1Filter<'a>,
}

#[derive(Serialize)]
struct S1Filter<'a> {
    uuids: Vec<&'a str>,
}

impl SentinelOneClient {
    fn new(base_url: String, token: String) -> Result<Self, EdrError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(http_timeout_secs()))
            .user_agent(concat!("vyrox-proxy/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| EdrError::Misconfigured(format!("http client build failed: {e}")))?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    async fn dispatch(
        &self,
        action: ActionType,
        direction: ActionDirection,
        host: &str,
    ) -> Result<(), EdrError> {
        // Resolve the vendor action BEFORE any network traffic. An
        // unsupported action must fail here, with zero EDR calls made.
        let action_path = sentinelone_action_path(action, direction)?;
        let url = format!(
            "{}/web/api/v2.1/agents/actions/{}",
            self.base_url.trim_end_matches('/'),
            action_path
        );

        let body = S1ActionBody {
            filter: S1Filter { uuids: vec![host] },
        };

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("ApiToken {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| EdrError::Transport(e.to_string()))?;

        let status = resp.status();
        if status.is_success() {
            info!(
                host,
                action = action_path,
                ?direction,
                "s1 action dispatched"
            );
            return Ok(());
        }

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

/// Map our internal `(ActionType, ActionDirection)` to the SentinelOne
/// agents-action path segment, or fail loudly if there is none.
///
/// SentinelOne's network containment is `disconnect` (network off) and the
/// rollback is `connect` (network on), at
/// `/web/api/v2.1/agents/actions/{disconnect|connect}`. Disconnect IS the
/// vendor's isolation primitive, so it is the faithful call for both
/// `HOST_ISOLATION` and `NETWORK_QUARANTINE` (same operation, not a
/// substitution). Previously the action type was ignored entirely and
/// every action became a disconnect; this mapping makes that decision
/// explicit and rejects what cannot be honoured.
///
/// `PROCESS_KILL` has no faithful mapping: S1 kills via threat mitigation
/// (`/threats/mitigate/kill`), which needs an S1 threat id, and the signed
/// request carries only the agent uuid. Until the wire contract carries a
/// threat id, the action fails loudly instead of disconnecting a host the
/// operator never asked to disconnect.
fn sentinelone_action_path(
    action: ActionType,
    direction: ActionDirection,
) -> Result<&'static str, EdrError> {
    match action {
        ActionType::HostIsolation | ActionType::NetworkQuarantine => Ok(match direction {
            ActionDirection::Apply => "disconnect",
            ActionDirection::Reverse => "connect",
        }),
        ActionType::ProcessKill => Err(EdrError::Unsupported {
            action,
            provider: "sentinelone",
            detail: "killing via threat mitigation needs a SentinelOne threat id, \
                     and the signed request carries only the agent uuid",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs_creds() -> EdrCredentials {
        EdrCredentials {
            provider: EdrProvider::Crowdstrike,
            api_key: "client-id".to_string(),
            api_secret: Some("client-secret".to_string()),
            base_url: Some("http://127.0.0.1:1".to_string()),
        }
    }

    #[tokio::test]
    async fn noop_fallback_succeeds_for_all_actions_both_directions() {
        let fallback = EdrClient::Noop;
        for action in [
            ActionType::HostIsolation,
            ActionType::ProcessKill,
            ActionType::NetworkQuarantine,
        ] {
            for dir in [ActionDirection::Apply, ActionDirection::Reverse] {
                assert!(
                    dispatch(&fallback, None, action, dir, "h-1").await.is_ok(),
                    "noop fallback should accept {action:?} {dir:?}"
                );
            }
        }
    }

    #[test]
    fn check_supported_mirrors_dispatch_provider_selection() {
        // Per-tenant CrowdStrike credential: PROCESS_KILL is unsupported,
        // containment actions pass. No client is built, no call leaves.
        let creds = cs_creds();
        for dir in [ActionDirection::Apply, ActionDirection::Reverse] {
            let err = check_supported(&EdrClient::Noop, Some(&creds), ActionType::ProcessKill, dir)
                .expect_err("PROCESS_KILL has no faithful CrowdStrike mapping");
            assert!(matches!(err, EdrError::Unsupported { .. }));
            check_supported(
                &EdrClient::Noop,
                Some(&creds),
                ActionType::HostIsolation,
                dir,
            )
            .expect("host isolation is supported");
        }
    }

    #[test]
    fn check_supported_treats_noop_fallback_as_supporting_everything() {
        // No usable credential and a Noop fallback: nothing real would run,
        // so nothing is unsupported. Mirrors dispatch, which returns Ok.
        for action in [
            ActionType::HostIsolation,
            ActionType::ProcessKill,
            ActionType::NetworkQuarantine,
        ] {
            check_supported(&EdrClient::Noop, None, action, ActionDirection::Apply)
                .expect("noop fallback supports every action");
        }
    }

    #[test]
    fn check_supported_unusable_credential_falls_back() {
        // A blank credential is "not configured": supportability follows the
        // fallback (Noop here), exactly like dispatch's routing.
        let creds = EdrCredentials {
            provider: EdrProvider::Crowdstrike,
            api_key: "  ".to_string(),
            api_secret: None,
            base_url: None,
        };
        check_supported(
            &EdrClient::Noop,
            Some(&creds),
            ActionType::ProcessKill,
            ActionDirection::Apply,
        )
        .expect("unusable credential routes to the Noop fallback");
    }

    #[test]
    fn crowdstrike_action_name_maps_direction() {
        assert_eq!(
            crowdstrike_action_name(ActionType::HostIsolation, ActionDirection::Apply)
                .expect("supported"),
            "contain"
        );
        assert_eq!(
            crowdstrike_action_name(ActionType::HostIsolation, ActionDirection::Reverse)
                .expect("supported"),
            "lift_containment"
        );
        // NETWORK_QUARANTINE is the same Falcon primitive (network
        // containment), so it maps to the same vendor action honestly.
        assert_eq!(
            crowdstrike_action_name(ActionType::NetworkQuarantine, ActionDirection::Apply)
                .expect("supported"),
            "contain"
        );
        assert_eq!(
            crowdstrike_action_name(ActionType::NetworkQuarantine, ActionDirection::Reverse)
                .expect("supported"),
            "lift_containment"
        );
    }

    #[test]
    fn crowdstrike_process_kill_is_unsupported_never_downgraded() {
        // The old behaviour mapped PROCESS_KILL to "contain" with only a
        // log line: the operator approved a surgical kill and got a full
        // host quarantine. The mapping must now refuse, both directions.
        for dir in [ActionDirection::Apply, ActionDirection::Reverse] {
            let err = crowdstrike_action_name(ActionType::ProcessKill, dir)
                .expect_err("PROCESS_KILL must not map to any CrowdStrike action");
            assert!(
                matches!(
                    err,
                    EdrError::Unsupported {
                        action: ActionType::ProcessKill,
                        provider: "crowdstrike",
                        ..
                    }
                ),
                "expected Unsupported, got {err:?}"
            );
        }
    }

    #[test]
    fn sentinelone_action_path_maps_each_action_type() {
        assert_eq!(
            sentinelone_action_path(ActionType::HostIsolation, ActionDirection::Apply)
                .expect("supported"),
            "disconnect"
        );
        assert_eq!(
            sentinelone_action_path(ActionType::HostIsolation, ActionDirection::Reverse)
                .expect("supported"),
            "connect"
        );
        assert_eq!(
            sentinelone_action_path(ActionType::NetworkQuarantine, ActionDirection::Apply)
                .expect("supported"),
            "disconnect"
        );
        assert_eq!(
            sentinelone_action_path(ActionType::NetworkQuarantine, ActionDirection::Reverse)
                .expect("supported"),
            "connect"
        );
    }

    #[test]
    fn sentinelone_process_kill_is_unsupported_never_downgraded() {
        for dir in [ActionDirection::Apply, ActionDirection::Reverse] {
            let err = sentinelone_action_path(ActionType::ProcessKill, dir)
                .expect_err("PROCESS_KILL must not map to any SentinelOne action");
            assert!(
                matches!(
                    err,
                    EdrError::Unsupported {
                        action: ActionType::ProcessKill,
                        provider: "sentinelone",
                        ..
                    }
                ),
                "expected Unsupported, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn crowdstrike_process_kill_fails_before_any_edr_call() {
        // The credential points at an unreachable address: if the client
        // attempted ANY network call (even the token fetch) we would see a
        // Transport error. Getting Unsupported proves the dispatch failed
        // loudly before a single byte left the proxy.
        let fallback = EdrClient::Noop;
        let creds = cs_creds();
        let err = dispatch(
            &fallback,
            Some(&creds),
            ActionType::ProcessKill,
            ActionDirection::Apply,
            "device-1",
        )
        .await
        .expect_err("PROCESS_KILL on CrowdStrike must fail");
        assert!(
            matches!(err, EdrError::Unsupported { .. }),
            "expected Unsupported (no call attempted), got {err:?}"
        );
    }

    #[tokio::test]
    async fn sentinelone_process_kill_fails_before_any_edr_call() {
        let fallback = EdrClient::Noop;
        let creds = EdrCredentials {
            provider: EdrProvider::Sentinelone,
            api_key: String::new(),
            api_secret: Some("tok".to_string()),
            base_url: Some("http://127.0.0.1:1".to_string()),
        };
        let err = dispatch(
            &fallback,
            Some(&creds),
            ActionType::ProcessKill,
            ActionDirection::Apply,
            "agent-1",
        )
        .await
        .expect_err("PROCESS_KILL on SentinelOne must fail");
        assert!(
            matches!(err, EdrError::Unsupported { .. }),
            "expected Unsupported (no call attempted), got {err:?}"
        );
    }

    #[test]
    fn credentials_usability_respects_provider_shape() {
        assert!(cs_creds().is_usable());

        // CrowdStrike needs both halves.
        let mut missing_secret = cs_creds();
        missing_secret.api_secret = None;
        assert!(!missing_secret.is_usable());

        let mut blank_key = cs_creds();
        blank_key.api_key = "  ".to_string();
        assert!(!blank_key.is_usable());

        // SentinelOne is token-only: the token lives in api_secret.
        let s1 = EdrCredentials {
            provider: EdrProvider::Sentinelone,
            api_key: String::new(),
            api_secret: Some("tok".to_string()),
            base_url: Some("https://s1.example".to_string()),
        };
        assert!(s1.is_usable());

        let s1_blank = EdrCredentials {
            provider: EdrProvider::Sentinelone,
            api_key: String::new(),
            api_secret: Some("   ".to_string()),
            base_url: Some("https://s1.example".to_string()),
        };
        assert!(!s1_blank.is_usable());
    }

    #[tokio::test]
    async fn per_tenant_credential_is_used_over_global_fallback() {
        // The fallback is Noop (would succeed). The per-tenant credential
        // points CrowdStrike at an unreachable base_url, so a transport
        // error proves the per-tenant client ran INSTEAD of the noop
        // fallback. If the fallback had been used we would get Ok.
        let fallback = EdrClient::Noop;
        let creds = cs_creds();
        let err = dispatch(
            &fallback,
            Some(&creds),
            ActionType::HostIsolation,
            ActionDirection::Apply,
            "device-1",
        )
        .await
        .expect_err("per-tenant CrowdStrike client should attempt a real call and fail transport");
        assert!(
            matches!(err, EdrError::Transport(_)),
            "expected transport error from per-tenant client, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unusable_credential_falls_back_to_global() {
        // A credential whose secret is blank is NOT usable, so dispatch must
        // fall back to the Noop global client and succeed.
        let fallback = EdrClient::Noop;
        let mut creds = cs_creds();
        creds.api_secret = Some(String::new());
        assert!(dispatch(
            &fallback,
            Some(&creds),
            ActionType::HostIsolation,
            ActionDirection::Apply,
            "device-1",
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn sentinelone_without_base_url_is_misconfigured() {
        let fallback = EdrClient::Noop;
        let creds = EdrCredentials {
            provider: EdrProvider::Sentinelone,
            api_key: String::new(),
            api_secret: Some("tok".to_string()),
            base_url: None,
        };
        let err = dispatch(
            &fallback,
            Some(&creds),
            ActionType::NetworkQuarantine,
            ActionDirection::Apply,
            "agent-1",
        )
        .await
        .expect_err("S1 with no base_url must be Misconfigured");
        assert!(matches!(err, EdrError::Misconfigured(_)));
    }

    // ── SentinelOne endpoint-level test against a loopback mock ────────
    //
    // Proves the S1 client hits the CORRECT agents-action endpoint for
    // each supported action type and direction, and that an unsupported
    // action produces zero calls.

    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;

    /// Start a SentinelOne-shaped mock recording every action path hit.
    async fn spawn_mock_s1() -> (String, Arc<StdMutex<Vec<String>>>) {
        use axum::extract::{Path, State};
        use axum::response::Json;
        use axum::Router;

        let hits: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));

        async fn agents_action(
            State(hits): State<Arc<StdMutex<Vec<String>>>>,
            Path(action): Path<String>,
        ) -> Json<serde_json::Value> {
            hits.lock().expect("mock s1 state poisoned").push(action);
            Json(serde_json::json!({"data": {"affected": 1}}))
        }

        let app = Router::new()
            .route(
                "/web/api/v2.1/agents/actions/:action",
                axum::routing::post(agents_action),
            )
            .with_state(hits.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock s1");
        let addr: SocketAddr = listener.local_addr().expect("mock s1 addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock s1 serve");
        });
        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn sentinelone_hits_correct_endpoint_per_action_and_direction() {
        let (base_url, hits) = spawn_mock_s1().await;
        let fallback = EdrClient::Noop;
        let creds = EdrCredentials {
            provider: EdrProvider::Sentinelone,
            api_key: String::new(),
            api_secret: Some("tok".to_string()),
            base_url: Some(base_url),
        };

        // Isolation: disconnect on apply, connect on rollback.
        dispatch(
            &fallback,
            Some(&creds),
            ActionType::HostIsolation,
            ActionDirection::Apply,
            "agent-1",
        )
        .await
        .expect("isolation apply");
        dispatch(
            &fallback,
            Some(&creds),
            ActionType::HostIsolation,
            ActionDirection::Reverse,
            "agent-1",
        )
        .await
        .expect("isolation rollback");

        // Network quarantine: the same S1 primitive, honestly.
        dispatch(
            &fallback,
            Some(&creds),
            ActionType::NetworkQuarantine,
            ActionDirection::Apply,
            "agent-1",
        )
        .await
        .expect("quarantine apply");

        // Process kill: unsupported, must NOT add a hit.
        let err = dispatch(
            &fallback,
            Some(&creds),
            ActionType::ProcessKill,
            ActionDirection::Apply,
            "agent-1",
        )
        .await
        .expect_err("process kill must fail loudly");
        assert!(matches!(err, EdrError::Unsupported { .. }));

        let recorded = hits.lock().expect("mock s1 state poisoned").clone();
        assert_eq!(
            recorded,
            vec!["disconnect", "connect", "disconnect"],
            "S1 must receive exactly the approved actions, in order, and nothing for PROCESS_KILL"
        );
    }
}
