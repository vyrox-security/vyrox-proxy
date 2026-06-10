//! Vyrox Proxy - Containment Action Executor
//!
//! Single-purpose HTTP service that executes EDR containment actions
//! (host isolation, process kill, network quarantine) on behalf of the
//! Vyrox SOC platform. Every action requires a human-approved request
//! signed with the shared HMAC secret; the proxy verifies the signature
//! and serves as the only code path that calls the EDR API.
//!
//! ## Request lifecycle
//!
//! For every `POST /execute` call:
//!
//! 1. **Capture raw body** before any parsing. The HMAC must be verified
//!    against the bytes the client signed, not against a re-serialized
//!    version of the parsed JSON (which would re-order keys and change
//!    the digest).
//! 2. **Verify HMAC** in constant time (see `hmac::verify_signature`).
//! 3. **Parse the JSON body** into an `ExecuteRequest`.
//! 4. **Replay window check** - reject if `approved_at` is outside the
//!    30-second window in either direction.
//! 5. **Nonce dedup** - claim the `request_id` in the nonce store. If
//!    already completed, return the cached response. If still in flight,
//!    return 409 Conflict.
//! 6. **Audit before action** - write an audit entry recording the
//!    intent BEFORE invoking the EDR (`audit::append_audit`). This way
//!    a crash mid-action still leaves a forensic trail.
//! 7. **Execute via the EDR client** (or return early if DRY_RUN).
//! 8. **Cache the response** in the nonce store so retries are idempotent.
//!
//! ## Endpoints
//!
//! | Method | Path             | Purpose                              |
//! |--------|------------------|--------------------------------------|
//! | GET    | /health          | Liveness probe                       |
//! | POST   | /execute         | Execute a containment action         |
//! | POST   | /rollback        | Reverse a containment action         |
//! | GET    | /audit/export    | Tenant-scoped audit log export       |
//!
//! `/execute` and `/rollback` share one lifecycle (`run_action`): the only
//! difference is the `ActionDirection` (apply vs reverse) and the audit
//! `action_type` tag. Both verify HMAC, enforce the replay window, dedupe by
//! nonce, audit BEFORE acting, and honour DRY_RUN identically.

use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

mod actions;
mod audit;
mod edr;
mod hmac;
mod nonce;

/// Replay protection window. Requests with `approved_at` more than this
/// many seconds away from the current time (in either direction) are
/// rejected. The bound is symmetric so we also reject far-future
/// timestamps caused by client clock skew or deliberate manipulation.
const REPLAY_WINDOW_SECONDS: i64 = 30;

/// Maximum requests served per rolling one-second window across the whole
/// proxy. Generous enough not to interfere with a real incident burst, low
/// enough to shed an unauthenticated flood before it reaches HMAC verification
/// (a CPU-DoS vector even though forgery is infeasible). Global rather than
/// per-IP so it needs no client-IP plumbing through the two serve paths.
const RATE_LIMIT_PER_SECOND: u32 = 100;

/// Application state. Cloned into every request handler, so anything
/// inside must be cheap to clone (Arc-wrapped data, primitives, etc.).
#[derive(Clone)]
struct AppState {
    /// Shared HMAC-SHA256 secret. Provided via env var; never logged.
    hmac_secret: String,

    /// Path to the append-only JSONL audit log.
    audit_log_path: String,

    /// If true, action execution is skipped and the EDR is never called.
    /// Default for development and CI. Production must set DRY_RUN=false
    /// **explicitly** (see `main` - we err on the side of safe-by-default).
    dry_run: bool,

    /// In-process dedup store keyed by `request_id`. See `nonce.rs`.
    nonces: nonce::NonceStore,

    /// EDR client implementation. Currently dispatches to the configured
    /// EDR (CrowdStrike Falcon for v0.1-alpha pilot). See `edr.rs`.
    edr: edr::EdrClient,

    /// SHA-256 hash chain state for the audit log. Seeded at boot from
    /// the last entry on disk so restarts do not break the chain.
    /// See `audit::ChainState`.
    audit_chain: audit::ChainState,

    /// Fixed-window global rate-limit counter: (window start, count in
    /// window). Shared across handlers to shed request floods. See
    /// `rate_limit` / `rate_check`.
    rate: Arc<Mutex<(Instant, u32)>>,
}

/// Pure rate-limit decision over a fixed one-second window. Extracted from
/// the middleware so it is unit-testable without spinning up the server.
/// Mutates the window in place and returns true if the request is allowed.
fn rate_check(window: &mut (Instant, u32), now: Instant, limit: u32) -> bool {
    if now.duration_since(window.0).as_secs() >= 1 {
        *window = (now, 0);
    }
    window.1 += 1;
    window.1 <= limit
}

/// Axum middleware applying the global fixed-window rate limit. Returns
/// 429 Too Many Requests once the per-second budget is exhausted.
async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let allowed = {
        let mut window = state.rate.lock().expect("rate-limit mutex poisoned");
        rate_check(&mut window, Instant::now(), RATE_LIMIT_PER_SECOND)
    };
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(req).await
}

/// Request payload for `POST /execute`.
///
/// **Stability:** This struct is part of the wire contract with the
/// Vyrox Discord bot. Changes here must be coordinated with the Python
/// side (`vyrox/discord_bot/proxy_client.py`).
#[derive(Debug, Deserialize, Serialize)]
struct ExecuteRequest {
    /// Idempotency key. UUID-v4 generated by the Discord bot at the
    /// moment of approval. The proxy uses it to dedupe retries - see
    /// `nonce::NonceStore`. MUST be non-empty.
    request_id: String,

    /// Tenant identifier for multi-tenancy isolation. Tagged on every
    /// audit entry; used to scope `/audit/export`.
    tenant_id: String,

    /// Reference to the original alert that triggered this action.
    /// Carried through to the audit entry for incident correlation.
    alert_id: String,

    /// Type of containment action to execute.
    action_type: actions::ActionType,

    /// Target hostname, device ID, or IP for the action. Format depends
    /// on the EDR - CrowdStrike Falcon uses device IDs (AIDs); a future
    /// SentinelOne integration uses agent UUIDs.
    host: String,

    /// Discord username (or display name) who approved the action.
    /// Recorded in the audit log for accountability.
    approved_by: String,

    /// Unix timestamp (seconds, UTC) of approval. Used for replay
    /// protection in `check_replay_window`. The bot sets this via
    /// `int(time.time())` at button-press time.
    #[serde(rename = "approved_at")]
    approved_at: i64,

    /// Per-tenant EDR credentials, decrypted by the Python orchestrator and
    /// carried inside this signed body (E7). When present and usable the
    /// proxy acts in THIS tenant's EDR with THESE credentials, never the
    /// global env. When absent the proxy falls back to its global env client
    /// (dev/sandbox only). Optional so the dev/CI path needs no credentials.
    ///
    /// Safe to carry here because the whole body is HMAC-signed (a tampered
    /// credential blob fails verification before it is read) and TLS encrypts
    /// it in transit. Never logged.
    #[serde(default)]
    edr_credentials: Option<edr::EdrCredentials>,
}

/// Response payload for `POST /execute` and `POST /rollback`.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ExecuteResponse {
    /// Human-readable status. One of:
    ///   - "executed" - EDR applied the action successfully.
    ///   - "rolled_back" - EDR reversed the action successfully.
    ///   - "dry_run" - DRY_RUN was set; EDR was not called.
    ///   - "replayed" - request was previously processed; cached result returned.
    status: String,

    /// Whether DRY_RUN was active when this response was generated.
    dry_run: bool,
}

/// Query parameters for the audit export endpoint.
#[derive(Debug, Deserialize)]
struct ExportQuery {
    /// Tenant ID filter. Only audit entries with a matching tenant_id
    /// are returned, ensuring tenant data isolation.
    tenant_id: String,
}

/// Reject if `approved_at` is outside the symmetric replay window.
///
/// The window is symmetric (past *and* future) so that a client whose
/// clock is wildly ahead of ours cannot pre-sign requests for later use.
fn check_replay_window(approved_at: i64) -> Result<(), StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .as_secs() as i64;

    if (now - approved_at).abs() > REPLAY_WINDOW_SECONDS {
        return Err(StatusCode::GONE);
    }
    Ok(())
}

/// `GET /health`
///
/// Liveness probe for orchestrators (Kubernetes, Fly.io, etc.). The body
/// is intentionally trivial - readiness vs liveness distinctions are not
/// useful for a single-binary stateless service of this size.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

/// `POST /execute` - apply a containment action.
///
/// Thin wrapper over `run_action` with `ActionDirection::Apply`. See
/// `run_action` for the full step-numbered lifecycle.
async fn execute(
    state: State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    run_action(state, headers, body, actions::ActionDirection::Apply).await
}

/// `POST /rollback` - reverse a containment action (un-isolate, restore
/// network).
///
/// Identical security path to `/execute`: same HMAC verification, same
/// replay window, same nonce dedup, same audit-before-act ordering, same
/// DRY_RUN short-circuit. The only difference is `ActionDirection::Reverse`,
/// which makes the EDR client call the inverse vendor action, and the audit
/// `action_type` is prefixed `ROLLBACK_` so the trail names what was undone.
async fn rollback(
    state: State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    run_action(state, headers, body, actions::ActionDirection::Reverse).await
}

/// Shared lifecycle for `/execute` and `/rollback` - the security-critical
/// entry point.
///
/// See module-level docs for the request lifecycle. The handler is
/// deliberately verbose and step-numbered to mirror the ordering the
/// security review depends on; do not reorder steps without re-reading
/// the threat model.
async fn run_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
    direction: actions::ActionDirection,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    // ─ Step 1: Verify HMAC on the RAW bytes we received. ──────────────
    //
    // Critical correctness point: we verify against `body` (the exact
    // bytes from the wire), NOT against a re-serialized version of a
    // parsed struct. The latter would re-order JSON keys and break
    // signatures, and historically did - that bug masked the real
    // verification because differing serialization made every signature
    // mismatch indistinguishable from an invalid signature.
    let signature = headers
        .get("X-Vyrox-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Err(err) = hmac::verify_signature(state.hmac_secret.as_bytes(), &body, signature) {
        warn!(error = %err, "signature verification failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // ─ Step 2: Parse JSON. ────────────────────────────────────────────
    //
    // Only after the HMAC passes do we trust the body enough to parse
    // it. Parsing before verification would expose any serde panic /
    // pathological input to unauthenticated callers.
    let payload: ExecuteRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    if payload.request_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // ─ Step 3: Replay window. ─────────────────────────────────────────
    check_replay_window(payload.approved_at)?;

    // ─ Step 4: Nonce dedup. ───────────────────────────────────────────
    //
    // Claim the request_id. If we've already finished this request,
    // return the cached response - the client gets a byte-identical
    // result and the EDR is NOT called again.
    match state.nonces.claim_or_replay(&payload.request_id) {
        nonce::Outcome::FreshClaim => { /* fall through to execution */ }
        nonce::Outcome::AlreadyExecuted {
            cached_response_json,
        } => {
            info!(request_id = %payload.request_id, "replaying cached response");
            let cached: ExecuteResponse = serde_json::from_str(&cached_response_json)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Ok(Json(ExecuteResponse {
                status: "replayed".to_string(),
                dry_run: cached.dry_run,
            }));
        }
        nonce::Outcome::InFlight => {
            warn!(request_id = %payload.request_id, "duplicate while in-flight");
            return Err(StatusCode::CONFLICT);
        }
    }

    // ─ Step 5: Audit BEFORE acting. ───────────────────────────────────
    //
    // Even if the EDR call panics, crashes the process, or hangs, we
    // have a durable record of the intent on disk. The audit log is the
    // ground truth, not the EDR's response. The action_type is prefixed
    // ROLLBACK_ on a reverse so the trail records what was undone.
    let audit_action = match direction {
        actions::ActionDirection::Apply => format!("{:?}", payload.action_type),
        actions::ActionDirection::Reverse => format!("ROLLBACK_{:?}", payload.action_type),
    };
    let entry = audit::build_entry(
        payload.tenant_id.clone(),
        audit_action,
        payload.host.clone(),
        payload.approved_by.clone(),
        state.dry_run,
    );
    if let Err(err) = audit::append_audit(&state.audit_log_path, &state.audit_chain, entry).await {
        // Audit log failure is fatal - we don't proceed without a
        // forensic trail. Release the nonce so the bot can retry once
        // the underlying issue (disk full, perm error) is fixed.
        warn!(error = %err, "audit write failed; releasing nonce claim");
        state.nonces.release_claim(&payload.request_id);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ─ Step 6: Execute (or skip in DRY_RUN). ──────────────────────────
    //
    // DRY_RUN short-circuits the EDR call for BOTH directions exactly the
    // same way: no live call leaves the proxy in dev (Rule #5).
    let success_status = match direction {
        actions::ActionDirection::Apply => "executed",
        actions::ActionDirection::Reverse => "rolled_back",
    };
    let response = if state.dry_run {
        info!(
            request_id = %payload.request_id,
            tenant_id = %payload.tenant_id,
            action = ?payload.action_type,
            ?direction,
            host = %payload.host,
            "DRY_RUN: skipping EDR call"
        );
        ExecuteResponse {
            status: "dry_run".to_string(),
            dry_run: true,
        }
    } else {
        // Real dispatch. The per-tenant credentials on the request take
        // precedence over the global env fallback (E7). The EDR client
        // owns its own retries, timeouts, and error mapping. Any error is
        // a 502 Bad Gateway and we release the nonce so a retry runs on
        // fresh state.
        match edr::dispatch(
            &state.edr,
            payload.edr_credentials.as_ref(),
            payload.action_type,
            direction,
            &payload.host,
        )
        .await
        {
            Ok(()) => ExecuteResponse {
                status: success_status.to_string(),
                dry_run: false,
            },
            Err(err) => {
                warn!(
                    request_id = %payload.request_id,
                    ?direction,
                    error = %err,
                    "EDR dispatch failed; releasing nonce claim"
                );
                state.nonces.release_claim(&payload.request_id);
                return Err(StatusCode::BAD_GATEWAY);
            }
        }
    };

    // ─ Step 7: Cache the response for future retries. ────────────────
    //
    // Serialize once so subsequent replays return byte-identical output.
    let cache_payload =
        serde_json::to_string(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .nonces
        .record_response(&payload.request_id, cache_payload);

    Ok(Json(response))
}

/// `GET /audit/export?tenant_id=<id>`
///
/// Returns all audit entries for the requested tenant. Filtering happens
/// server-side so a misbehaving caller cannot read another tenant's
/// entries by post-processing.
///
/// ## Authentication
///
/// The export endpoint is HMAC-protected. Callers must send:
///
///   `X-Vyrox-Signature: sha256=<hex>` - HMAC-SHA256 of the canonical
///                                       message `"<tenant_id>:<ts>"`.
///   `X-Vyrox-Timestamp: <unix_seconds>` - UTC unix timestamp used in
///                                         the canonical message.
///
/// The signature is computed over `format!("{tenant_id}:{timestamp}")`
/// using the same `VYROX_HMAC_SECRET` that protects `/execute`. The
/// timestamp is rejected if it falls outside the replay window. This
/// gives `/audit/export` parity with `/execute` for auth + replay
/// protection without needing a request body.
///
/// Without this check, anyone who reaches the proxy can dump any
/// tenant's containment history just by passing a tenant_id query
/// parameter. That was the SEV-2 leak we shipped in the original
/// pilot build; this commit closes it.
///
/// ## Production notes
///
/// This reads the entire log into memory on every call. Fine for
/// pilot scale (10s of MB max); for SaaS we'll move to a streaming
/// JSONL response and per-tenant log shards.
async fn export_audit(
    State(state): State<AppState>,
    Query(query): Query<ExportQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<audit::AuditEntry>>, StatusCode> {
    // ─ Step 1: Pull and validate the auth headers. ─────────────────
    let signature = headers
        .get("X-Vyrox-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let timestamp_str = headers
        .get("X-Vyrox-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let timestamp: i64 = timestamp_str
        .trim()
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ─ Step 2: Replay window. ─────────────────────────────────────
    //
    // Same window as /execute. A stale `X-Vyrox-Timestamp` cannot be
    // used to repeatedly fetch a tenant's audit log forever.
    check_replay_window(timestamp).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ─ Step 3: HMAC verify on the canonical message. ──────────────
    //
    // The canonical message is `"<tenant_id>:<timestamp>"`. It binds
    // the request to (a) the tenant being queried, so an attacker
    // cannot swap the tenant_id query parameter without invalidating
    // the signature, and (b) the timestamp, so a replay outside the
    // window is impossible.
    let canonical = format!("{}:{}", query.tenant_id, timestamp);
    if let Err(err) = hmac::verify_signature(
        state.hmac_secret.as_bytes(),
        canonical.as_bytes(),
        signature,
    ) {
        warn!(error = %err, "audit export signature verification failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // ─ Step 4: Actual export. ─────────────────────────────────────
    let entries = audit::read_audit_logs(&state.audit_log_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let filtered: Vec<audit::AuditEntry> = entries
        .into_iter()
        .filter(|e| e.tenant_id == query.tenant_id)
        .collect();

    Ok(Json(filtered))
}

/// Parse a boolean-ish environment variable.
///
/// We accept the common spellings ("true"/"false"/"1"/"0"/"yes"/"no")
/// because operators write env files by hand and a strict parser leads
/// to silently-wrong DRY_RUN settings (which is exactly the failure mode
/// we cannot tolerate).
fn parse_bool_env(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            other => {
                warn!(
                    var = name,
                    value = other,
                    default,
                    "unrecognized boolean env var; using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Assemble the Axum router with the rate-limit layer over a given state.
///
/// Extracted from `main` so the full HTTP path (HMAC, replay, nonce, audit,
/// DRY_RUN, dispatch) is exercisable in-process by the test suite via
/// `tower::ServiceExt::oneshot`, with no real socket and no live EDR.
fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/execute", post(execute))
        .route("/rollback", post(rollback))
        .route("/audit/export", get(export_audit))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .with_state(state)
}

/// Initialize Sentry error tracking (T31).
///
/// Reads `SENTRY_DSN` from the environment. When it is unset or empty the
/// returned guard is a no-op, sentry::init with an empty DSN installs no
/// transport and sends nothing, so dev/CI and unconfigured deploys are
/// unaffected. The caller MUST hold the returned guard for the life of the
/// process; dropping it flushes and shuts the client down.
fn init_sentry() -> sentry::ClientInitGuard {
    let dsn = env::var("SENTRY_DSN").unwrap_or_default();
    if dsn.trim().is_empty() {
        info!("Sentry disabled (SENTRY_DSN not set)");
    } else {
        info!("Sentry enabled");
    }
    let environment = env::var("SENTRY_ENVIRONMENT").ok().map(Into::into);
    sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment,
            ..Default::default()
        },
    ))
}

/// Application entry point.
fn main() {
    // Sentry must be initialized BEFORE the async runtime so panics in the
    // runtime setup are captured, and the guard must outlive the server.
    // sentry::init returns a no-op guard when SENTRY_DSN is unset.
    let _sentry_guard = init_sentry();
    run();
}

/// Build the Tokio runtime and run the server. Split out from `main` so the
/// Sentry guard in `main` outlives the entire async lifetime.
#[tokio::main]
async fn run() {
    tracing_subscriber::fmt::init();

    // Required: secret used for HMAC verification. We refuse to start
    // without it - running with a default would silently disable auth.
    let hmac_secret = env::var("VYROX_HMAC_SECRET").expect("VYROX_HMAC_SECRET must be set");
    if hmac_secret.len() < 32 {
        warn!("VYROX_HMAC_SECRET is shorter than 32 bytes; consider rotating to a longer key");
    }

    let audit_log_path = env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "./audit.jsonl".to_string());

    // Safe-by-default: DRY_RUN is TRUE unless explicitly turned off.
    // Operators who want real execution must opt in.
    let dry_run = parse_bool_env("DRY_RUN", true);

    // Initialize the EDR client. See `edr.rs` for the configuration
    // contract - secrets are read from env there, not here.
    let edr = edr::EdrClient::from_env();

    // Seed the audit chain from the existing log file so a restart
    // continues the chain instead of branching from genesis. New
    // deployments with no log file fall through to the genesis hash.
    let audit_chain = audit::ChainState::from_file(&audit_log_path).await;

    let state = AppState {
        hmac_secret,
        audit_log_path,
        dry_run,
        nonces: nonce::NonceStore::new(),
        edr,
        audit_chain,
        rate: Arc::new(Mutex::new((Instant::now(), 0))),
    };

    let app = build_router(state);

    // Bind address is configurable so the container/host can override
    // it. Default :3000 keeps backward compatibility with existing
    // deployment configs.
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    // TLS is enabled when both BOTH cert and key paths are set. This is
    // an all-or-nothing toggle - partial config (one set, one missing)
    // is an operator error and we fail loudly so it's not mistaken for
    // a working TLS deploy.
    let tls_cert = env::var("TLS_CERT_PATH").ok();
    let tls_key = env::var("TLS_KEY_PATH").ok();

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            info!(addr = %bind_addr, tls = true, dry_run, "vyrox proxy starting (TLS)");
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .expect("failed to load TLS cert/key - check TLS_CERT_PATH and TLS_KEY_PATH");
            axum_server::bind_rustls(bind_addr.parse().expect("invalid BIND_ADDR"), config)
                .serve(app.into_make_service())
                .await
                .expect("server should run");
        }
        (None, None) => {
            // Plain HTTP. Intended for deployment behind a TLS-terminating
            // reverse proxy (Cloudflare Tunnel, Caddy, nginx). NOT for direct
            // internet exposure: /execute carries hostnames + action types and
            // /audit/export returns a tenant's full containment history, all in
            // cleartext over plain HTTP (signed for integrity, NOT encrypted).
            //
            // Fail CLOSED on a non-loopback plaintext bind unless the operator
            // explicitly acknowledges with ALLOW_INSECURE=true. A warning was
            // not enough - a misconfigured deploy would happily serve cleartext
            // containment traffic to the internet (CSO finding #7). Insecure
            // modes must be opted into, never reached by omission.
            let allow_insecure = parse_bool_env("ALLOW_INSECURE", false);
            let is_loopback = bind_addr
                .parse::<std::net::SocketAddr>()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false);
            if !is_loopback && !allow_insecure {
                panic!(
                    "refusing to bind plain HTTP to a non-loopback address ({bind_addr}): \
                     containment + audit traffic would be cleartext. Set \
                     TLS_CERT_PATH/TLS_KEY_PATH for direct TLS, bind 127.0.0.1 behind a \
                     TLS-terminating reverse proxy, or set ALLOW_INSECURE=true to \
                     acknowledge the risk explicitly."
                );
            }
            info!(addr = %bind_addr, tls = false, dry_run, "vyrox proxy starting (plain HTTP)");
            let listener = tokio::net::TcpListener::bind(&bind_addr)
                .await
                .expect("bind should work");
            axum::serve(listener, app).await.expect("server should run");
        }
        _ => panic!("TLS_CERT_PATH and TLS_KEY_PATH must both be set, or both unset"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_check_allows_up_to_limit_then_blocks() {
        let now = Instant::now();
        let mut window = (now, 0u32);
        assert!(rate_check(&mut window, now, 3));
        assert!(rate_check(&mut window, now, 3));
        assert!(rate_check(&mut window, now, 3));
        // The 4th request in the same one-second window is rejected.
        assert!(!rate_check(&mut window, now, 3));
    }

    #[test]
    fn rate_check_resets_after_one_second_window() {
        let start = Instant::now();
        let mut window = (start, 0u32);
        assert!(rate_check(&mut window, start, 1));
        assert!(!rate_check(&mut window, start, 1)); // 2nd in window blocked
                                                     // A request more than a second later opens a fresh window.
        let later = start + Duration::from_secs(2);
        assert!(rate_check(&mut window, later, 1));
    }

    // ── HTTP-level lifecycle tests for /execute and /rollback ──────────
    //
    // These drive the assembled router in-process with `tower::oneshot`,
    // so the whole path (HMAC, replay window, nonce, audit-before-act,
    // DRY_RUN short-circuit, EDR dispatch) is exercised with no socket and
    // no live EDR.

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-secret-32-bytes-long-padding!!";

    /// Build a router with a known secret and a temp audit log. `dry_run`
    /// toggles the EDR short-circuit; `edr` is the global fallback client.
    fn test_router(dry_run: bool, edr: edr::EdrClient) -> (Router, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl").to_str().unwrap().to_string();
        let state = AppState {
            hmac_secret: TEST_SECRET.to_string(),
            audit_log_path,
            dry_run,
            nonces: nonce::NonceStore::new(),
            edr,
            audit_chain: audit::ChainState::genesis(),
            rate: Arc::new(Mutex::new((Instant::now(), 0))),
        };
        (build_router(state), dir)
    }

    /// Sign a body the way the Python proxy_client does: HMAC-SHA256 hex
    /// with the `sha256=` prefix.
    fn sign_body(body: &[u8]) -> String {
        // `::hmac` (the external crate) is fully qualified to disambiguate
        // from the proxy's own `crate::hmac` module.
        use ::hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(TEST_SECRET.as_bytes()).expect("mac");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Build a request body for `/execute` or `/rollback`. `creds` is the
    /// optional per-tenant credential blob.
    fn action_body(request_id: &str, creds: Option<serde_json::Value>) -> Vec<u8> {
        let mut obj = json!({
            "request_id": request_id,
            "tenant_id": "tenant-a",
            "alert_id": "alert-1",
            "action_type": "HOST_ISOLATION",
            "host": "device-1",
            "approved_by": "analyst-jane",
            "approved_at": now_secs(),
        });
        if let Some(c) = creds {
            obj["edr_credentials"] = c;
        }
        serde_json::to_vec(&obj).expect("serialize")
    }

    async fn post(router: &Router, path: &str, body: Vec<u8>, sig: Option<String>) -> StatusCode {
        let mut builder = Request::builder().method("POST").uri(path);
        if let Some(s) = sig {
            builder = builder.header("X-Vyrox-Signature", s);
        }
        let req = builder.body(Body::from(body)).expect("request");
        router
            .clone()
            .oneshot(req)
            .await
            .expect("router response")
            .status()
    }

    async fn post_json(
        router: &Router,
        path: &str,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let sig = sign_body(&body);
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("X-Vyrox-Signature", sig)
            .body(Body::from(body))
            .expect("request");
        let resp = router.clone().oneshot(req).await.expect("router response");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn execute_dry_run_short_circuits_and_audits() {
        let (router, dir) = test_router(true, edr::EdrClient::Noop);
        let body = action_body("req-exec-dry", None);
        let (status, value) = post_json(&router, "/execute", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "dry_run");
        assert_eq!(value["dry_run"], true);
        // Audit-before-act: the entry is on disk even though no EDR ran.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("HostIsolation"));
    }

    #[tokio::test]
    async fn rollback_dry_run_short_circuits_and_audits_rollback_action() {
        let (router, dir) = test_router(true, edr::EdrClient::Noop);
        let body = action_body("req-rb-dry", None);
        let (status, value) = post_json(&router, "/rollback", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "dry_run");
        assert_eq!(value["dry_run"], true);
        // The audit entry names the rollback so the trail shows what was undone.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("ROLLBACK_HostIsolation"));
    }

    #[tokio::test]
    async fn rollback_real_dispatch_succeeds_via_noop_fallback() {
        // dry_run=false but the global fallback is Noop, so the rollback
        // dispatch path runs to completion and reports rolled_back.
        let (router, _dir) = test_router(false, edr::EdrClient::Noop);
        let body = action_body("req-rb-live", None);
        let (status, value) = post_json(&router, "/rollback", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "rolled_back");
        assert_eq!(value["dry_run"], false);
    }

    #[tokio::test]
    async fn per_tenant_creds_used_over_global_env_fallback() {
        // Global fallback is Noop (would succeed). The request carries a
        // CrowdStrike credential pointed at an unreachable base_url, so a
        // 502 proves the proxy used the PER-TENANT credential, not the
        // global Noop fallback (which would have returned 200).
        let (router, _dir) = test_router(false, edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-id",
            "api_secret": "tenant-a-secret",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body("req-creds", Some(creds));
        let status = {
            let sig = sign_body(&body);
            post(&router, "/execute", body, Some(sig)).await
        };
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "per-tenant cred should be used and fail transport, not fall back to noop"
        );
    }

    #[tokio::test]
    async fn missing_signature_is_unauthorized() {
        let (router, _dir) = test_router(true, edr::EdrClient::Noop);
        let body = action_body("req-nosig", None);
        let status = post(&router, "/execute", body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bad_signature_is_unauthorized_on_rollback() {
        let (router, _dir) = test_router(true, edr::EdrClient::Noop);
        let body = action_body("req-badsig", None);
        let status = post(&router, "/rollback", body, Some("sha256=deadbeef".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stale_timestamp_is_rejected_by_replay_window() {
        let (router, _dir) = test_router(true, edr::EdrClient::Noop);
        // approved_at far in the past: outside the 30s replay window.
        let mut obj = json!({
            "request_id": "req-stale",
            "tenant_id": "tenant-a",
            "alert_id": "alert-1",
            "action_type": "HOST_ISOLATION",
            "host": "device-1",
            "approved_by": "analyst-jane",
            "approved_at": now_secs() - 3600,
        });
        obj["edr_credentials"] = serde_json::Value::Null;
        let body = serde_json::to_vec(&obj).unwrap();
        let sig = sign_body(&body);
        let status = post(&router, "/rollback", body, Some(sig)).await;
        assert_eq!(status, StatusCode::GONE);
    }

    #[tokio::test]
    async fn duplicate_request_id_is_replayed_not_re_executed() {
        let (router, _dir) = test_router(true, edr::EdrClient::Noop);
        let body = action_body("req-dup", None);
        let (s1, v1) = post_json(&router, "/execute", body.clone()).await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(v1["status"], "dry_run");
        // Same request_id again: cached replay, not a second execution.
        let (s2, v2) = post_json(&router, "/execute", body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["status"], "replayed");
    }

    // ── End-to-end: execute then rollback against a stateful mock EDR ──────
    //
    // The tests above short-circuit the EDR (DRY_RUN) or point a per-tenant
    // credential at an unreachable address. This one proves the WHOLE loop:
    // the proxy verifies the request, audits, and drives a REAL EDR call (over
    // loopback HTTP) that isolates a host on /execute and un-isolates it on
    // /rollback. A tiny stateful mock EDR implements the exact CrowdStrike
    // contract the proxy speaks (the same shapes the Python mock_edr serves),
    // so the assertion is end-to-end: host isolated, then un-isolated, both
    // audited. No live CrowdStrike, no network beyond loopback. Hermetic.

    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    /// Shared isolation state for the in-test mock EDR: host -> isolated?
    type MockEdrState = Arc<StdMutex<HashMap<String, bool>>>;

    /// Start a stateful CrowdStrike-shaped mock EDR on a loopback port.
    ///
    /// Implements the two endpoints the proxy's `CrowdstrikeClient` calls:
    /// `POST /oauth2/token` (returns a bearer) and
    /// `POST /devices/entities/devices-actions/v2?action_name=contain|lift_containment`
    /// (flips the host's isolation bit and records it). Returns the base URL to
    /// point a per-tenant credential at, and the shared state to assert on.
    async fn spawn_mock_edr() -> (String, MockEdrState) {
        let state: MockEdrState = Arc::new(StdMutex::new(HashMap::new()));

        async fn token() -> Json<serde_json::Value> {
            Json(json!({
                "access_token": "mock-bearer",
                "token_type": "bearer",
                "expires_in": 1800,
            }))
        }

        async fn device_action(
            State(state): State<MockEdrState>,
            Query(params): Query<HashMap<String, String>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            // Presence-check the bearer so a proxy that forgot to authenticate
            // is caught, exactly like the Python mock.
            let authed = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_ascii_lowercase().starts_with("bearer "))
                .unwrap_or(false);
            if !authed {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let action_name = params.get("action_name").cloned().unwrap_or_default();
            let isolated = match action_name.as_str() {
                "contain" => true,
                "lift_containment" => false,
                _ => return Err(StatusCode::BAD_REQUEST),
            };
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            let ids = parsed
                .get("ids")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if ids.is_empty() {
                return Err(StatusCode::BAD_REQUEST);
            }
            {
                let mut guard = state.lock().expect("mock edr state poisoned");
                for id in &ids {
                    if let Some(host) = id.as_str() {
                        guard.insert(host.to_string(), isolated);
                    }
                }
            }
            Ok(Json(json!({ "resources": [], "errors": [] })))
        }

        // Fully-qualify the routing `post`: this test module has a local
        // `post` helper (the request driver) that would otherwise shadow it.
        let app = Router::new()
            .route("/oauth2/token", axum::routing::post(token))
            .route(
                "/devices/entities/devices-actions/v2",
                axum::routing::post(device_action),
            )
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock edr");
        let addr: SocketAddr = listener.local_addr().expect("mock edr addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock edr serve");
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn execute_then_rollback_isolates_then_unisolates_against_mock_edr() {
        let (edr_base, edr_state) = spawn_mock_edr().await;
        // Real dispatch (dry_run=false); the global fallback is Noop and must
        // NOT be used because the per-tenant credential is present and usable.
        let (router, dir) = test_router(false, edr::EdrClient::Noop);

        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-client-id",
            "api_secret": "tenant-a-client-secret",
            "base_url": edr_base,
        });
        let host = "device-1";

        // 1) Execute -> the mock EDR should mark the host isolated.
        let exec_body = action_body("e2e-exec", Some(creds.clone()));
        let (exec_status, exec_value) = post_json(&router, "/execute", exec_body).await;
        assert_eq!(exec_status, StatusCode::OK);
        assert_eq!(exec_value["status"], "executed");
        assert_eq!(exec_value["dry_run"], false);
        assert_eq!(
            edr_state.lock().unwrap().get(host).copied(),
            Some(true),
            "host should be isolated after /execute"
        );

        // 2) Rollback -> the mock EDR should mark the host un-isolated.
        let rb_body = action_body("e2e-rb", Some(creds));
        let (rb_status, rb_value) = post_json(&router, "/rollback", rb_body).await;
        assert_eq!(rb_status, StatusCode::OK);
        assert_eq!(rb_value["status"], "rolled_back");
        assert_eq!(rb_value["dry_run"], false);
        assert_eq!(
            edr_state.lock().unwrap().get(host).copied(),
            Some(false),
            "host should be un-isolated after /rollback"
        );

        // 3) Both actions are audited: the execute names HostIsolation, the
        //    rollback names ROLLBACK_HostIsolation.
        let entries = audit::read_audit_logs(dir.path().join("audit.jsonl").to_str().unwrap())
            .await
            .expect("read audit log");
        let actions: Vec<&str> = entries.iter().map(|e| e.action_type.as_str()).collect();
        assert!(
            actions.contains(&"HostIsolation"),
            "execute must be audited, saw {actions:?}"
        );
        assert!(
            actions.contains(&"ROLLBACK_HostIsolation"),
            "rollback must be audited, saw {actions:?}"
        );
    }

    #[tokio::test]
    async fn rollback_against_failing_edr_is_bad_gateway() {
        // A mock EDR that always 500s on the action endpoint. The proxy must
        // surface that as 502 BAD_GATEWAY (the Python side maps that to a
        // paged ROLLBACK_FAILED), never a silent success.
        let state: MockEdrState = Arc::new(StdMutex::new(HashMap::new()));

        async fn token() -> Json<serde_json::Value> {
            Json(json!({"access_token": "t", "expires_in": 1800}))
        }
        async fn always_500() -> StatusCode {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        let app = Router::new()
            .route("/oauth2/token", axum::routing::post(token))
            .route(
                "/devices/entities/devices-actions/v2",
                axum::routing::post(always_500),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let (router, _dir) = test_router(false, edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": format!("http://{addr}"),
        });
        let body = action_body("e2e-rb-fail", Some(creds));
        let sig = sign_body(&body);
        let status = post(&router, "/rollback", body, Some(sig)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }
}
