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
//! 7. **Execute via the configured EDR client.** The proxy ALWAYS dispatches
//!    to the EDR (the global DRY_RUN kill-switch is gone). For a demo/mock
//!    tenant the request carries `simulated=true` and the per-tenant
//!    credential points the same real call at the bundled mock EDR, so the
//!    execute/rollback path runs end to end against a simulated fleet.
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
//! nonce, and audit BEFORE acting identically.

use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

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

/// Total number of `/rollback` dispatch attempts before we give up and emit the
/// terminal `ROLLBACK_FAILED` state (RB-01 / T64). One initial try plus
/// `ROLLBACK_MAX_ATTEMPTS - 1` retries. Small on purpose: contain/lift are
/// idempotent, so a couple of quick retries absorb a transient EDR 5xx or a
/// brief network blip without turning the request handler into a long-running
/// pager. A persistent failure still surfaces promptly to the human pager.
const ROLLBACK_MAX_ATTEMPTS: u32 = 3;

/// Base backoff between `/rollback` retry attempts. The delay grows linearly
/// with the attempt number (attempt 1 waits one base, attempt 2 waits two), a
/// gentle backoff that stays well inside a normal request timeout. Kept short
/// because a human approved this rollback and is waiting on the result.
const ROLLBACK_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// Minimum acceptable length (bytes) of the proxy signing secret (PRX-08).
/// 32 bytes = 256 bits, matching the HMAC-SHA256 output width. A shorter secret
/// weakens the one check that authorizes a real EDR action, so it fails closed
/// in production.
const MIN_SECRET_LEN: usize = 32;

/// Default per-tenant request budget per one-second window. One tenant's
/// containment burst can consume at most this many slots per second; once it
/// is exhausted, only THAT tenant gets 429s. Every other tenant's
/// human-approved actions are unaffected, which is the whole point of moving
/// off the old single global counter. Override with `RATE_LIMIT_PER_TENANT`.
const DEFAULT_RATE_LIMIT_PER_TENANT: u32 = 50;

/// Default global safety ceiling per one-second window across ALL tenants and
/// all unauthenticated callers. This is the flood shield: it runs in the
/// middleware before HMAC verification, so an unauthenticated flood is shed
/// before it can burn CPU on signature checks (a CPU-DoS vector even though
/// forgery is infeasible). Sized well above the sum of normal per-tenant
/// traffic so it never clips legitimate load; it only trips under an actual
/// flood. Override with `RATE_LIMIT_GLOBAL`.
const DEFAULT_RATE_LIMIT_GLOBAL: u32 = 1_000;

/// Env var names for the two configurable rate limits.
const RATE_LIMIT_PER_TENANT_VAR: &str = "RATE_LIMIT_PER_TENANT";
const RATE_LIMIT_GLOBAL_VAR: &str = "RATE_LIMIT_GLOBAL";

/// Upper bound on the number of distinct tenants tracked at once. Each tracked
/// tenant costs one small fixed-window counter. The cap stops an attacker who
/// forges (un-signed, so they 401 anyway, but the per-tenant check runs only
/// after HMAC, so in practice only real tenants reach it) or a pathological
/// fan-out from growing the map without bound. At the cap we drop the oldest
/// idle windows. 50k comfortably exceeds the 50+ partner target with headroom.
const MAX_TRACKED_TENANTS: usize = 50_000;

/// Application state. Cloned into every request handler, so anything
/// inside must be cheap to clone (Arc-wrapped data, primitives, etc.).
#[derive(Clone)]
struct AppState {
    /// Shared HMAC-SHA256 secret. Provided via env var; never logged.
    hmac_secret: String,

    /// Path to the append-only JSONL audit log.
    audit_log_path: String,

    /// In-process dedup store keyed by `request_id`. See `nonce.rs`.
    nonces: nonce::NonceStore,

    /// EDR client implementation. Currently dispatches to the configured
    /// EDR (CrowdStrike Falcon for v0.1-alpha pilot). See `edr.rs`.
    edr: edr::EdrClient,

    /// SHA-256 hash chain state for the audit log. Seeded at boot from
    /// the last entry on disk so restarts do not break the chain.
    /// See `audit::ChainState`.
    audit_chain: audit::ChainState,

    /// Two-tier rate limiter: a per-tenant fixed-window budget (checked after
    /// the signed request is parsed, so one tenant's burst only 429s that
    /// tenant) plus a global safety ceiling (checked in the middleware before
    /// HMAC, to shed unauthenticated floods). See `RateLimiter`.
    rate: RateLimiter,
}

/// Two-tier fixed-window rate limiter.
///
/// The original limiter was a single global counter, so one tenant's
/// containment burst 429'd every other tenant's human-approved actions. This
/// splits the budget:
///
/// - **Per tenant** (`per_tenant` limit): keyed by `tenant_id` from the signed
///   request body, so tenant A burning its budget never blocks tenant B. This
///   check necessarily runs AFTER HMAC verification and JSON parsing, because
///   that is the first point the tenant_id is known and trustworthy.
/// - **Global** (`global` limit): a single counter across every request,
///   checked in the middleware BEFORE HMAC so an unauthenticated flood is shed
///   cheaply. Sized high so it only trips under an actual flood, never on
///   normal multi-tenant load.
///
/// Both windows are one second. Limits are read from the environment once at
/// construction. The per-tenant counters live in a `DashMap` so concurrent
/// tenants do not contend on a single lock; the map is capped
/// (`MAX_TRACKED_TENANTS`) and sheds the oldest idle windows when full.
#[derive(Clone)]
struct RateLimiter {
    /// Per-tenant request budget per one-second window.
    per_tenant_limit: u32,
    /// Global request ceiling per one-second window across all callers.
    global_limit: u32,
    /// Per-tenant fixed-window counters: tenant_id -> (window start, count).
    tenants: Arc<DashMap<String, (Instant, u32)>>,
    /// The single global fixed-window counter: (window start, count).
    global: Arc<Mutex<(Instant, u32)>>,
}

impl RateLimiter {
    /// Build the limiter, reading both limits from the environment.
    ///
    /// `RATE_LIMIT_PER_TENANT` and `RATE_LIMIT_GLOBAL` override the defaults; a
    /// missing, blank, or zero value falls back to the default (a zero limit
    /// would wedge the proxy, so it is rejected as a misconfiguration).
    fn from_env() -> Self {
        let per_tenant_limit =
            parse_u32_env(RATE_LIMIT_PER_TENANT_VAR, DEFAULT_RATE_LIMIT_PER_TENANT);
        let global_limit = parse_u32_env(RATE_LIMIT_GLOBAL_VAR, DEFAULT_RATE_LIMIT_GLOBAL);
        info!(
            per_tenant_limit,
            global_limit, "rate limiter: per-tenant + global ceiling (per one-second window)"
        );
        Self {
            per_tenant_limit,
            global_limit,
            tenants: Arc::new(DashMap::new()),
            global: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }

    /// Check (and consume) one slot against the global ceiling.
    ///
    /// Runs in the middleware before HMAC verification. Returns true if the
    /// request is allowed.
    fn check_global(&self, now: Instant) -> bool {
        // PRX-03: recover from a poisoned lock instead of panicking. This mutex
        // runs in the pre-HMAC middleware on EVERY request; a single panic
        // while holding it would poison it and turn every subsequent /execute
        // into a panic, a total DoS of containment. The guarded data is a
        // plain (Instant, u32) fixed-window counter with no invariant a panic
        // could have left half-updated, so taking the inner value on poison is
        // safe: at worst one window's count is slightly off, which self-heals
        // on the next one-second rollover.
        let mut window = self
            .global
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rate_check(&mut window, now, self.global_limit)
    }

    /// Check (and consume) one slot against a single tenant's budget.
    ///
    /// Runs after the signed body is parsed. Each tenant gets an independent
    /// fixed-window counter, so one tenant exhausting its budget returns 429
    /// only for that tenant. Returns true if the request is allowed.
    fn check_tenant(&self, tenant_id: &str, now: Instant) -> bool {
        // Bound the number of tracked tenants. Only sweep at the cap so the
        // O(N) eviction amortizes; under the 50+ partner target this never
        // runs, it only defends against a pathological tenant-id fan-out.
        if self.tenants.len() >= MAX_TRACKED_TENANTS {
            self.evict_idle_tenants(now);
        }

        let mut window = self
            .tenants
            .entry(tenant_id.to_string())
            .or_insert_with(|| (now, 0));
        rate_check(&mut window, now, self.per_tenant_limit)
    }

    /// Drop tenant windows that have rolled over (idle for at least one full
    /// window), bringing the map back under the cap. Collect keys first so we
    /// never hold an iteration guard and a write guard on the same shard.
    fn evict_idle_tenants(&self, now: Instant) {
        let stale: Vec<String> = self
            .tenants
            .iter()
            .filter(|e| now.duration_since(e.value().0).as_secs() >= 1)
            .map(|e| e.key().clone())
            .collect();
        for key in stale {
            // Remove only if still idle, so we never evict a tenant that just
            // opened a fresh window between the scan and the remove.
            self.tenants.remove_if(&key, |_, (start, _)| {
                now.duration_since(*start).as_secs() >= 1
            });
        }
    }
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

/// Axum middleware applying the GLOBAL safety ceiling before HMAC. Returns
/// 429 Too Many Requests once the global per-second budget is exhausted. The
/// per-tenant budget is enforced separately inside `run_action`, after the
/// signed body is parsed and the tenant_id is known.
async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !state.rate.check_global(Instant::now()) {
        return (StatusCode::TOO_MANY_REQUESTS, "global rate limit exceeded").into_response();
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

    /// Honesty label: this action targets a demo/mock fleet, not a real
    /// customer EDR. The Python side sets it from the tenant's `is_demo` flag
    /// and signs it inside the body (tamper-evident, not a spoofable header).
    ///
    /// It does NOT change proxy behavior: the proxy still performs the real EDR
    /// call. For a demo tenant the per-tenant credential points that real call
    /// at the bundled mock EDR (vyrox/mock_edr), so the whole execute/rollback
    /// path runs end to end against a simulated fleet. `simulated=true` records
    /// in the audit + response that the action targeted a demo/mock fleet.
    ///
    /// `#[serde(default)]` keeps this backward-compatible: an older Python
    /// caller that omits the field signs a body the proxy still accepts, and
    /// the flag defaults to false (treated as a real fleet).
    #[serde(default)]
    simulated: bool,
}

/// Response payload for `POST /execute` and `POST /rollback`.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ExecuteResponse {
    /// Human-readable status. One of:
    ///   - "executed" - EDR applied the action successfully.
    ///   - "rolled_back" - EDR reversed the action successfully.
    ///   - "replayed" - request was previously processed; cached result returned.
    status: String,

    /// Honesty label echoed back from the request: whether this action
    /// targeted a demo/mock fleet. It does NOT mean the EDR call was skipped,
    /// the call always runs; for a demo tenant it lands on the bundled mock
    /// EDR. Mirrors the `simulated` field recorded in the audit entry.
    simulated: bool,
}

/// Distinct status string the `/rollback` path returns when every internal
/// retry is exhausted and the lift may not have taken effect. The Python pager
/// keys on this exact string (and the `502` status) to page a human for manual
/// reconciliation, distinct from a transient blip that the bounded retry
/// already recovered from (RB-01 / T64).
const ROLLBACK_FAILED_STATUS: &str = "rollback_failed";

/// Distinct status string the `/execute` and `/rollback` paths return when an
/// EDR transport failure is AMBIGUOUS about whether the action ran (timeout
/// after send, lost response). The nonce is deliberately NOT released, so a
/// blind retry cannot double-execute; the Python side keys on this to surface a
/// human-reconciliation task instead of an auto-retry (CNT-05 / T63).
const NEEDS_RECONCILIATION_STATUS: &str = "needs_reconciliation";

/// Body for the error responses (`/execute` ambiguous, `/rollback` terminal
/// failure). Distinct from `ExecuteResponse` so the Python caller can pattern
/// match on `status` without it ever being confused with a success body. The
/// `may_have_executed` flag is the load-bearing field: true means the EDR may
/// already have acted and the nonce was held back to block a double-execute.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ActionFailureResponse {
    /// One of `ROLLBACK_FAILED_STATUS` or `NEEDS_RECONCILIATION_STATUS`.
    status: String,

    /// True when the action MAY have executed (ambiguous transport failure or
    /// a rollback whose final attempt was ambiguous). When true the nonce was
    /// NOT released, so a naive retry will be deduped rather than re-run.
    may_have_executed: bool,

    /// Honesty label echoed from the request (demo/mock fleet), same meaning
    /// as on `ExecuteResponse`.
    simulated: bool,
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
async fn execute(state: State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    run_action(state, headers, body, actions::ActionDirection::Apply).await
}

/// `POST /rollback` - reverse a containment action (un-isolate, restore
/// network).
///
/// Identical security path to `/execute`: same HMAC verification, same
/// replay window, same nonce dedup, same audit-before-act ordering. The only
/// difference is `ActionDirection::Reverse`, which makes the EDR client call
/// the inverse vendor action, and the audit `action_type` is prefixed
/// `ROLLBACK_` so the trail names what was undone.
async fn rollback(state: State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    run_action(state, headers, body, actions::ActionDirection::Reverse).await
}

/// Release a nonce claim, logging (not propagating) a store error.
///
/// Release is best-effort: it only runs on an error path where we are already
/// returning a failure status. If the release itself fails (Redis blip) the
/// stale in-flight key simply TTLs out on its own, so there is nothing useful
/// to do with the error but record it.
async fn release_nonce(nonces: &nonce::NonceStore, request_id: &str) {
    if let Err(err) = nonces.release_claim(request_id).await {
        warn!(error = %err, request_id, "failed to release nonce claim (will TTL out)");
    }
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
) -> Response {
    // ─ Step 1: Verify HMAC on the RAW bytes we received. ──────────────
    //
    // Critical correctness point: we verify against `body` (the exact
    // bytes from the wire), NOT against a re-serialized version of a
    // parsed struct. The latter would re-order JSON keys and break
    // signatures, and historically did - that bug masked the real
    // verification because differing serialization made every signature
    // mismatch indistinguishable from an invalid signature.
    let Some(signature) = headers
        .get("X-Vyrox-Signature")
        .and_then(|v| v.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if let Err(err) = hmac::verify_signature(state.hmac_secret.as_bytes(), &body, signature) {
        warn!(error = %err, "signature verification failed");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // ─ Step 2: Parse JSON. ────────────────────────────────────────────
    //
    // Only after the HMAC passes do we trust the body enough to parse
    // it. Parsing before verification would expose any serde panic /
    // pathological input to unauthenticated callers.
    let Ok(payload) = serde_json::from_slice::<ExecuteRequest>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    if payload.request_id.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // ─ Step 2b: Per-tenant rate limit. ────────────────────────────────
    //
    // Enforced here, after the body is parsed, because this is the first
    // point the tenant_id is known and trustworthy (it is inside the
    // HMAC-signed body). Keyed by tenant_id so one tenant's containment burst
    // returns 429 only for THAT tenant, never for another tenant's
    // human-approved action. The global ceiling already ran in the middleware.
    if !state.rate.check_tenant(&payload.tenant_id, Instant::now()) {
        warn!(
            tenant_id = %payload.tenant_id,
            "per-tenant rate limit exceeded"
        );
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // ─ Step 3: Replay window. ─────────────────────────────────────────
    if let Err(status) = check_replay_window(payload.approved_at) {
        return status.into_response();
    }

    // ─ Step 4: Nonce dedup. ───────────────────────────────────────────
    //
    // Claim the request_id. If we've already finished this request,
    // return the cached response - the client gets a byte-identical
    // result and the EDR is NOT called again. A nonce-store transport
    // error (Redis down) fails CLOSED with a 503: skipping dedup could
    // double-execute a containment, so we refuse rather than guess.
    let claim = match state.nonces.claim_or_replay(&payload.request_id).await {
        Ok(claim) => claim,
        Err(err) => {
            warn!(error = %err, "nonce store unavailable; failing closed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    match claim {
        nonce::Outcome::FreshClaim => { /* fall through to execution */ }
        nonce::Outcome::AlreadyExecuted {
            cached_response_json,
        } => {
            info!(request_id = %payload.request_id, "replaying cached response");
            let Ok(cached) = serde_json::from_str::<ExecuteResponse>(&cached_response_json) else {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            return Json(ExecuteResponse {
                status: "replayed".to_string(),
                simulated: cached.simulated,
            })
            .into_response();
        }
        nonce::Outcome::InFlight => {
            warn!(request_id = %payload.request_id, "duplicate while in-flight");
            return StatusCode::CONFLICT.into_response();
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
        audit_action.clone(),
        payload.host.clone(),
        payload.approved_by.clone(),
        payload.simulated,
    );
    if let Err(err) = audit::append_audit(&state.audit_log_path, &state.audit_chain, entry).await {
        // Audit log failure is fatal - we don't proceed without a
        // forensic trail. Release the nonce so the bot can retry once
        // the underlying issue (disk full, perm error) is fixed.
        warn!(error = %err, "audit write failed; releasing nonce claim");
        release_nonce(&state.nonces, &payload.request_id).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // ─ Step 6: Execute. ───────────────────────────────────────────────
    //
    // The proxy ALWAYS dispatches to the configured EDR. The global DRY_RUN
    // kill-switch is gone: there is no longer a path that audits an intent and
    // then quietly declines to act on it. For a demo/mock tenant the request
    // carries `simulated=true` and the per-tenant credential points this same
    // real call at the bundled mock EDR, so the execute/rollback path runs end
    // to end against a simulated fleet. `simulated` is an honesty label on the
    // audit + response only; it never gates the call.
    //
    // The supportability check runs first, on purpose: an action the provider
    // cannot faithfully perform (e.g. PROCESS_KILL on CrowdStrike) must fail
    // loudly with a 501 before any network call, never be silently substituted.
    // The check is pure (action-name mappers only, no client, no network).
    //
    // contain/lift are idempotent, so the Reverse (/rollback) direction wraps
    // the dispatch in a small bounded retry (RB-01 / T64): a transient EDR 5xx
    // or a brief blip is absorbed in-proxy rather than immediately paging a
    // human. /execute keeps a single attempt; a failed isolate is retried at the
    // approval layer, and silently re-isolating is not something we want this
    // handler doing on its own.
    let success_status = match direction {
        actions::ActionDirection::Apply => "executed",
        actions::ActionDirection::Reverse => "rolled_back",
    };

    // Pure supportability pre-flight: reject an action the provider cannot
    // faithfully perform BEFORE any network call (and before the retry loop), so
    // an unsupported action is one 501 with zero EDR calls, never retried and
    // never silently substituted. `dispatch` re-checks internally, this keeps
    // the decision explicit at the handler and out of the retry path.
    if let Err(err) = edr::check_supported(
        &state.edr,
        payload.edr_credentials.as_ref(),
        payload.action_type,
        direction,
    ) {
        return handle_dispatch_failure(&state, &payload, direction, &audit_action, err).await;
    }

    let dispatch_result = dispatch_with_retry(&state, &payload, direction).await;

    match dispatch_result {
        Ok(()) => { /* fall through to success caching + 200 */ }
        Err(err) => {
            return handle_dispatch_failure(&state, &payload, direction, &audit_action, err).await;
        }
    }

    let response = ExecuteResponse {
        status: success_status.to_string(),
        simulated: payload.simulated,
    };

    // ─ Step 7: Cache the response for future retries. ────────────────
    //
    // Serialize once so subsequent replays return byte-identical output.
    // The action already happened and was audited; if caching the response
    // fails (Redis blip) we log and still return success rather than 500 a
    // completed containment. The worst case is that a retry re-executes an
    // idempotent EDR action, which the replay window and EDR idempotency both
    // bound, and which is strictly safer than reporting a failure for an action
    // that succeeded.
    let Ok(cache_payload) = serde_json::to_string(&response) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Err(err) = state
        .nonces
        .record_response(&payload.request_id, cache_payload)
        .await
    {
        warn!(
            request_id = %payload.request_id,
            error = %err,
            "failed to cache response in nonce store; action already executed and audited"
        );
    }

    Json(response).into_response()
}

/// Dispatch the action to the EDR, retrying transient failures for the
/// idempotent `/rollback` (Reverse) direction (RB-01 / T64).
///
/// `/execute` (Apply) dispatches exactly once: re-isolating a host on a blip is
/// the approval layer's call, not this handler's. `/rollback` (Reverse) retries
/// up to `ROLLBACK_MAX_ATTEMPTS` times because contain/lift are idempotent and a
/// transient EDR 5xx or a momentary blip should not page a human when one more
/// quick attempt would succeed.
///
/// What is retried: only genuinely transient, retry-safe failures, a server
/// 5xx, or an ambiguous transport error where the lift may not have landed.
/// What is NOT retried: a pre-send failure (returned immediately so the nonce
/// can be released and the request retried cleanly from scratch), a 4xx client
/// error (a bad request will not get better by repeating it), and `Unsupported`
/// / `Misconfigured` (decided before any call). The supportability check that
/// rejects unsupported actions is pure and runs inside `dispatch`, so an
/// unsupported action still fails on the first attempt with zero calls.
async fn dispatch_with_retry(
    state: &AppState,
    payload: &ExecuteRequest,
    direction: actions::ActionDirection,
) -> Result<(), edr::EdrError> {
    let max_attempts = match direction {
        actions::ActionDirection::Apply => 1,
        actions::ActionDirection::Reverse => ROLLBACK_MAX_ATTEMPTS,
    };

    let mut attempt = 0;
    loop {
        attempt += 1;
        let result = edr::dispatch(
            &state.edr,
            payload.edr_credentials.as_ref(),
            payload.action_type,
            direction,
            &payload.host,
        )
        .await;

        let err = match result {
            Ok(()) => return Ok(()),
            Err(err) => err,
        };

        // Stop early when another attempt cannot help: we are out of attempts,
        // the failure is not retry-safe (4xx, pre-send, unsupported,
        // misconfigured), or this is the Apply direction (max_attempts == 1).
        if attempt >= max_attempts || !is_retryable(&err) {
            return Err(err);
        }

        warn!(
            request_id = %payload.request_id,
            ?direction,
            attempt,
            max_attempts,
            error = %err,
            "rollback dispatch failed transiently; retrying after backoff"
        );
        // Linear backoff: attempt 1 waits one base, attempt 2 waits two. Short
        // by design, a human approved this rollback and is waiting on it.
        tokio::time::sleep(ROLLBACK_RETRY_BACKOFF * attempt).await;
    }
}

/// Whether a dispatch error is worth another attempt for an idempotent action.
///
/// Only a server 5xx and an ambiguous transport error qualify: both can be a
/// momentary condition that a quick retry of an idempotent contain/lift clears.
/// A 4xx will not improve on repeat, and a pre-send / unsupported /
/// misconfigured error is handled by releasing the nonce (pre-send) or failing
/// loudly, never by retrying.
fn is_retryable(err: &edr::EdrError) -> bool {
    matches!(
        err,
        edr::EdrError::ServerError { .. } | edr::EdrError::Transport(_)
    )
}

/// Build the failure response (and companion audit entries) after a dispatch
/// failed, honoring the exactly-once and rollback-terminal-state contracts.
///
/// Three distinct outcomes, by error class and direction:
///
/// 1. **Unsupported** (`/execute` or `/rollback`): 501 Not Implemented. The
///    action has no faithful provider mapping; never substituted. The nonce is
///    released, a `FAILED_` entry records the intent did not happen.
/// 2. **Pre-send transport failure** (connection refused, DNS): the action
///    provably did NOT run, so we release the nonce so a retry runs cleanly on
///    fresh state, write a `FAILED_` entry, and return 502.
/// 3. **Ambiguous transport failure** (timeout after send, lost response): the
///    action MAY have run. We do NOT release the nonce, a blind retry would risk
///    a double-execute. We write a distinct `NEEDS_RECONCILIATION_` audit entry
///    making clear the action may have executed, and return a body the Python
///    pager keys on (`needs_reconciliation`, `may_have_executed: true`).
/// 4. **Rollback that exhausted its retries** (`/rollback` only, server 5xx or
///    ambiguous after `ROLLBACK_MAX_ATTEMPTS`): a distinct terminal
///    `ROLLBACK_FAILED` audit entry + `rollback_failed` response body the pager
///    keys on. The nonce is released for a 5xx (the lift did not land, a fresh
///    retry is safe) and held for an ambiguous final attempt (it may have).
///
/// Audit-before-act ordering is preserved: the intent entry was already written
/// in step 5, and every companion entry here is written BEFORE this returns.
async fn handle_dispatch_failure(
    state: &AppState,
    payload: &ExecuteRequest,
    direction: actions::ActionDirection,
    audit_action: &str,
    err: edr::EdrError,
) -> Response {
    let is_rollback = matches!(direction, actions::ActionDirection::Reverse);

    // An action with no faithful provider mapping is 501 and is never retried or
    // reconciled: nothing ran, release the nonce and audit the non-event.
    if matches!(err, edr::EdrError::Unsupported { .. }) {
        warn!(
            request_id = %payload.request_id,
            ?direction,
            error = %err,
            "EDR action unsupported; auditing non-event and releasing nonce"
        );
        write_failure_entry(state, payload, &format!("FAILED_{audit_action}")).await;
        release_nonce(&state.nonces, &payload.request_id).await;
        return StatusCode::NOT_IMPLEMENTED.into_response();
    }

    // Did the side effect provably NOT happen? Drives both the nonce-release
    // decision (release only when safe) and the audit/response wording.
    let safe_to_release = err.side_effect_definitely_did_not_happen();

    // The terminal label distinguishes a rollback that exhausted its retries
    // (the pager treats it as needing human attention) from a one-shot execute
    // failure, and an ambiguous "may have executed" from a clean non-event.
    let (audit_label, response): (String, Response) = if is_rollback {
        // /rollback exhausted ROLLBACK_MAX_ATTEMPTS (or hit a non-retryable
        // error). Emit the distinct terminal ROLLBACK_FAILED state the Python
        // pager keys on, rather than a generic 502 it has to infer from.
        warn!(
            request_id = %payload.request_id,
            error = %err,
            safe_to_release,
            "rollback failed after internal retries; emitting terminal ROLLBACK_FAILED"
        );
        let body = ActionFailureResponse {
            status: ROLLBACK_FAILED_STATUS.to_string(),
            may_have_executed: !safe_to_release,
            simulated: payload.simulated,
        };
        (
            format!("ROLLBACK_FAILED_{audit_action}"),
            (StatusCode::BAD_GATEWAY, Json(body)).into_response(),
        )
    } else if safe_to_release {
        // /execute, pre-send: the isolate provably did not run. A FAILED_ entry
        // records the non-event; the nonce is released below so a clean retry
        // can run on fresh state. Plain 502.
        warn!(
            request_id = %payload.request_id,
            error = %err,
            "EDR execute failed pre-send; auditing non-event and releasing nonce"
        );
        (
            format!("FAILED_{audit_action}"),
            StatusCode::BAD_GATEWAY.into_response(),
        )
    } else {
        // /execute, ambiguous: the isolate MAY have run. Hold the nonce so a
        // blind retry cannot double-execute, and surface a distinct
        // needs-reconciliation state with may_have_executed:true.
        warn!(
            request_id = %payload.request_id,
            error = %err,
            "EDR execute transport failure is ambiguous; holding nonce and flagging for \
             human reconciliation (the action MAY have executed)"
        );
        let body = ActionFailureResponse {
            status: NEEDS_RECONCILIATION_STATUS.to_string(),
            may_have_executed: true,
            simulated: payload.simulated,
        };
        (
            format!("NEEDS_RECONCILIATION_{audit_action}"),
            (StatusCode::BAD_GATEWAY, Json(body)).into_response(),
        )
    };

    // Audit the outcome BEFORE returning. The step-5 entry recorded the intent;
    // without this companion the trail would read as if the action happened (or
    // as if it cleanly failed when it may not have).
    write_failure_entry(state, payload, &audit_label).await;

    // Release the nonce ONLY when the side effect provably did not happen. This
    // is the exactly-once invariant: an ambiguous failure keeps the claim so the
    // next retry is deduped (replayed/InFlight), never re-executed. nonce.rs
    // warns to release only when sure the side effect did not happen.
    if safe_to_release {
        release_nonce(&state.nonces, &payload.request_id).await;
    } else {
        warn!(
            request_id = %payload.request_id,
            "NOT releasing nonce: the EDR action may have executed; a retry must be deduped, \
             not re-run, until a human reconciles"
        );
    }

    response
}

/// Append a companion failure/outcome audit entry (best-effort).
///
/// The action-type label (`FAILED_...`, `ROLLBACK_FAILED_...`,
/// `NEEDS_RECONCILIATION_...`) names what happened so the trail never reads as a
/// clean success. A write error is logged, not swallowed into a fake success and
/// not propagated, the caller is already returning a failure status.
async fn write_failure_entry(state: &AppState, payload: &ExecuteRequest, audit_label: &str) {
    let entry = audit::build_entry(
        payload.tenant_id.clone(),
        audit_label.to_string(),
        payload.host.clone(),
        payload.approved_by.clone(),
        payload.simulated,
    );
    if let Err(audit_err) =
        audit::append_audit(&state.audit_log_path, &state.audit_chain, entry).await
    {
        warn!(
            request_id = %payload.request_id,
            error = %audit_err,
            audit_label,
            "failed to write failure audit entry"
        );
    }
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
/// The log is read by streaming it line-by-line and keeping only this tenant's
/// entries (`audit::read_tenant_entries_streaming`, PRX-04), so the whole file
/// is never resident in RAM and concurrent exports do not multiply into an
/// unbounded-memory amplifier. The matched slice is still materialised because
/// the response is a JSON array; bounding it further (pagination, per-tenant log
/// shards) is the next step as pack volume grows.
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
    //
    // Stream the log line-by-line and keep only this tenant's entries (PRX-04),
    // so the whole file is never read into RAM. The tenant filter is applied
    // inside the streaming read, not after, so a misbehaving caller cannot read
    // another tenant's entries by post-processing.
    let filtered = audit::read_tenant_entries_streaming(&state.audit_log_path, &query.tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(filtered))
}

/// Parse a positive `u32` environment variable.
///
/// A missing, blank, unparseable, or zero value falls back to `default`. Zero
/// is rejected because a zero rate limit would wedge the proxy (every request
/// 429s), which is never the intended config; we warn and use the default so a
/// fat-fingered limit fails safe rather than taking the proxy down.
fn parse_u32_env(name: &str, default: u32) -> u32 {
    match env::var(name) {
        Ok(value) => match value.trim().parse::<u32>() {
            Ok(parsed) if parsed > 0 => parsed,
            Ok(_) => {
                warn!(var = name, "rate limit of 0 is invalid; using default");
                default
            }
            Err(_) => {
                warn!(
                    var = name,
                    value = value.trim(),
                    default,
                    "unparseable rate-limit env var; using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Parse a boolean-ish environment variable.
///
/// We accept the common spellings ("true"/"false"/"1"/"0"/"yes"/"no")
/// because operators write env files by hand and a strict parser leads
/// to silently-wrong safety toggles (e.g. `ALLOW_INSECURE`,
/// `VYROX_PROXY_ALLOW_EPHEMERAL_NONCE`), which is exactly the failure mode we
/// cannot tolerate.
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

/// Resolve the HMAC secret used to verify proxy requests (SRF-07).
///
/// Mirrors the Python signer's `effective_proxy_secret()`: prefer the
/// dedicated `VYROX_PROXY_SECRET`, fall back to the shared `VYROX_HMAC_SECRET`.
/// The two sides must resolve to the same value or every signed call 401s.
///
/// In production we fail closed if neither is set: serving with no secret would
/// silently disable authentication on the one component that talks to a real
/// EDR. In dev/CI a missing secret is still fatal (there is nothing to verify
/// against), but the message is the same; we never invent a default.
///
/// HKDF / per-tenant key derivation is deliberately NOT done this wave, to keep
/// the Rust and Python sides in lockstep.
fn resolve_proxy_secret(is_production: bool) -> String {
    let dedicated = env::var("VYROX_PROXY_SECRET").unwrap_or_default();
    if !dedicated.trim().is_empty() {
        return dedicated;
    }
    let shared = env::var("VYROX_HMAC_SECRET").unwrap_or_default();
    if !shared.trim().is_empty() {
        warn!(
            "VYROX_PROXY_SECRET is not set; verifying containment proxy requests with the shared \
             VYROX_HMAC_SECRET (dev/test fallback). Set a dedicated VYROX_PROXY_SECRET so a leak \
             of the inter-service secret cannot authorize an EDR action."
        );
        return shared;
    }
    if is_production {
        panic!(
            "neither VYROX_PROXY_SECRET nor VYROX_HMAC_SECRET is set in production: refusing to \
             start the containment proxy with no signing secret, which would disable \
             authentication on every /execute and /rollback. Set VYROX_PROXY_SECRET (SRF-07)."
        );
    }
    panic!(
        "neither VYROX_PROXY_SECRET nor VYROX_HMAC_SECRET is set: the proxy has no secret to \
         verify request signatures against. Set VYROX_PROXY_SECRET (preferred) or \
         VYROX_HMAC_SECRET."
    );
}

/// Decide whether a signing secret is too weak to serve production traffic
/// (PRX-08).
///
/// Returns `Some(message)` when the boot must fail closed: a secret shorter than
/// `MIN_SECRET_LEN` (256 bits) in production. Returns `None` otherwise, including
/// for a short secret in dev/CI (the caller warns instead). Extracted as a pure
/// function so the fail-closed rule is unit-testable without booting the async
/// runtime, mirroring `resolve_proxy_secret`.
fn secret_strength_error(secret: &str, is_production: bool) -> Option<String> {
    if is_production && secret.len() < MIN_SECRET_LEN {
        return Some(format!(
            "proxy signing secret is only {} bytes; refusing to start in production with a \
             signing secret shorter than {MIN_SECRET_LEN} bytes (256 bits), which weakens the \
             HMAC that authorizes every EDR action. Set a >= {MIN_SECRET_LEN}-byte \
             VYROX_PROXY_SECRET (PRX-08).",
            secret.len()
        ));
    }
    None
}

/// Decide whether this is a production boot.
///
/// The proxy has no first-class environment field, so it reads the same
/// `VYROX_ENV` / `ENVIRONMENT` the rest of the platform sets (`VYROX_ENV` wins).
/// Only an explicit "production" (case-insensitive) counts; anything else, or
/// nothing, is treated as dev/CI. We fail closed only when we are SURE the boot
/// is production, so a forgotten env var never silently relaxes a prod gate in
/// the other direction: it just means the explicit dev opt-ins remain required.
fn is_production_env() -> bool {
    for var in ["VYROX_ENV", "ENVIRONMENT"] {
        if let Ok(value) = env::var(var) {
            if value.trim().eq_ignore_ascii_case("production") {
                return true;
            }
        }
    }
    false
}

/// Assemble the Axum router with the rate-limit layer over a given state.
///
/// Extracted from `main` so the full HTTP path (HMAC, replay, nonce, audit,
/// dispatch) is exercisable in-process by the test suite via
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

/// Marker the EDR error Display strings put right before the raw EDR response
/// body, e.g. `edr returned client error 403: {body}`. The scrubber redacts
/// everything after this marker so a captured EDR body never reaches Sentry.
const EDR_BODY_MARKER: &str = " error ";
/// What the scrubbed EDR body is replaced with in any outbound Sentry event.
const EDR_BODY_REDACTED: &str = "[edr-body-redacted]";

/// Initialize Sentry error tracking (T31).
///
/// Reads `SENTRY_DSN` from the environment. When it is unset or empty the
/// returned guard is a no-op, sentry::init with an empty DSN installs no
/// transport and sends nothing, so dev/CI and unconfigured deploys are
/// unaffected. The caller MUST hold the returned guard for the life of the
/// process; dropping it flushes and shuts the client down.
///
/// PRX-05: a `before_send` hook scrubs the raw EDR response body out of every
/// outbound event. Today the EDR body lives only in an `EdrError` that is
/// mapped to an HTTP status and never returned to the client or sent to Sentry
/// (the `warn!` path is not wired to Sentry). This is defense in depth: if the
/// body ever reaches an event, via a panic carrying the error string or a
/// future tracing-to-Sentry bridge, it is redacted before egress. The Python
/// `scrub.py` does not cover this Rust path, so the proxy owns it.
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
            before_send: Some(Arc::new(|mut event| {
                scrub_edr_body_from_event(&mut event);
                Some(event)
            })),
            ..Default::default()
        },
    ))
}

/// Redact any captured EDR response body from a Sentry event before it leaves
/// the process (PRX-05).
///
/// The EDR body only ever appears in an `EdrError` Display string of the form
/// `edr returned {client|server} error {status}: {body}`. We redact the message
/// and every exception value at the first `EDR_BODY_MARKER` occurrence, keeping
/// the diagnostic prefix (which error, which status) but dropping the raw body.
fn scrub_edr_body_from_event(event: &mut sentry::protocol::Event) {
    if let Some(message) = event.message.take() {
        event.message = Some(redact_after_edr_marker(&message));
    }
    for exception in &mut event.exception.values {
        if let Some(value) = &exception.value {
            exception.value = Some(redact_after_edr_marker(value));
        }
    }
}

/// If `text` looks like an EDR error string (`... error {status}: {body}`),
/// return it with everything after the status colon replaced by a redaction
/// marker. Otherwise return it unchanged. Pure so it is unit-testable.
fn redact_after_edr_marker(text: &str) -> String {
    if !text.contains("edr returned") || !text.contains(EDR_BODY_MARKER) {
        return text.to_string();
    }
    // The body follows the first ": " after the status code. Keep the prefix
    // (which error, which status), redact the rest.
    match text.find(": ") {
        Some(idx) => format!("{}: {EDR_BODY_REDACTED}", &text[..idx]),
        None => text.to_string(),
    }
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

    // Decide once whether this is a production boot. Drives the two fail-closed
    // gates below (proxy secret, nonce durability). The proxy has no first-class
    // environment field, so we read the same `VYROX_ENV`/`ENVIRONMENT` the rest
    // of the platform uses; absent or any non-"production" value is treated as
    // dev/CI (the safe direction is to fail closed only when we are SURE it is
    // production).
    let is_production = is_production_env();

    // Secret used to verify the HMAC on every /execute, /rollback and
    // /audit/export request. Mirrors the Python signer's
    // `effective_proxy_secret()` (SRF-07): prefer the dedicated
    // `VYROX_PROXY_SECRET`, fall back to the shared `VYROX_HMAC_SECRET`. The two
    // sides MUST resolve to the same value or every call 401s. In production we
    // fail closed if neither is set; running with a default would silently
    // disable auth. (Per-tenant HKDF key derivation is deferred to keep this
    // wave in lockstep with the Python side.)
    let hmac_secret = resolve_proxy_secret(is_production);
    // PRX-08: fail closed on a weak signing secret in production (see
    // `secret_strength_error`). The check is extracted so it is unit-testable
    // without booting the runtime; here we turn its verdict into a panic (prod)
    // or a warning (dev/CI).
    match secret_strength_error(&hmac_secret, is_production) {
        Some(message) => panic!("{message}"),
        None if hmac_secret.len() < MIN_SECRET_LEN => {
            warn!(
                secret_len = hmac_secret.len(),
                min_len = MIN_SECRET_LEN,
                "proxy signing secret is shorter than the minimum; this fails closed in \
                 production. Rotate to a longer key (PRX-08)."
            );
        }
        None => {}
    }

    let audit_log_path = env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "./audit.jsonl".to_string());

    // Initialize the EDR client. See `edr.rs` for the configuration
    // contract - secrets are read from env there, not here.
    let edr = edr::EdrClient::from_env();

    // Seed the audit chain from the existing log file so a restart
    // continues the chain instead of branching from genesis. New
    // deployments with no log file fall through to the genesis hash.
    let audit_chain = audit::ChainState::from_file(&audit_log_path).await;

    // Build the nonce/replay store. Prefers a durable Redis backend
    // (NONCE_REDIS_URL/REDIS_URL); falls back to in-memory only when no Redis
    // URL is set. A configured-but-unreachable Redis is a hard boot error, the
    // operator asked for durability and we will not silently downgrade to the
    // restart-double-execute path.
    //
    // PRX-01: a MISSING Redis URL is itself fatal in production (and in any
    // boot that has not explicitly opted into the ephemeral store). The
    // in-memory store loses its dedup table on restart, so a retry crossing a
    // restart re-executes containment (double-isolate / double-bill). We refuse
    // to serve that path by omission; dev/CI must opt in with
    // `VYROX_PROXY_ALLOW_EPHEMERAL_NONCE=1`, mirroring how `ALLOW_INSECURE`
    // gates the cleartext bind. This is enforced BEFORE we build the store so a
    // missing URL never reaches the in-memory fallback unacknowledged.
    let allow_ephemeral_nonce = parse_bool_env("VYROX_PROXY_ALLOW_EPHEMERAL_NONCE", false);
    if nonce::redis_url_configured() {
        // A URL is set: from_env returns Redis or hard-errors on an unreachable
        // one. Either is correct, never the silent in-memory downgrade.
    } else if is_production {
        panic!(
            "no Redis URL configured (NONCE_REDIS_URL/REDIS_URL) in production: the in-memory \
             nonce store loses its dedup table on restart, so a retry crossing a restart can \
             double-execute a containment action. Configure Redis for durable, shared dedup. \
             (VYROX_PROXY_ALLOW_EPHEMERAL_NONCE is ignored in production.)"
        );
    } else if !allow_ephemeral_nonce {
        panic!(
            "no Redis URL configured (NONCE_REDIS_URL/REDIS_URL): refusing to fall back to the \
             in-memory nonce store, which is not durable and would re-execute a containment on a \
             retry crossing a restart. Set REDIS_URL, or set \
             VYROX_PROXY_ALLOW_EPHEMERAL_NONCE=1 to explicitly accept the ephemeral store for \
             local dev / CI."
        );
    }
    let nonces = nonce::NonceStore::from_env()
        .await
        .expect("failed to connect to the configured Redis nonce store");
    if nonces.is_durable() {
        info!("nonce store backend: redis (durable, shared)");
    } else {
        info!(
            "nonce store backend: in-memory (NOT durable; dev/CI only, explicitly opted in via \
             VYROX_PROXY_ALLOW_EPHEMERAL_NONCE)"
        );
    }

    let state = AppState {
        hmac_secret,
        audit_log_path,
        nonces,
        edr,
        audit_chain,
        rate: RateLimiter::from_env(),
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
            info!(addr = %bind_addr, tls = true, is_production, "vyrox proxy starting (TLS)");
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
            info!(addr = %bind_addr, tls = false, is_production, "vyrox proxy starting (plain HTTP)");
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

    /// Build a limiter with explicit limits for the rate-limiter unit tests.
    fn limiter(per_tenant: u32, global: u32) -> RateLimiter {
        RateLimiter {
            per_tenant_limit: per_tenant,
            global_limit: global,
            tenants: Arc::new(DashMap::new()),
            global: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }

    #[test]
    fn per_tenant_budget_isolates_one_tenant_from_another() {
        // Per-tenant budget of 2, generous global ceiling. Tenant A burns its
        // budget; tenant B is completely unaffected. This is the core property
        // the old single global counter could not provide.
        let rl = limiter(2, 1_000);
        let now = Instant::now();

        assert!(rl.check_tenant("tenant-a", now), "A #1 allowed");
        assert!(rl.check_tenant("tenant-a", now), "A #2 allowed");
        assert!(!rl.check_tenant("tenant-a", now), "A #3 over its budget");

        // Tenant B has its own fresh budget despite A being throttled.
        assert!(rl.check_tenant("tenant-b", now), "B #1 allowed");
        assert!(rl.check_tenant("tenant-b", now), "B #2 allowed");
        assert!(
            !rl.check_tenant("tenant-b", now),
            "B #3 over ITS own budget"
        );
    }

    #[test]
    fn per_tenant_window_resets_after_one_second() {
        let rl = limiter(1, 1_000);
        let start = Instant::now();
        assert!(rl.check_tenant("t", start));
        assert!(!rl.check_tenant("t", start), "2nd in same window blocked");
        let later = start + Duration::from_secs(2);
        assert!(rl.check_tenant("t", later), "fresh window after 1s");
    }

    #[test]
    fn global_ceiling_sheds_flood_across_all_callers() {
        // The global ceiling does not care about tenant identity: it caps total
        // throughput so an unauthenticated flood is shed before HMAC.
        let rl = limiter(1_000, 2);
        let now = Instant::now();
        assert!(rl.check_global(now));
        assert!(rl.check_global(now));
        assert!(!rl.check_global(now), "3rd request over the global ceiling");
    }

    #[test]
    fn tenant_map_is_bounded_and_evicts_idle_windows() {
        // Fill far past a tiny logical view of the cap by using rolled-over
        // windows, then confirm eviction reclaims idle entries. We exercise the
        // eviction helper directly rather than allocating 50k entries.
        let rl = limiter(5, 1_000);
        let t0 = Instant::now();
        for i in 0..1_000 {
            let _ = rl.check_tenant(&format!("tenant-{i}"), t0);
        }
        assert_eq!(rl.tenants.len(), 1_000);
        // One second later every window is idle; eviction clears them all.
        let t1 = t0 + Duration::from_secs(2);
        rl.evict_idle_tenants(t1);
        assert_eq!(rl.tenants.len(), 0, "idle windows should be evicted");
    }

    #[test]
    fn edr_body_scrubber_redacts_body_keeps_prefix() {
        // PRX-05: the raw EDR response body is redacted, the diagnostic prefix
        // (which error, which status) is kept. Mirrors the EdrError Display
        // shapes from edr.rs.
        let client = redact_after_edr_marker(
            "edr returned client error 403: {\"secret\":\"leak\",\"detail\":\"forbidden\"}",
        );
        assert_eq!(client, "edr returned client error 403: [edr-body-redacted]");

        let server = redact_after_edr_marker(
            "edr returned server error 500: stacktrace with hostnames and ids",
        );
        assert_eq!(server, "edr returned server error 500: [edr-body-redacted]");

        // Unrelated messages pass through untouched.
        let unrelated = redact_after_edr_marker("nonce store unavailable; failing closed");
        assert_eq!(unrelated, "nonce store unavailable; failing closed");

        // A transport error has no body to leak and is left alone.
        let transport = redact_after_edr_marker("edr transport error: connection refused");
        assert_eq!(
            transport, "edr transport error: connection refused",
            "transport errors carry no EDR body, leave them readable"
        );
    }

    #[test]
    fn parse_u32_env_rejects_zero_and_garbage() {
        std::env::set_var("VYROX_TEST_RL", "0");
        assert_eq!(parse_u32_env("VYROX_TEST_RL", 50), 50, "zero -> default");
        std::env::set_var("VYROX_TEST_RL", "notnum");
        assert_eq!(parse_u32_env("VYROX_TEST_RL", 50), 50, "garbage -> default");
        std::env::set_var("VYROX_TEST_RL", "7");
        assert_eq!(parse_u32_env("VYROX_TEST_RL", 50), 7, "valid -> parsed");
        std::env::remove_var("VYROX_TEST_RL");
        assert_eq!(parse_u32_env("VYROX_TEST_RL", 50), 50, "unset -> default");
    }

    // ── HTTP-level lifecycle tests for /execute and /rollback ──────────
    //
    // These drive the assembled router in-process with `tower::oneshot`,
    // so the whole path (HMAC, replay window, nonce, audit-before-act,
    // EDR dispatch) is exercised with no socket and no live EDR.

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-secret-32-bytes-long-padding!!";

    /// A rate limiter with generous limits for the default lifecycle tests, so
    /// the rate path never interferes with the security-path assertions.
    fn permissive_limiter() -> RateLimiter {
        RateLimiter {
            per_tenant_limit: 10_000,
            global_limit: 10_000,
            tenants: Arc::new(DashMap::new()),
            global: Arc::new(Mutex::new((Instant::now(), 0))),
        }
    }

    /// Build a router with a known secret and a temp audit log. `edr` is the
    /// global fallback client. The proxy always dispatches to the EDR now (the
    /// DRY_RUN kill-switch is gone), so a `Noop` fallback is what lets a test
    /// exercise the dispatch path without a live EDR; a per-tenant credential
    /// on the request overrides it.
    fn test_router(edr: edr::EdrClient) -> (Router, TempDir) {
        test_router_with_limiter(edr, permissive_limiter())
    }

    /// Same as `test_router` but with a caller-supplied limiter, so the
    /// per-tenant isolation test can set a tiny per-tenant budget.
    fn test_router_with_limiter(edr: edr::EdrClient, rate: RateLimiter) -> (Router, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl").to_str().unwrap().to_string();
        let state = AppState {
            hmac_secret: TEST_SECRET.to_string(),
            audit_log_path,
            nonces: nonce::NonceStore::in_memory(),
            edr,
            audit_chain: audit::ChainState::genesis(),
            rate,
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
    /// optional per-tenant credential blob. Tenant defaults to "tenant-a",
    /// `simulated` defaults to false (real fleet).
    fn action_body(request_id: &str, creds: Option<serde_json::Value>) -> Vec<u8> {
        action_body_for("tenant-a", request_id, creds)
    }

    /// As `action_body` but with an explicit tenant_id, for the per-tenant
    /// rate-limit isolation test.
    fn action_body_for(
        tenant_id: &str,
        request_id: &str,
        creds: Option<serde_json::Value>,
    ) -> Vec<u8> {
        action_body_full(tenant_id, request_id, "HOST_ISOLATION", creds, false)
    }

    /// As `action_body` but with an explicit action_type, for the
    /// unsupported-action tests.
    fn action_body_with_type(
        action_type: &str,
        request_id: &str,
        creds: Option<serde_json::Value>,
    ) -> Vec<u8> {
        action_body_full("tenant-a", request_id, action_type, creds, false)
    }

    /// As `action_body` but with the `simulated` honesty label set, for the
    /// tests that prove the flag round-trips through audit + response.
    fn action_body_simulated(
        request_id: &str,
        creds: Option<serde_json::Value>,
        simulated: bool,
    ) -> Vec<u8> {
        action_body_full("tenant-a", request_id, "HOST_ISOLATION", creds, simulated)
    }

    /// Fully parameterised request-body builder backing the helpers above.
    fn action_body_full(
        tenant_id: &str,
        request_id: &str,
        action_type: &str,
        creds: Option<serde_json::Value>,
        simulated: bool,
    ) -> Vec<u8> {
        let mut obj = json!({
            "request_id": request_id,
            "tenant_id": tenant_id,
            "alert_id": "alert-1",
            "action_type": action_type,
            "host": "device-1",
            "approved_by": "analyst-jane",
            "approved_at": now_secs(),
            "simulated": simulated,
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
    async fn execute_always_dispatches_and_audits() {
        // The global DRY_RUN kill-switch is gone: the proxy ALWAYS dispatches.
        // The Noop fallback stands in for the EDR so the dispatch path runs to
        // completion without a live call, and the status is "executed", never
        // the old "dry_run". The intent is audited before the action.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let body = action_body("req-exec", None);
        let (status, value) = post_json(&router, "/execute", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "executed");
        assert_eq!(value["simulated"], false);
        // Audit-before-act: the entry is on disk.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("HostIsolation"));
    }

    #[tokio::test]
    async fn rollback_always_dispatches_and_audits_rollback_action() {
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let body = action_body("req-rb", None);
        let (status, value) = post_json(&router, "/rollback", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "rolled_back");
        assert_eq!(value["simulated"], false);
        // The audit entry names the rollback so the trail shows what was undone.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("ROLLBACK_HostIsolation"));
    }

    #[tokio::test]
    async fn simulated_flag_round_trips_through_response_and_audit() {
        // A demo/mock tenant sends simulated=true. It does NOT change behavior
        // (the proxy still dispatches, here to the Noop fallback), but it MUST
        // be echoed in the response and recorded in the audit entry so the
        // evidence shows the action targeted a demo/mock fleet.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let body = action_body_simulated("req-sim", None, true);
        let (status, value) = post_json(&router, "/execute", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["status"], "executed", "still dispatches; not skipped");
        assert_eq!(value["simulated"], true, "honesty label echoed back");
        // The audit entry carries simulated:true.
        let entries = audit::read_audit_logs(dir.path().join("audit.jsonl").to_str().unwrap())
            .await
            .expect("read audit log");
        assert!(
            entries
                .iter()
                .any(|e| e.simulated && e.action_type == "HostIsolation"),
            "the audit entry must record simulated=true"
        );
    }

    #[tokio::test]
    async fn per_tenant_creds_used_over_global_env_fallback() {
        // Global fallback is Noop (would succeed). The request carries a
        // CrowdStrike credential pointed at an unreachable base_url, so a
        // 502 proves the proxy used the PER-TENANT credential, not the
        // global Noop fallback (which would have returned 200).
        let (router, _dir) = test_router(edr::EdrClient::Noop);
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
    async fn process_kill_unsupported_returns_501_and_audits_failure() {
        // The operator approves a PROCESS_KILL; CrowdStrike has no faithful
        // mapping for it. The proxy must fail loudly (501, not a silent
        // host quarantine) and the audit trail must record both the intent
        // and the failure. The credential points at an unreachable address:
        // 501 (not 502 Transport) proves no EDR call was even attempted.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-id",
            "api_secret": "tenant-a-secret",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body_with_type("PROCESS_KILL", "req-kill-unsupported", Some(creds));
        let (status, _) = post_json(&router, "/execute", body).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "unsupported action must be 501, never silently substituted"
        );

        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(
            log.contains("\"ProcessKill\""),
            "intent entry must be audited"
        );
        assert!(
            log.contains("\"FAILED_ProcessKill\""),
            "failure entry must be audited so the trail does not read as executed"
        );
    }

    #[tokio::test]
    async fn process_kill_unsupported_on_sentinelone_returns_501() {
        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "sentinelone",
            "api_key": "",
            "api_secret": "tenant-b-token",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body_with_type("PROCESS_KILL", "req-kill-s1", Some(creds));
        let sig = sign_body(&body);
        let status = post(&router, "/execute", body, Some(sig)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn process_kill_unsupported_fails_before_any_edr_call() {
        // An unsupported action must fail loudly with 501 BEFORE any network
        // call, never be silently substituted with a broader containment. The
        // supportability check is pure (action-name mappers only) and the
        // credential points at an unreachable address: 501 (not 502 Transport)
        // proves no EDR call was attempted. This held under the old DRY_RUN
        // gate and must still hold now that the proxy always dispatches.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-id",
            "api_secret": "tenant-a-secret",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body_with_type("PROCESS_KILL", "req-kill-pure", Some(creds));
        let (status, _) = post_json(&router, "/execute", body).await;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "unsupported action must be 501, attempted before any EDR call"
        );
        // Intent entry plus a FAILED_ companion so the trail does not read as
        // a success.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("\"ProcessKill\""));
        assert!(log.contains("\"FAILED_ProcessKill\""));
    }

    #[tokio::test]
    async fn process_kill_unsupported_on_sentinelone_fails_before_any_call() {
        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "sentinelone",
            "api_key": "",
            "api_secret": "tenant-b-token",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body_with_type("PROCESS_KILL", "req-kill-pure-s1", Some(creds));
        let sig = sign_body(&body);
        let status = post(&router, "/execute", body, Some(sig)).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn supported_action_with_creds_always_dispatches_no_short_circuit() {
        // There is no DRY_RUN short-circuit anymore: a supported action with a
        // usable per-tenant credential ALWAYS attempts the real EDR call. The
        // credential points at an unreachable address, so the proxy reaches the
        // transport and returns 502, proving the call left the proxy rather than
        // being skipped. Under the old gate this returned a "dry_run" success
        // with zero network calls; that path is gone.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-id",
            "api_secret": "tenant-a-secret",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body("req-iso-creds", Some(creds));
        let sig = sign_body(&body);
        let status = post(&router, "/execute", body, Some(sig)).await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "supported action must attempt the real call, not short-circuit"
        );
        // Intent audited, plus a FAILED_ companion for the transport failure.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("\"HostIsolation\""));
        assert!(log.contains("\"FAILED_HostIsolation\""));
    }

    #[tokio::test]
    async fn failed_dispatch_audits_failure_entry() {
        // A reachable-looking but dead EDR (transport failure) must leave a
        // FAILED_ entry next to the intent entry, so an auditor reading the
        // trail can tell intent from outcome.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "tenant-a-id",
            "api_secret": "tenant-a-secret",
            "base_url": "http://127.0.0.1:1",
        });
        let body = action_body("req-iso-fail", Some(creds));
        let sig = sign_body(&body);
        let status = post(&router, "/execute", body, Some(sig)).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("\"HostIsolation\""));
        assert!(log.contains("\"FAILED_HostIsolation\""));
    }

    #[tokio::test]
    async fn missing_signature_is_unauthorized() {
        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let body = action_body("req-nosig", None);
        let status = post(&router, "/execute", body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bad_signature_is_unauthorized_on_rollback() {
        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let body = action_body("req-badsig", None);
        let status = post(&router, "/rollback", body, Some("sha256=deadbeef".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stale_timestamp_is_rejected_by_replay_window() {
        let (router, _dir) = test_router(edr::EdrClient::Noop);
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
        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let body = action_body("req-dup", None);
        let (s1, v1) = post_json(&router, "/execute", body.clone()).await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(v1["status"], "executed");
        // Same request_id again: cached replay, not a second execution.
        let (s2, v2) = post_json(&router, "/execute", body).await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(v2["status"], "replayed");
    }

    #[tokio::test]
    async fn per_tenant_rate_limit_isolates_tenants_over_http() {
        // Drive the FULL router with a tiny per-tenant budget (2) and a high
        // global ceiling. Tenant A bursts past its budget and starts getting
        // 429s; tenant B, sharing the same proxy, is completely unaffected and
        // still gets 200s. This is the end-to-end proof that one tenant's burst
        // no longer 429s another tenant's human-approved actions, the gap the
        // old single global counter left open.
        let limiter = RateLimiter {
            per_tenant_limit: 2,
            global_limit: 10_000,
            tenants: Arc::new(DashMap::new()),
            global: Arc::new(Mutex::new((Instant::now(), 0))),
        };
        let (router, _dir) = test_router_with_limiter(edr::EdrClient::Noop, limiter);

        // Tenant A: first two succeed, the rest are throttled (429).
        let a1 = action_body_for("tenant-a", "a-1", None);
        let a2 = action_body_for("tenant-a", "a-2", None);
        let a3 = action_body_for("tenant-a", "a-3", None);
        let a4 = action_body_for("tenant-a", "a-4", None);
        let (sa1, _) = post_json(&router, "/execute", a1).await;
        let (sa2, _) = post_json(&router, "/execute", a2).await;
        assert_eq!(sa1, StatusCode::OK, "A #1 ok");
        assert_eq!(sa2, StatusCode::OK, "A #2 ok");
        let sa3 = post(&router, "/execute", a3.clone(), Some(sign_body(&a3))).await;
        let sa4 = post(&router, "/execute", a4.clone(), Some(sign_body(&a4))).await;
        assert_eq!(sa3, StatusCode::TOO_MANY_REQUESTS, "A #3 throttled");
        assert_eq!(sa4, StatusCode::TOO_MANY_REQUESTS, "A #4 throttled");

        // Tenant B: untouched by A's burst, both requests succeed.
        let b1 = action_body_for("tenant-b", "b-1", None);
        let b2 = action_body_for("tenant-b", "b-2", None);
        let (sb1, vb1) = post_json(&router, "/execute", b1).await;
        let (sb2, vb2) = post_json(&router, "/execute", b2).await;
        assert_eq!(sb1, StatusCode::OK, "B #1 must be ok despite A's burst");
        assert_eq!(sb2, StatusCode::OK, "B #2 must be ok despite A's burst");
        assert_eq!(vb1["status"], "executed");
        assert_eq!(vb2["status"], "executed");
    }

    // ── End-to-end: execute then rollback against a stateful mock EDR ──────
    //
    // The tests above use the Noop fallback or point a per-tenant credential at
    // an unreachable address. This one proves the WHOLE loop:
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
        // Real dispatch; the global fallback is Noop and must NOT be used
        // because the per-tenant credential is present and usable.
        let (router, dir) = test_router(edr::EdrClient::Noop);

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
        assert_eq!(exec_value["simulated"], false);
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
        assert_eq!(rb_value["simulated"], false);
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
    async fn simulated_demo_tenant_runs_real_path_against_mock_edr() {
        // The milestone case: a demo/mock tenant (simulated=true) is NOT
        // short-circuited. The proxy runs the SAME real execute path, the
        // per-tenant credential just points it at the bundled mock EDR, so the
        // host is genuinely isolated on the (mock) fleet AND the honesty label
        // is echoed in the response and recorded in the audit/evidence. This is
        // the end-to-end replacement for the old DRY_RUN behaviour.
        let (edr_base, edr_state) = spawn_mock_edr().await;
        let (router, dir) = test_router(edr::EdrClient::Noop);

        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "demo-tenant-client-id",
            "api_secret": "demo-tenant-client-secret",
            "base_url": edr_base,
        });
        let host = "device-1";

        let body = action_body_simulated("sim-exec", Some(creds), true);
        let (status, value) = post_json(&router, "/execute", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            value["status"], "executed",
            "the real path ran; not skipped"
        );
        assert_eq!(value["simulated"], true, "honesty label echoed");

        // The mock EDR really isolated the host: the real call ran.
        assert_eq!(
            edr_state.lock().unwrap().get(host).copied(),
            Some(true),
            "the real execute path must have reached the mock EDR"
        );

        // The audit entry records simulated=true so the evidence shows the
        // action targeted a demo/mock fleet.
        let entries = audit::read_audit_logs(dir.path().join("audit.jsonl").to_str().unwrap())
            .await
            .expect("read audit log");
        assert!(
            entries
                .iter()
                .any(|e| e.simulated && e.action_type == "HostIsolation"),
            "the executed entry must carry simulated=true"
        );
    }

    #[tokio::test]
    async fn rollback_against_failing_edr_is_bad_gateway() {
        // A mock EDR that always 500s on the action endpoint. After the bounded
        // internal retries (RB-01 / T64) the proxy must surface that as 502
        // BAD_GATEWAY with the distinct terminal ROLLBACK_FAILED body the Python
        // pager keys on, never a silent success.
        let (router, _dir) = always_500_crowdstrike_router("rb-fail").await;
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": router.1,
        });
        let body = action_body("e2e-rb-fail", Some(creds));
        let (status, value) = post_json(&router.0, "/rollback", body).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            value["status"], ROLLBACK_FAILED_STATUS,
            "a rollback that exhausts its retries must report the terminal ROLLBACK_FAILED state"
        );
    }

    /// Build a router plus a CrowdStrike-shaped mock whose token endpoint works
    /// but whose device-action endpoint ALWAYS 500s, for the RB-01 terminal-state
    /// tests. Returns (router, base_url) and a tempdir kept alive by the caller.
    async fn always_500_crowdstrike_router(_tag: &str) -> ((Router, String), TempDir) {
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
            .with_state(());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let (router, dir) = test_router(edr::EdrClient::Noop);
        ((router, format!("http://{addr}")), dir)
    }

    // ── T63 / CNT-05: pre-send vs ambiguous transport failure ──────────────

    #[tokio::test]
    async fn execute_presend_failure_releases_nonce_for_clean_retry() {
        // A connection refused on /execute is a PRE-SEND failure: the isolate
        // provably did not run, so the nonce is released and a retry with the
        // SAME request_id re-dispatches (502 again) rather than being deduped to
        // 409. If the nonce had been wrongly held, the retry would be 409.
        let (router, dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": "http://127.0.0.1:1", // nothing listening -> connect refused
        });
        let body = action_body("presend-1", Some(creds.clone()));
        let (s1, _) = post_json(&router, "/execute", body).await;
        assert_eq!(s1, StatusCode::BAD_GATEWAY, "pre-send failure is 502");

        // Same request_id again: a released nonce means a FRESH claim and another
        // real attempt (502), NOT a 409 in-flight.
        let body2 = action_body("presend-1", Some(creds));
        let (s2, _) = post_json(&router, "/execute", body2).await;
        assert_eq!(
            s2,
            StatusCode::BAD_GATEWAY,
            "a pre-send failure must release the nonce so the retry re-dispatches, not 409"
        );

        // The trail records the non-event as FAILED_, never NEEDS_RECONCILIATION_.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(log.contains("\"FAILED_HostIsolation\""));
        assert!(!log.contains("NEEDS_RECONCILIATION"));
    }

    #[tokio::test]
    async fn execute_ambiguous_failure_holds_nonce_and_flags_reconciliation() {
        // A 5xx from the EDR on /execute is AMBIGUOUS: the EDR was contacted and
        // may have acted. The proxy must NOT release the nonce (a blind retry
        // would risk a double-isolate) and must surface the distinct
        // needs_reconciliation state with may_have_executed:true. A retry with
        // the same request_id is then deduped to 409 (the claim is still
        // in-flight), proving the nonce was held.
        let ((router, base_url), dir) = always_500_crowdstrike_router("amb").await;
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": base_url,
        });
        let body = action_body("ambiguous-1", Some(creds.clone()));
        let (s1, v1) = post_json(&router, "/execute", body).await;
        assert_eq!(s1, StatusCode::BAD_GATEWAY);
        assert_eq!(
            v1["status"], NEEDS_RECONCILIATION_STATUS,
            "an ambiguous execute failure must flag for human reconciliation"
        );
        assert_eq!(
            v1["may_have_executed"], true,
            "the response must warn the action may have executed"
        );

        // Same request_id again: the nonce was held (in-flight), so this dedups
        // to 409 rather than re-executing.
        let body2 = action_body("ambiguous-1", Some(creds));
        let s2 = post(&router, "/execute", body2.clone(), Some(sign_body(&body2))).await;
        assert_eq!(
            s2,
            StatusCode::CONFLICT,
            "an ambiguous failure must HOLD the nonce: the retry is deduped, not re-run"
        );

        // The trail records the ambiguity, not a clean failure.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(
            log.contains("\"NEEDS_RECONCILIATION_HostIsolation\""),
            "the audit entry must make clear the action may have executed"
        );
    }

    // ── T64 / RB-01: bounded rollback retry + terminal ROLLBACK_FAILED ─────

    #[tokio::test]
    async fn rollback_retries_transient_failure_then_succeeds() {
        // A mock that 500s on the FIRST device-action hit and 200s afterward.
        // The bounded internal retry must absorb the transient failure and the
        // rollback must ultimately succeed (200 rolled_back), with no human page.
        let attempt = Arc::new(StdMutex::new(0u32));

        async fn token() -> Json<serde_json::Value> {
            Json(json!({"access_token": "t", "expires_in": 1800}))
        }
        async fn flaky(
            State(attempt): State<Arc<StdMutex<u32>>>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            let mut n = attempt.lock().unwrap();
            *n += 1;
            if *n == 1 {
                // First attempt: transient server error.
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            } else {
                Ok(Json(json!({ "resources": [], "errors": [] })))
            }
        }
        let app = Router::new()
            .route("/oauth2/token", axum::routing::post(token))
            .route(
                "/devices/entities/devices-actions/v2",
                axum::routing::post(flaky),
            )
            .with_state(attempt.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let (router, _dir) = test_router(edr::EdrClient::Noop);
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": format!("http://{addr}"),
        });
        let body = action_body("rb-retry-ok", Some(creds));
        let (status, value) = post_json(&router, "/rollback", body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the bounded retry must recover a transient rollback failure"
        );
        assert_eq!(value["status"], "rolled_back");
        assert!(
            *attempt.lock().unwrap() >= 2,
            "the rollback must have retried at least once"
        );
    }

    #[tokio::test]
    async fn rollback_exhausts_retries_then_emits_terminal_rollback_failed() {
        // A device-action that ALWAYS 500s. After ROLLBACK_MAX_ATTEMPTS the proxy
        // emits the distinct terminal ROLLBACK_FAILED audit entry + body. A 5xx
        // is AMBIGUOUS about whether the EDR partially applied the lift, so the
        // nonce is HELD (may_have_executed:true) rather than released: the human
        // pager reconciles, and a blind retry is deduped to 409 instead of
        // risking a second uncoordinated lift.
        let ((router, base_url), dir) = always_500_crowdstrike_router("rb-exhaust").await;
        let creds = json!({
            "provider": "crowdstrike",
            "api_key": "id",
            "api_secret": "secret",
            "base_url": base_url,
        });
        let body = action_body("rb-exhaust-1", Some(creds.clone()));
        let (status, value) = post_json(&router, "/rollback", body).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(value["status"], ROLLBACK_FAILED_STATUS);
        assert_eq!(
            value["may_have_executed"], true,
            "a server 5xx is ambiguous: the EDR may have partially applied the lift"
        );

        // The terminal state is in the audit trail under a distinct label.
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("audit log");
        assert!(
            log.contains("\"ROLLBACK_FAILED_ROLLBACK_HostIsolation\""),
            "the trail must carry the distinct terminal ROLLBACK_FAILED label, saw: {log}"
        );

        // The ambiguous failure HELD the nonce: a retry is deduped to 409, never
        // a second uncoordinated lift, until a human reconciles.
        let body2 = action_body("rb-exhaust-1", Some(creds));
        let s2 = post(&router, "/rollback", body2.clone(), Some(sign_body(&body2))).await;
        assert_eq!(
            s2,
            StatusCode::CONFLICT,
            "an ambiguous rollback failure holds the nonce: the retry is deduped, not re-run"
        );
    }

    // ── PRX-08: weak signing secret fails closed in production ─────────────

    #[test]
    fn secret_strength_error_fails_closed_only_in_production() {
        let short = "too-short"; // < 32 bytes
        let long = "this-secret-is-definitely-at-least-32-bytes-long"; // >= 32

        // Production + short secret -> hard error (the caller panics on this).
        assert!(
            secret_strength_error(short, true).is_some(),
            "a short secret must fail closed in production"
        );
        // Production + long secret -> fine.
        assert!(
            secret_strength_error(long, true).is_none(),
            "a >= 32-byte secret is accepted in production"
        );
        // Dev/CI + short secret -> no hard error (the caller only warns).
        assert!(
            secret_strength_error(short, false).is_none(),
            "a short secret only warns in dev/CI, never blocks"
        );
        assert!(secret_strength_error(long, false).is_none());
    }
}
