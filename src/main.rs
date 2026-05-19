//! Vyrox Proxy - Rust Containment Action Executor
//!
//! This service executes approved containment actions (host isolation,
//! process kill, network quarantine) on behalf of the Vyrox SOC platform.
//!
//! ## Security Model
//!
//! - All execution requests must include valid HMAC-SHA256 signature
//! - Timestamps are validated against 30-second replay window
//! - Actions are logged to append-only audit log with tenant isolation
//! - DRY_RUN mode prevents actual execution in development
//!
//! ## API Endpoints
//!
//! - `GET /health` - Service health check
//! - `POST /execute` - Execute containment action
//! - `GET /audit/export?tenant_id=<id>` - Export audit logs for tenant

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

// Internal modules for security-critical functionality
mod actions; // Action type definitions and execution logic
mod audit; // Audit log writing with append-only guarantee
mod hmac; // HMAC-SHA256 signature verification

/// Replay protection window in seconds.
/// Requests with timestamps older than this will be rejected.
const REPLAY_WINDOW_SECONDS: i64 = 30;

/// Application state shared across all request handlers.
/// This struct is cloned for each request, so it should contain
/// only static configuration data.
#[derive(Clone)]
struct AppState {
    /// Shared secret for HMAC signature verification.
    /// In production, this should come from a secure secrets manager.
    hmac_secret: String,

    /// File path for the append-only audit log.
    /// Format: one JSON entry per line (JSONL)
    audit_log_path: String,

    /// Development mode flag - when true, actions are logged but not executed.
    /// This prevents accidental containment actions in development.
    dry_run: bool,
}

/// Request payload for containment action execution.
/// This struct is received from the Discord bot after human approval.
#[derive(Debug, Deserialize, Serialize)]
struct ExecuteRequest {
    /// Tenant identifier for multi-tenancy isolation.
    /// All audit entries are tagged with this value.
    tenant_id: String,

    /// Reference to the original alert that triggered this action.
    alert_id: String,

    /// Type of containment action to execute.
    action_type: actions::ActionType,

    /// Target hostname or IP address for the action.
    host: String,

    /// Discord username who approved this action.
    approved_by: String,

    /// Unix timestamp when approval was granted.
    /// Used for replay attack detection.
    #[serde(rename = "approved_at")]
    approved_at: i64,
}

/// Response payload returned after action execution.
#[derive(Debug, Serialize)]
struct ExecuteResponse {
    /// Human-readable status message.
    status: String,

    /// Whether the action was actually executed or just logged (dry run).
    dry_run: bool,
}

/// Query parameters for the audit export endpoint.
#[derive(Debug, Deserialize)]
struct ExportQuery {
    /// Tenant ID to filter audit entries.
    /// Only entries matching this tenant will be returned.
    tenant_id: String,
}

/// Validates that the approval timestamp is within the replay window.
///
/// This function prevents replay attacks where an attacker captures a
/// valid request and resubmits it later. By checking the timestamp
/// against the current time, we ensure requests are fresh.
///
/// Arguments:
///   - approved_at: Unix timestamp of the original approval
///
/// Returns:
///   - Ok(()) if timestamp is within the window
///   - Err(StatusCode::GONE) if timestamp is too old
fn check_replay_window(approved_at: i64) -> Result<(), StatusCode> {
    // Get current Unix timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .as_secs() as i64;

    // Calculate absolute time difference
    let diff = now - approved_at;

    // Reject if the timestamp difference exceeds our window
    // This handles both old requests (replay) and far-future requests (clock skew)
    if diff.abs() > REPLAY_WINDOW_SECONDS {
        return Err(StatusCode::GONE);
    }

    Ok(())
}

/// Health check endpoint for Kubernetes liveness/readiness probes.
///
/// Returns a simple JSON object indicating the service is running.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

/// Execute a containment action after validating the request.
///
/// This is the primary endpoint that the Discord bot calls after a human
/// analyst approves a containment action. The request goes through:
///
/// 1. Timestamp validation (replay protection)
/// 2. HMAC signature verification
/// 3. Audit log entry creation
/// 4. Action execution (if not dry-run)
///
/// Arguments:
///   - state: Application configuration (HMAC secret, dry-run flag)
///   - headers: HTTP headers including signature
///   - payload: Action request details
///
/// Returns:
///   - ExecuteResponse with status and dry-run flag
async fn execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    // Step 1: Validate timestamp for replay protection
    // This must happen before any other processing
    check_replay_window(payload.approved_at)?;

    // Step 2: Extract and verify HMAC signature
    // The signature must be present in the X-Vyrox-Signature header
    let signature = headers
        .get("X-Vyrox-Signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Serialize payload to bytes for HMAC verification
    let body = serde_json::to_vec(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify HMAC-SHA256 signature using constant-time comparison
    hmac::verify_signature(state.hmac_secret.as_bytes(), &body, signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Step 3: Create audit log entry BEFORE executing
    // This is a critical security requirement - we log before acting
    let entry = audit::build_entry(
        payload.tenant_id.clone(),
        format!("{:?}", payload.action_type),
        payload.host,
        payload.approved_by,
        state.dry_run,
    );
    audit::append_audit(&state.audit_log_path, entry)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Step 4: Execute the action (or simulate in dry-run mode)
    // In production, this would call the actual EDR API
    // For now, we just return the status

    Ok(Json(ExecuteResponse {
        status: "executed".to_string(),
        dry_run: state.dry_run,
    }))
}

/// Export audit logs filtered by tenant ID.
///
/// This endpoint allows tenants to retrieve their audit logs for
/// compliance and investigation purposes. The logs are filtered
/// server-side to ensure tenant isolation.
///
/// Arguments:
///   - state: Application configuration (audit log path)
///   - query: Query parameters including tenant_id
///
/// Returns:
///   - Vector of AuditEntry objects for the requested tenant
async fn export_audit(
    State(state): State<AppState>,
    Query(query): Query<ExportQuery>,
) -> Result<Json<Vec<audit::AuditEntry>>, StatusCode> {
    // Read all audit entries from the log file
    let entries = audit::read_audit_logs(&state.audit_log_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Filter entries to only include those from the requested tenant
    // This ensures multi-tenant data isolation
    let filtered: Vec<audit::AuditEntry> = entries
        .into_iter()
        .filter(|e| e.tenant_id == query.tenant_id)
        .collect();

    Ok(Json(filtered))
}

/// Application entry point.
///
/// Initializes configuration from environment variables and starts
/// the Axum HTTP server on port 3000.
#[tokio::main]
async fn main() {
    // Initialize structured logging with timestamps
    tracing_subscriber::fmt::init();

    // Load configuration from environment variables
    // These are required for security-critical functionality
    let hmac_secret = env::var("VYROX_HMAC_SECRET").expect("VYROX_HMAC_SECRET must be set");
    let audit_log_path = env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "./audit.jsonl".to_string());
    let dry_run = env::var("DRY_RUN").unwrap_or_else(|_| "true".to_string()) == "true";

    // Build application state
    let state = AppState {
        hmac_secret,
        audit_log_path,
        dry_run,
    };

    // Build HTTP router with all endpoints
    let app = Router::new()
        .route("/health", get(health))
        .route("/execute", post(execute))
        .route("/audit/export", get(export_audit))
        .with_state(state);

    // Bind to port 3000 and start accepting connections
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("bind should work");
    info!("vyrox proxy listening on :3000");
    axum::serve(listener, app).await.expect("server should run");
}
