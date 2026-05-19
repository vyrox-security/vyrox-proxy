use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

mod actions;
mod audit;
mod hmac;

const REPLAY_WINDOW_SECONDS: i64 = 30;

#[derive(Clone)]
struct AppState {
    hmac_secret: String,
    audit_log_path: String,
    dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExecuteRequest {
    tenant_id: String,
    alert_id: String,
    action_type: actions::ActionType,
    host: String,
    approved_by: String,
    #[serde(rename = "approved_at")]
    approved_at: i64,
}

#[derive(Debug, Serialize)]
struct ExecuteResponse {
    status: String,
    dry_run: bool,
}

fn check_replay_window(approved_at: i64) -> Result<(), StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .as_secs() as i64;

    let diff = now - approved_at;

    if diff.abs() > REPLAY_WINDOW_SECONDS {
        return Err(StatusCode::GONE);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let hmac_secret = env::var("VYROX_HMAC_SECRET").expect("VYROX_HMAC_SECRET must be set");
    let audit_log_path = env::var("AUDIT_LOG_PATH").unwrap_or_else(|_| "./audit.jsonl".to_string());
    let dry_run = env::var("DRY_RUN").unwrap_or_else(|_| "true".to_string()) == "true";

    let state = AppState {
        hmac_secret,
        audit_log_path,
        dry_run,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/execute", post(execute))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("bind should work");
    info!("vyrox proxy listening on :3000");
    axum::serve(listener, app).await.expect("server should run");
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status":"ok"}))
}

async fn execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    // Check replay window (Rule 3: HMAC Before Processing)
    check_replay_window(payload.approved_at)?;

    let signature = headers
        .get("X-Vyrox-Signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let body = serde_json::to_vec(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    hmac::verify_signature(state.hmac_secret.as_bytes(), &body, signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let entry = audit::build_entry(
        format!("{:?}", payload.action_type),
        payload.host,
        payload.approved_by,
        state.dry_run,
    );
    // TODO: Pass tenant_id to append_audit for Rule 1 namespacing
    audit::append_audit(&state.audit_log_path, entry)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ExecuteResponse {
        status: "executed".to_string(),
        dry_run: state.dry_run,
    }))
}
