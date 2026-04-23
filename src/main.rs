use std::env;

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

#[derive(Clone)]
struct AppState {
    hmac_secret: String,
    audit_log_path: String,
    dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExecuteRequest {
    alert_id: String,
    action_type: actions::ActionType,
    host: String,
    approved_by: String,
}

#[derive(Debug, Serialize)]
struct ExecuteResponse {
    status: String,
    dry_run: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let hmac_secret = env::var("VYROX_HMAC_SECRET").unwrap_or_else(|_| "dev-secret".to_string());
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.expect("bind should work");
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
    audit::append_audit(&state.audit_log_path, entry)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ExecuteResponse {
        status: "executed".to_string(),
        dry_run: state.dry_run,
    }))
}
