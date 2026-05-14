# Rust Proxy Security Standards

> This is public, MIT-licensed code. CISOs and security researchers will audit it.
> Every line must be production-grade, explainable, and hardened.

---

## 1. HMAC Verification — First, Always

HMAC verification MUST be the first operation in any request handler. Before parsing,
before logging, before anything else.

```rust
// CORRECT — verify before any other processing
async fn execute(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, StatusCode> {
    let signature = headers.get("X-Vyrox-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let body = serde_json::to_vec(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    auth::verify_signature(state.hmac_secret.as_bytes(), &body, signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // NOW parse and process
}
```

### Flag if
- Any operation before HMAC verification → CRITICAL, reject immediately
- Signature parsed or logged before verification → CRITICAL
- `unwrap()` on header extraction → HIGH

---

## 2. Replay Attack Prevention

Every request carries a timestamp (`approved_at: i64` in the request body). The proxy
MUST reject requests where `abs(now - approved_at) > 30 seconds`.

```rust
let now = chrono::Utc::now().timestamp();
if now - req.approved_at > 30 || req.approved_at - now > 30 {
    return Err(StatusCode::GONE); // 410: Request expired
}
```

### Flag if
- No timestamp check → CRITICAL
- Timestamp check after business logic → CRITICAL
- Window not exactly 30 seconds → HIGH

---

## 3. Error Types — Explicit, No Panic

Production code never panics. No `unwrap()`, `expect()`, `todo!()`, `unreachable!()`
in request handlers. All errors return explicit HTTP status codes.

```rust
// CORRECT — explicit error handling
let signature = headers.get("X-Vyrox-Signature")
    .and_then(|v| v.to_str().ok())
    .ok_or(StatusCode::UNAUTHORIZED)?;

// CORRECT — typed error with context
let body = serde_json::to_vec(&payload)
    .map_err(|_| StatusCode::BAD_REQUEST)?;

// WRONG — panicking on invalid input
let sig = headers.get("X-Vyrox-Signature").unwrap(); // CRITICAL
```

### Flag if
- `unwrap()` in any request handler path → CRITICAL
- `expect()` in production code → HIGH
- `panic!()` anywhere → CRITICAL
- `todo!()` or `unreachable!()` in non-test code → HIGH

---

## 4. Unsafe Blocks — Forbidden Unless Documented

No `unsafe` blocks unless:
1. Absolutely necessary (FFI, specific performance requirement)
2. Documented with exact reason why safe code is insufficient
3. Isolated to a single, clearly-bounded module
4. Accompanied by a safety comment explaining the invariant being maintained

```rust
// Only if absolutely necessary:
/// SAFETY: This is the only call site. The pointer is valid for
/// 'a because it comes from Arc::from_raw which guarantees exclusivity.
unsafe { std::mem::transmute_copy(&value) }
```

### Flag if
- `unsafe` block without documentation → CRITICAL
- `unsafe` block in a request handler → CRITICAL

---

## 5. Audit Log — Before HTTP 200

Every action MUST write an append-only JSONL audit entry BEFORE returning HTTP 200
to the caller. The audit entry is the authoritative record.

```rust
// CORRECT — audit entry written first
let entry = audit::build_entry(...);
audit::append_audit(&state.audit_log_path, entry)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

Ok(Json(ExecuteResponse { status: "executed", ... }))
```

### Audit entry format
```json
{
  "ts": 1745280000,
  "action_type": "HOST_ISOLATION",
  "host": "WKSTN-FINANCE-07",
  "approved_by": "alice@acmecorp.com",
  "dry_run": false,
  "prev_hash": "sha256:...",
  "this_hash": "sha256:..."
}
```

### Flag if
- HTTP 200 returned before audit write → CRITICAL
- Audit write uses `O_WRONLY` instead of `O_APPEND` → CRITICAL
- Audit entry missing required fields → HIGH

---

## 6. Rate Limiting — Per Tenant, Not Global

Rate limiting MUST be per `tenant_id`. A single tenant exceeding their limit must
NOT affect other tenants.

```rust
// CORRECT — per-tenant rate limit
state.rate_limiter.check_key(&req.tenant_id)
    .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;

// WRONG — global rate limit → CRITICAL
state.rate_limiter.check_global()
```

### Flag if
- Global rate limit (no tenant_id key) → CRITICAL
- Rate limit checked after action execution → HIGH

---

## 7. DRY_RUN — Complete Prevention, Not Skipping

When `DRY_RUN=true`, EDR API calls MUST be completely prevented. Logging the action
and skipping the call is correct. Silently succeeding without the call is wrong.

```rust
if state.dry_run {
    tracing::info!(action = ?req.action_type, host = ?req.host, "DRY_RUN: action not executed");
} else {
    executor::dispatch(&req).await.map_err(|e| {
        tracing::error!("EDR API error: {}", e);
        StatusCode::BAD_GATEWAY
    })?;
}
```

### Flag if
- `DRY_RUN=true` still makes EDR API calls → CRITICAL
- `DRY_RUN=true` silently returns success without logging → HIGH

---

## 8. Constant-Time Comparison

All cryptographic comparisons MUST use constant-time algorithms. Do not use `==`
for secret comparisons.

```rust
// CORRECT — constant-time
if computed == hex_sig { Ok(()) } else { Err("mismatch") }
// The hmac crate's verify_slice does this automatically

// WRONG — timing leak
if computed == hex_sig {
    return Ok(());
} else {
    return Err("mismatch");
} // String length differs → timing leak
```

---

## Build & CI Requirements

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings   # Treats all clippy warnings as errors
cargo audit                    # Check for known vulnerabilities
cargo fmt                      # Check formatting
```

### CI gates
Every PR MUST pass all of the above before merge. `cargo audit` with any advisory
found → CRITICAL failure, block merge.

### Dependencies
- Keep `Cargo.lock` committed
- `cargo outdated` / `cargo audit` in CI — no exceptions for known CVEs
- Minimal dependencies: each new dependency increases attack surface

---

## Error Response Format

All error responses use explicit HTTP status codes with generic detail messages.
Stack traces, file paths, and internal details are NEVER included in responses.

| Status | Condition |
|---|---|
| 400 Bad Request | Malformed JSON body |
| 401 Unauthorized | Missing or invalid HMAC signature |
| 410 Gone | Request timestamp expired (replay attack) |
| 429 Too Many Requests | Rate limit exceeded |
| 500 Internal Server Error | Audit write failed |
| 502 Bad Gateway | EDR API returned error |
| 503 Service Unavailable | EDR API unreachable after retries |
