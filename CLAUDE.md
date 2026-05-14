# vyrox-proxy — Rust Containment Proxy

> Public, MIT-licensed. CISOs will audit this code. Every line must be explainable.

## What This Is

An Axum-based Rust HTTP server that executes containment actions against EDR APIs
(CrowdStrike RTR, SentinelOne) on human-approved requests from the Vyrox Python backend.

```
src/
├── main.rs       # App entry, route registration, /execute handler
├── hmac.rs       # HMAC-SHA256 verification (constant-time)
├── audit.rs      # Append-only JSONL audit log with hash chain
├── actions.rs    # Action type definitions and dispatch
└── rate_limiter.rs  # Per-tenant token bucket rate limiter
```

---

## Critical Rules

### 1. cargo audit clean before any PR
`cargo audit` with any known CVE → CRITICAL failure. Block merge.

### 2. No unsafe blocks without documented justification
This is public code. `unsafe` without documentation is a security liability.

### 3. Audit entry written BEFORE HTTP 200
The audit log is the system of record. Never return success before writing.

### 4. HMAC verification first, always
Before parsing, before logging, before anything else.

### 5. DRY_RUN completely prevents EDR calls
`DRY_RUN=true` means log the action and return. Not: make the call but skip the result.

### 6. Rate limit is per tenant
Global rate limits are a denial-of-service vector. Each tenant gets their own bucket.

---

## Build & Test

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo audit
cargo fmt --check
```

### Required CI gates
All of the above must pass on every PR. No exceptions.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VYROX_HMAC_SECRET` | Yes | 32-byte hex (64 chars), shared with Python backend |
| `CROWDSTRIKE_CLIENT_ID` | Yes (prod) | CrowdStrike OAuth2 client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | Yes (prod) | CrowdStrike OAuth2 client secret |
| `SENTINELONE_API_TOKEN` | Yes (prod) | SentinelOne API token |
| `AUDIT_LOG_PATH` | Yes | Path to append-only JSONL file |
| `DRY_RUN` | Yes | `true` in dev, `false` in prod |
| `RATE_LIMIT_PER_MINUTE` | No | Per-tenant rate limit (default: 10) |

---

## The HMAC Protocol

### Request format to this proxy
```
POST /execute
Content-Type: application/json
X-Vyrox-Signature: sha256=<hex_digest>
X-Vyrox-Timestamp: <unix_epoch>

{
  "alert_id": "...",
  "action_type": "HOST_ISOLATION",
  "host": "WKSTN-FINANCE-07",
  "approved_by": "alice@acmecorp.com",
  "approved_at": 1745280000
}
```

### Signature format
- Body is the raw JSON bytes
- HMAC-SHA256 of the body using `VYROX_HMAC_SECRET`
- Result is hex-encoded
- Header value is `sha256=<hex>` (note the prefix)
- **The Python side in `slack_bot/proxy_client.py` does NOT currently prepend the
  `sha256=` prefix. This is a known bug — flag any proxy client changes.**

---

## Action Types

| Action | Description | EDR API call |
|---|---|---|
| `HOST_ISOLATION` | Isolate host from network | CrowdStrike RTR / S1 containment |
| `PROCESS_KILL` | Kill suspicious process | CrowdStrike RTR / S1 process kill |
| `NETWORK_QUARANTINE` | Block network access | S1 network containment |
| `MONITOR` | Log and watch | No EDR call |
| `DISMISS` | False positive | No EDR call |

`MONITOR` and `DISMISS` never make EDR API calls, even when `DRY_RUN=false`.

---

## Error Codes

| Code | Meaning |
|---|---|
| 400 | Malformed JSON body |
| 401 | Invalid or missing HMAC signature |
| 410 | Request expired (>30s old) |
| 429 | Rate limit exceeded for this tenant |
| 500 | Failed to write audit entry |
| 502 | EDR API returned error |
| 503 | EDR API unreachable |

All error response bodies:
```json
{"error": "short generic message"}
```
No stack traces. No internal paths. No secret values.
