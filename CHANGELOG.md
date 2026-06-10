# Changelog

All notable changes to the Vyrox containment proxy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Durable, shared nonce/replay store backed by Redis.** Request
  de-duplication now survives a proxy restart and is shared across multiple
  proxy instances, so a retry that crosses a restart or lands on a different
  instance no longer risks double-executing a containment. Configured by
  `REDIS_URL` (or `NONCE_REDIS_URL`); the TTL is `NONCE_RETENTION_SECONDS`.
- **Per-tenant rate limiting.** The rate limiter is now keyed by `tenant_id`
  from the signed request, so one tenant's containment burst only throttles
  that tenant. A separate global ceiling still runs before signature
  verification to shed unauthenticated floods. Both are configurable via
  `RATE_LIMIT_PER_TENANT` and `RATE_LIMIT_GLOBAL`.

### Changed
- The in-memory nonce store is now a fallback used only when no Redis URL is
  configured; the proxy logs a loud warning when it falls back, because that
  mode is not durable and not shared.
- The global fixed-window rate limiter is no longer the only tier; it became
  the global safety ceiling above the new per-tenant budget.

## [0.1.0] - 2026-05-25

First tagged release of the Rust containment proxy, the component that turns a
human-approved decision into an EDR containment action, with a tamper-evident
record. MIT licensed.

### Added
- **Axum HTTP service**: `GET /health`, `POST /execute` (containment), and
  `GET /audit/export`.
- **HMAC-SHA256 request authentication** with constant-time comparison; the
  proxy only acts on a signed request.
- **30-second replay window + nonce de-duplication**, a captured signed request
  can't be replayed or replayed-within-window.
- **DRY_RUN, default true**, containment is logged and audited but no real EDR
  call is made unless an operator explicitly opts in. Returns before any EDR
  dispatch.
- **Append-only, SHA-256 hash-chained audit log**, each entry chains the
  previous one; the chain seeds from the existing log on startup and survives
  restarts. Tamper-evident by construction.
- **Authenticated `/audit/export`**, requires a signed request inside the same
  30-second replay window as `/execute`.
- **Global rate limiter** (fixed-window) and a loud warning when binding plain
  HTTP to a non-loopback address without an explicit opt-in.

### Security
- Constant-time HMAC comparison; typed signature errors.
- No autonomous containment, the proxy only executes a request that a human
  approved upstream.
