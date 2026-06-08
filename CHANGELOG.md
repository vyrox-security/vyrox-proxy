# Changelog

All notable changes to the Vyrox containment proxy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
