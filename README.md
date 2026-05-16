# Vyrox Proxy

![Licence](https://img.shields.io/badge/licence-MIT-2ea44f?style=flat-square)
![Build](https://img.shields.io/badge/build-passing-2ea44f?style=flat-square)
![Version](https://img.shields.io/badge/version-v0.1.0--alpha-005cc5?style=flat-square)
![Platform](https://img.shields.io/badge/platform-rust-b7410e?style=flat-square)
![Compile Time](https://img.shields.io/badge/cargo%20build-coffee%20required-6a737d?style=flat-square)

**Vyrox is now an AI Security Copilot that runs your SOC 24/7 — for $2K/month.**

The proxy is the containment execution boundary for Vyrox, implemented as a small Rust service that receives signed action requests and calls endpoint security APIs only after boundary checks pass. It exists as a separate repository because the open-core model depends on it: this proxy is MIT licensed so CISOs in zero-trust mode can audit exactly what code is allowed to isolate a host, kill a process, or block a hash before deploying anything else.

Website: [vyrox.dev](https://vyrox.dev)

## Why This Exists

The proxy is where side effects happen. The rest of the system can classify alerts incorrectly and produce embarrassment; this component can interrupt production workloads if implemented poorly. That is why it is isolated from the triage stack and kept intentionally narrow in scope.

As part of Vyrox's AI Security Copilot model, this proxy executes the automated response actions that make 24/7 SOC operations possible — without requiring human intervention for routine threats.

Rust is used here for memory safety and predictable runtime behavior in a service that should fail closed, not fail interestingly. Request authentication is HMAC-SHA256 so callers can be verified without introducing expensive key exchange machinery in the alpha phase.

Rate limiting exists because compromised credentials plus high automation is a bad combination. The append-only audit log exists because every action should be attributable, reviewable, and boring to investigate months later.

## Architecture

```text
[Python backend]
	|
	| POST /execute + X-Vyrox-Signature
	v
[HMAC verify] --fail--> [401]
	|
	v
[Rate limiter] --exceeded--> [429]
	|
	v
[Action dispatcher]
	|\
	| +--> [Audit log append]
	|
	+--> [DRY_RUN=true] -> [return executed,dry_run]
	|
	+--> [DRY_RUN=false] -> [EDR API call] -> [response]
```

## Quickstart

Prerequisites:

1. Rust stable toolchain
2. Docker and Docker Compose
3. A local `.env` file with proxy variables

1. Start the local stack using the compose file in `vyrox-deploy`.

```bash
# Start ingestion, worker, Discord bot, and proxy from the shared compose file
docker compose -f ../vyrox-deploy/docker-compose.yml up -d
```

2. Run proxy tests locally.

```bash
# Execute the Rust test suite in single-thread mode for deterministic IO tests
cargo test -- --test-threads=1
```

3. Run lint and formatting checks.

```bash
# Enforce zero clippy warnings and formatting compliance
cargo clippy -- -D warnings
cargo fmt -- --check
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| VYROX_HMAC_SECRET | Yes | None | Shared request signing key [secret] |
| DRY_RUN | No | true | If true, logs actions and skips live EDR calls |
| AUDIT_LOG_PATH | No | ./audit.jsonl | Append-only JSONL audit log output path |

## Request Authentication

All requests to `/execute` must include a valid HMAC-SHA256 signature in the `X-Vyrox-Signature` header:

```
X-Vyrox-Signature: sha256=<hex-encoded-hmac-signature>
```

The signature must be computed using the shared `VYROX_HMAC_SECRET` over the raw request body. The `sha256=` prefix is required.

## Contributing

Contributions are most useful in tests, input validation hardening, error-path behavior, and documentation improvements that remove ambiguity in the execution contract. Bug reports with reproducible requests and signatures are especially valuable.

Do not submit changes that weaken HMAC verification, bypass the rate limiter, or add unsafe Rust without a written security justification. New action types require threat review and audit-log coverage before discussion moves past draft.

See CONTRIBUTING.md for the full process. The project is in alpha and external contributions are accepted selectively for security-critical paths.

Security contact: sec.vyrox@proton.me

## Licence

MIT License
Copyright (c) 2026 Vyrox Security, Inc.