# Contributing to Vyrox Proxy

## Before You Open a PR

Vyrox Proxy is in alpha. Bug reports and reproducible test cases are welcome from anyone.

Code contributions are welcome, but this repository executes containment actions and is reviewed accordingly. Changes touching HMAC verification, rate limiting, action dispatch, or audit logging receive stricter review.

## Development Setup

```bash
# Clone repository
git clone https://github.com/vyrox-security/vyrox-proxy.git
cd vyrox-proxy

# Build with locked dependencies
cargo build --locked

# Run tests in single-thread mode for deterministic IO tests
cargo test -- --test-threads=1

# Enforce lint and formatting
cargo clippy -- -D warnings
cargo fmt -- --check

# Run dependency vulnerability scan
cargo install cargo-audit --locked || true
cargo audit
```

## Opening an Issue

Use issue templates under `.github/ISSUE_TEMPLATE`.

Do not report security vulnerabilities in a public GitHub issue. Follow `SECURITY.md`.

## Opening a Pull Request

Use `.github/PULL_REQUEST_TEMPLATE.md` and complete all checklists.

Every PR must include a test for the changed path.

PRs touching HMAC verification, rate limiter logic, or action dispatching require maintainer approval before merge.

## Code Style

- `rustfmt` is required
- `clippy` must pass with `-D warnings`
- `unsafe` is not accepted without explicit security justification
- `unwrap()` is not allowed in production request paths
- Commit messages follow Conventional Commits (`feat`, `fix`, `docs`, `test`, `chore`)

## What We Will Not Merge

- Changes that weaken or bypass HMAC verification
- Changes that bypass rate limiting
- New action behavior without corresponding audit-log coverage
- `unsafe` additions without security review documentation
- Documentation-only PRs that do not correct a concrete inaccuracy
