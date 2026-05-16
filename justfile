# Vyrox Proxy (Rust) Justfile
# =====================================================================
# Production-grade task runner for the Rust containment proxy.
# MIT licensed - handles execution of EDR containment actions.
#
# Usage:
#   just              # Show all commands
#   just <command>   # Run specific command
# =====================================================================

set shell := ["sh", "-cu"]

# =====================================================================
# DEFAULT
# =====================================================================

default:
    @just --list

# =====================================================================
# BUILDING
# =====================================================================

# Build debug binary
build:
    cargo build

# Build release binary
build-release:
    cargo build --release

# Build with all features
build-all:
    cargo build --all-features

# =====================================================================
# RUNNING
# =====================================================================

# Run the proxy server
run:
    cargo run

# Run in release mode
run-release:
    cargo run --release

# =====================================================================
# TESTING
# =====================================================================

# Run all tests (single-threaded for deterministic IO tests)
test:
    cargo test --all -- --test-threads=1

# Run tests with output
test-verbose:
    cargo test --all -- --nocapture --test-threads=1

# Run specific test
test-name name:
    cargo test {{ name }} -- --test-threads=1

# Run doc tests
test-docs:
    cargo test --doc

# =====================================================================
# LINTING & FORMATTING
# =====================================================================

# Run clippy linter
lint:
    cargo clippy --all-targets -- -D warnings

# Auto-fix with clippy
lint-fix:
    cargo clippy --all-targets --fix --allow-dirty

# Format code
format:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Full quality gate
quality-gate: lint fmt-check test

# =====================================================================
# SECURITY
# =====================================================================

# Run security audit
audit:
    cargo audit

# Check for vulnerabilities
audit-json:
    cargo audit --json

# Check dependencies
outdated:
    cargo outdated || true

# =====================================================================
# RELEASE
# =====================================================================

# Bump version and tag (requires cargo-release plugin)
release type="patch":
    @echo "Manual version bump required. Use: cargo release {{ type }}"
    @echo "Tag created. Push with: git push --follow-tags"

# Publish to crates.io
publish:
    cargo publish

# Build binary for release
release-binary:
    RUSTFLAGS="-C strip=symbols" cargo build --release
    @echo "Binary: target/release/vyrox-proxy"

# =====================================================================
# CLEANUP
# =====================================================================

# Clean build artifacts
clean:
    cargo clean

# Remove dev dependencies
prune:
    cargo prune

# =====================================================================
# DOCUMENTATION
# =====================================================================

# Generate documentation
docs:
    cargo doc --no-deps --open

# Generate documentation (published)
docs-open:
    cargo doc --no-deps

# Check docs build
docs-check:
    cargo doc --no-deps

# =====================================================================
# DEVELOPMENT
# =====================================================================

# Watch for changes and rebuild
watch:
    cargo watch -x build -x test

# Open Rust shell
shell:
    @echo "Use: cargo run --example <name>"

# Show dependency tree
deps:
    cargo tree

# Show size of binary
size:
    ls -lh target/release/vyrox-proxy 2>/dev/null || echo "Build release first: just build-release"

# =====================================================================
# CI/CD
# =====================================================================

# Full CI pipeline
ci:
    cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all -- --test-threads=1 && cargo audit

# Build for multiple targets
cross-compile:
    cargo build --target x86_64-unknown-linux-gnu --release
    cargo build --target x86_64-apple-darwin --release
    cargo build --target aarch64-unknown-linux-gnu --release

# =====================================================================
# HELP
# =====================================================================

help:
    @just --list --unsorted