## What this does

Describe what changed and why in one to three sentences.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation only
- [ ] Test coverage
- [ ] Dependency update
- [ ] Security fix

## How to test

1. Describe setup.
2. Run the relevant test commands.
3. Confirm expected behavior.

```bash
cargo test -- --test-threads=1
cargo clippy -- -D warnings
cargo fmt -- --check
```

## Security checklist

- [ ] HMAC verification is not weakened by this change
- [ ] Every new action behavior has a corresponding audit log entry
- [ ] No secrets are hardcoded or logged
- [ ] Rate limiter is not bypassed by this change
- [ ] If this adds a dependency: cargo audit reports no known vulnerabilities

## Breaking changes

State whether this changes request payloads, signatures, or response contracts.

## Linked issues

Closes #

## Notes for reviewers

Anything important that is not obvious from the diff.
