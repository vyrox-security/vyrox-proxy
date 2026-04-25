# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.1.x | Yes |
| < v0.1.0-alpha | No |

Versions before `v0.1.0-alpha` are not supported and should not be deployed.

## Reporting a Vulnerability

Do not open public GitHub issues for vulnerabilities.

Email: `security@vyrox.security`

Subject format:

```text
SECURITY: <brief description>
```

Response SLA:

- Acknowledgement within 48 hours
- Initial triage within 7 days
- Patch timeline communicated within 14 days

PGP key available at https://vyrox.security/.well-known/pgp-key.txt.

## Scope

In scope:

- HMAC bypass
- Rate limiter bypass
- Audit log tampering
- Action execution without approval
- Authentication weaknesses in the proxy

Out of scope:

- UI/UX concerns
- Physical-access attack scenarios
- Model hallucinations outside proxy execution logic

## Disclosure Policy

Vyrox follows coordinated disclosure. Reporters are credited in release notes unless anonymity is requested.

No bounty program is active during alpha.

## Known Limitations

- `DRY_RUN=true` is expected in non-production environments and intentionally short-circuits EDR side effects.
- Free-tier infrastructure constraints may affect throughput during burst loads.

These are operational constraints, not vulnerabilities.
