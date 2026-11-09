# Security policy

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub **private vulnerability reporting**
(Security tab → *Report a vulnerability*). Reports are acknowledged within 2 business days.

## Response targets (from detection)

| Severity | Internet-facing / prod | Internal / non-prod |
|---|---|---|
| Critical | 72 hours (live secret: revoke within 1 hour) | 7 days |
| High | 14 days | 30 days |
| Medium | 60 days | 90 days |
| Low | 180 days | Best effort |

## Supported versions

Only the latest release on the default branch receives security fixes unless stated otherwise.

## Internal documentation

- `docs/security/vulnerability-management.md` - severity model, gates, exceptions
- `docs/security/secret-incident-response.md` - exposed-credential runbook
- `docs/security/DEVSECOPS.md` - pipeline inventory, decisions and validation evidence
- `skills.md` - the implementation standard for this pipeline
