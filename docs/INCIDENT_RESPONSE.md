# Incident response process

## Scope

This process covers security incidents affecting Trust Gate itself,
not findings discovered by Trust Gate in user code.

## Severity levels

| Level | Description | Response time |
|-------|-------------|---------------|
| Critical | Active exploitation, data breach | Immediate |
| High | Exploitable vulnerability, no active exploitation | 24 hours |
| Medium | Vulnerability requiring specific conditions | 72 hours |
| Low | Informational, defence-in-depth improvement | Next release |

## Process

1. **Triage** — confirm the report, assess severity, assign owner.
2. **Contain** — if actively exploited, issue advisory and workaround.
3. **Fix** — develop and test patch.
4. **Release** — publish fix, update changelog, notify affected users.
5. **Review** — post-incident review within 7 days.

## Responsible disclosure

See `SECURITY.md` in the repository root for reporting instructions.
