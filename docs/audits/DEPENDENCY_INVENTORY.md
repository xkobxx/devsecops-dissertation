# Dependency Inventory

Audit date: 2026-07-24
Audited commit: `a780add`

## Summary

The repository has no reproducible dependency set. Three Python libraries are
exactly versioned in `requirements.txt`, but there are no hashes or separated
runtime/development/scanner locks. `pyproject.toml` separately declares an
unbounded Flask dependency. Scanner packages and most GitHub Actions are mutable,
all research container images are mutable, and the webhook uses a SemVer range
without a lockfile.

Version and licence entries below are inventory data, not a legal compatibility
opinion. Scanner and image licence compatibility still requires the dedicated
review specified in roadmap Phase 25.

## Python application dependencies

| Dependency | Declaration | Consumer | Pin status | Notes |
|---|---|---|---|---|
| `matplotlib` | `3.10.8` in `requirements.txt` | `scripts/visualise_results.py` | Exact, no hash | Research/charting only |
| `numpy` | `2.3.2` in `requirements.txt` | `scripts/visualise_results.py` | Exact, no hash | Research/charting only |
| `cryptography` | `49.0.0` in `requirements.txt` | Licence issue/verify scripts | Exact, no hash | Also installed unpinned by `action.yml` |
| `flask` | Unbounded in `pyproject.toml` | `test_app/app.py` via Vercel entrypoint | Unbounded | Fixture dependency is separately pinned to `3.1.1` |
| Python standard library | Python `3.11` in Actions | All scripts | Minor line only | CI runners can receive any 3.11 patch |

`pyproject.toml` and `requirements.txt` describe different environments. There is
no build-system declaration, package discovery, dependency grouping, or
`trustgate` console entry point.

## Python scanner dependencies

| Scanner/runtime | Installation or invocation | Current evidence | Pin status |
|---|---|---|---|
| Bandit | `pip install bandit`; `bandit` | Architecture doc says `1.9.4`; report has no version field | Unpinned |
| Semgrep | `pip install semgrep`; registry config `p/python` | Committed report says `1.165.0`; architecture doc says `1.156.0` | Package and remote ruleset unpinned |
| pip-audit | `pip install pip-audit` | No version recorded in report | Unpinned |
| Trivy | `aquasecurity/trivy-action` | Reusable Action pins action `v0.36.0` SHA; report says scanner `0.69.3` | Pinned in `action.yml`, mutable `master` in workflow |
| Gitleaks | `ghcr.io/gitleaks/gitleaks:latest` | Report is an empty list with no metadata | Mutable `latest` |
| OWASP ZAP | `zaproxy/action-baseline@v0.12.0` | Workflow-only research job | Mutable Git tag |

The scanners do not have a compatibility lock or a recorded exit-code contract.
No runtime verifies the scanner version before trusting a report.

## Deliberately vulnerable fixture dependencies

`test_app/requirements.txt` contains exact, unhashed research pins:

| Dependency | Version |
|---|---:|
| Flask | 3.1.1 |
| Flask-SQLAlchemy | 3.1.1 |
| Flask-Migrate | 4.0.5 |
| Flask-Login | 0.6.2 |
| Flask-WTF | 1.2.1 |
| Flask-Mail | 0.9.1 |
| Flask-Bootstrap | 3.3.7.1 |
| Flask-Moment | 1.0.5 |
| python-dotenv | 1.0.0 |
| email-validator | 2.1.0.post1 |
| python-dateutil | 2.8.2 |
| Pillow | 10.2.0 |
| PyJWT | 2.13.0 |
| requests | 2.31.0 |
| bleach | 6.1.0 |
| Markdown | 3.5.2 |
| Flask-PageDown | 0.4.0 |
| Flask-HTTPAuth | 4.8.0 |

These dependencies belong to a benchmark fixture and must not become production
Trust Gate runtime dependencies.

## JavaScript dependencies

| Dependency | Declaration | Consumer | Pin status |
|---|---|---|---|
| `stripe` | `^18.0.0` | `webhook/api/stripe-webhook.js` | Range; no lockfile |
| Node.js built-ins | `node:crypto` | Webhook licence signing | Runtime not declared |
| Fetch API | Node runtime global | Resend API call | Minimum Node version not declared |

The webhook has no `engines` declaration, package lock, test dependency, lint
configuration, or pinned Stripe API version in source.

## GitHub Actions

| Action | References | Pin status |
|---|---|---|
| `actions/checkout` | `@v4` in workflow and documentation | Mutable major tag |
| `actions/setup-python` | `@v5` in workflow and Action | Mutable major tag |
| `actions/upload-artifact` | `@v4` in workflow and Action | Mutable major tag |
| `actions/download-artifact` | `@v4` in workflow | Mutable major tag |
| `zaproxy/action-baseline` | `@v0.12.0` | Mutable release tag |
| `aquasecurity/trivy-action` | `@master` in workflow | Unbounded branch |
| `aquasecurity/trivy-action` | `@ed142fd0673e97e23eac54620cfb913e5ce36c25` in Action, noted as v0.36.0 | Correct immutable pin |
| `actions/upload-pages-artifact` | `@v3` | Mutable major tag |
| `actions/deploy-pages` | `@v4` | Mutable major tag |
| `actions/github-script` | `@v7` | Mutable major tag |
| Product Action examples | `xkobxx/devsecops-dissertation@v1.0.0` | Mutable Git tag for consumers |

Only one third-party Action reference is pinned to a full commit SHA.

## Container images

| Image | Use | Pin status |
|---|---|---|
| `ghcr.io/gitleaks/gitleaks:latest` | Product and workflow secret scanning | Mutable tag |
| `vulnerables/web-dvwa` | Local DAST research | Implicit `latest` |
| `mariadb:10.1` | DVWA database | Mutable version tag; obsolete major line |
| `bkimminich/juice-shop` | Local DAST research | Implicit `latest` |
| `webgoat/goatandwolf` | Local DAST research | Implicit `latest` |

No image is pinned by digest.

## External services and network dependencies

| Service | Data sent | Location | Default behaviour |
|---|---|---|---|
| GitHub Actions/Artifacts/Pages | Source checkout, reports, dashboard | Workflow and composite Action | Required for hosted Action mode |
| Semgrep Registry | Ruleset request for `p/python` | Semgrep invocation | Network-dependent, unpinned rules |
| GitHub Container Registry | Gitleaks image pull | Action/workflow | Network-dependent |
| Container registries | Vulnerable app image pulls | `docker-compose.yml` | Manual research only |
| Google Fonts | Viewer IP/request metadata | Generated dashboard | Requested whenever dashboard is opened online |
| Stripe | Invoice/customer metadata | Webhook | Optional commercial sketch |
| Resend | Customer email, expiry and licence key | Webhook | Optional commercial sketch |
| Vercel | Webhook code and secrets | Webhook README/pyproject | Optional, not deployed |

No scanner source upload is explicitly implemented, but Semgrep configuration and
all third-party actions/images require documented data-handling review. The
dashboard's Google Fonts request conflicts with a strict offline/local-only mode.

## Project licensing boundaries

| Component | Repository terms |
|---|---|
| Core Action, aggregation, reporting, licence verification, docs and fixtures | MIT per `LICENSE` |
| `scripts/score_findings.py` | Proprietary/source-available per `LICENSE-COMMERCIAL` |
| `scripts/build_confidence_table.py` | Proprietary/source-available per `LICENSE-COMMERCIAL` |
| `confidence_table.json` | Proprietary/source-available per `LICENSE-COMMERCIAL` |
| `webhook/` | MIT by current catch-all wording, despite being commercial operations code |

The roadmap requires separating licensing from security-scoring logic and obtaining
formal legal review before commercial reliance.

## Required Phase 1 dependency work

1. Create `requirements/runtime.lock`, `development.lock`, and `scanners.lock`
   with exact versions and hashes.
2. Reconcile `pyproject.toml` with the actual runtime package.
3. Pin every GitHub Action to a full commit SHA with a readable version comment.
4. Pin scanner and fixture images by immutable digest.
5. Pin the Semgrep ruleset or vendor an approved configuration.
6. Add a webhook lockfile and declared Node runtime.
7. Record scanner versions and compatibility in every scan run.
8. Add automated dependency update PRs and an upgrade qualification test.

## Completion assessment

- [x] All direct Python and JavaScript dependencies are accounted for.
- [x] All scanner installations and invocations are accounted for.
- [x] All GitHub Actions are accounted for.
- [x] All container images are accounted for.
- [x] External network and service dependencies are accounted for.
- [x] Current project licensing boundaries are recorded.
