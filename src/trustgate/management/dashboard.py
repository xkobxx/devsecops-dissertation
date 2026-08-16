"""Management plane data aggregation.

Each function takes normalised finding/scan data and returns a summary
dict.  No network calls — all aggregation is local.
"""

from __future__ import annotations

from typing import Any

MANAGEMENT_SCHEMA_VERSION = "1.0.0"

SEVERITIES = ("critical", "high", "medium", "low", "info")


class ManagementPlaneError(ValueError):
    """Raised when management plane input is invalid."""


# --- helpers ---


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _group_by(items: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        k = item.get(key, "unknown")
        groups.setdefault(k, []).append(item)
    return groups


# --- 20.1 management plane functions ---


def multi_repository_dashboard(
    repositories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate finding counts across repositories.

    Each repo dict must have 'name' and 'findings' (list of finding dicts).
    """
    if not isinstance(repositories, list):
        raise ManagementPlaneError("repositories must be a list")

    repo_summaries = []
    total_findings = 0
    total_by_severity: dict[str, int] = {s: 0 for s in SEVERITIES}

    for repo in repositories:
        name = repo.get("name", "unknown")
        findings = repo.get("findings", [])
        counts = _severity_counts(findings)
        repo_summaries.append({
            "repository": name,
            "total_findings": len(findings),
            "by_severity": counts,
        })
        total_findings += len(findings)
        for s in SEVERITIES:
            total_by_severity[s] += counts[s]

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "multi_repository_dashboard",
        "repository_count": len(repositories),
        "total_findings": total_findings,
        "total_by_severity": total_by_severity,
        "repositories": repo_summaries,
    }


def organisation_risk_overview(
    repositories: list[dict[str, Any]],
    *,
    organisation: str = "default",
) -> dict[str, Any]:
    """Organisation-level risk summary from repository data."""
    dashboard = multi_repository_dashboard(repositories)

    # Risk score: weighted severity counts
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    risk_score = sum(
        dashboard["total_by_severity"].get(s, 0) * w
        for s, w in weights.items()
    )

    # Identify highest-risk repos
    ranked = sorted(
        dashboard["repositories"],
        key=lambda r: sum(
            r["by_severity"].get(s, 0) * weights.get(s, 0) for s in SEVERITIES
        ),
        reverse=True,
    )

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "organisation_risk_overview",
        "organisation": organisation,
        "risk_score": risk_score,
        "total_findings": dashboard["total_findings"],
        "total_by_severity": dashboard["total_by_severity"],
        "highest_risk_repositories": [r["repository"] for r in ranked[:5]],
    }


def repository_trends(
    snapshots: list[dict[str, Any]],
) -> dict[str, Any]:
    """Track finding counts over time for a single repository.

    Each snapshot has 'timestamp' and 'findings' (list).
    """
    if not snapshots:
        return {
            "schema_version": MANAGEMENT_SCHEMA_VERSION,
            "type": "repository_trends",
            "snapshots": [],
            "direction": "stable",
        }

    trend_points = []
    for snap in snapshots:
        findings = snap.get("findings", [])
        trend_points.append({
            "timestamp": snap.get("timestamp"),
            "total": len(findings),
            "by_severity": _severity_counts(findings),
        })

    # Direction: compare first vs last
    if len(trend_points) >= 2:
        first, last = trend_points[0]["total"], trend_points[-1]["total"]
        direction = "improving" if last < first else (
            "worsening" if last > first else "stable"
        )
    else:
        direction = "stable"

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "repository_trends",
        "snapshots": trend_points,
        "direction": direction,
    }


def scanner_health_summary(
    scanner_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise scanner health from run metadata.

    Each run has 'scanner', 'success' (bool), 'duration_seconds' (float),
    and optionally 'version', 'timestamp'.
    """
    by_scanner = _group_by(scanner_runs, "scanner")
    summaries = {}

    for scanner, runs in by_scanner.items():
        successes = sum(1 for r in runs if r.get("success", False))
        durations = [r["duration_seconds"] for r in runs if "duration_seconds" in r]
        versions = {r.get("version", "unknown") for r in runs}
        summaries[scanner] = {
            "total_runs": len(runs),
            "successes": successes,
            "failures": len(runs) - successes,
            "success_rate": successes / len(runs) if runs else 0.0,
            "avg_duration_seconds": (
                sum(durations) / len(durations) if durations else None
            ),
            "versions_seen": sorted(versions),
        }

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "scanner_health",
        "scanners": summaries,
    }


def policy_compliance_summary(
    evaluations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate policy evaluation results.

    Each evaluation has 'repository', 'policy', 'passed' (bool).
    """
    total = len(evaluations)
    passed = sum(1 for e in evaluations if e.get("passed", False))
    by_policy = _group_by(evaluations, "policy")
    policy_rates = {
        name: sum(1 for e in evals if e.get("passed", False)) / len(evals)
        for name, evals in by_policy.items()
    }

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "policy_compliance",
        "total_evaluations": total,
        "passed": passed,
        "failed": total - passed,
        "compliance_rate": passed / total if total else 1.0,
        "by_policy": policy_rates,
    }


def mean_time_to_remediation(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate MTTR from findings with opened_at and resolved_at timestamps.

    Timestamps are epoch seconds (float).
    """
    remediated = [
        f for f in findings
        if f.get("resolved_at") is not None and f.get("opened_at") is not None
    ]
    if not remediated:
        return {
            "schema_version": MANAGEMENT_SCHEMA_VERSION,
            "type": "mean_time_to_remediation",
            "mttr_seconds": None,
            "mttr_days": None,
            "sample_size": 0,
        }

    deltas = [
        f["resolved_at"] - f["opened_at"]
        for f in remediated
    ]
    mttr = sum(deltas) / len(deltas)

    by_severity: dict[str, list[float]] = {}
    for f in remediated:
        sev = f.get("severity", "info").lower()
        by_severity.setdefault(sev, []).append(
            f["resolved_at"] - f["opened_at"]
        )

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "mean_time_to_remediation",
        "mttr_seconds": mttr,
        "mttr_days": mttr / 86400,
        "sample_size": len(remediated),
        "by_severity": {
            s: sum(ds) / len(ds) / 86400  # days
            for s, ds in by_severity.items()
        },
    }


def finding_ownership_summary(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise finding ownership by assignee."""
    by_owner = _group_by(findings, "owner")
    summary = {}
    unassigned = 0

    for owner, owned in by_owner.items():
        if owner in ("unknown", None, ""):
            unassigned += len(owned)
            continue
        summary[owner] = {
            "total": len(owned),
            "by_severity": _severity_counts(owned),
            "open": sum(1 for f in owned if f.get("status") != "resolved"),
        }

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "finding_ownership",
        "assigned": len(findings) - unassigned,
        "unassigned": unassigned,
        "owners": summary,
    }


def suppression_expiry_summary(
    suppressions: list[dict[str, Any]],
    *,
    current_time: float | None = None,
) -> dict[str, Any]:
    """Identify suppressions that are expired or expiring soon.

    Each suppression has 'expires_at' (epoch seconds) and 'finding_fingerprint'.
    """
    expired = []
    expiring_soon = []
    active = []

    for s in suppressions:
        exp = s.get("expires_at")
        if exp is None:
            active.append(s)  # no expiry = permanent
            continue
        if current_time is not None and exp <= current_time:
            expired.append(s)
        elif current_time is not None and exp <= current_time + 7 * 86400:
            expiring_soon.append(s)
        else:
            active.append(s)

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "suppression_expiry",
        "total": len(suppressions),
        "active": len(active),
        "expired": len(expired),
        "expiring_within_7_days": len(expiring_soon),
        "expired_fingerprints": [
            s.get("finding_fingerprint") for s in expired
        ],
    }


def benchmark_drift_summary(
    baseline_metrics: dict[str, Any],
    current_metrics: dict[str, Any],
) -> dict[str, Any]:
    """Detect benchmark drift between two evaluation snapshots.

    Each metrics dict has tool-level precision/recall/f1.
    """
    drifts = []
    baseline_tools = baseline_metrics.get("tools", {})
    current_tools = current_metrics.get("tools", {})

    all_tools = set(baseline_tools) | set(current_tools)
    for tool in sorted(all_tools):
        bt = baseline_tools.get(tool, {})
        ct = current_tools.get(tool, {})
        for metric in ("precision", "recall", "f1"):
            bv = bt.get(metric)
            cv = ct.get(metric)
            if bv is not None and cv is not None:
                delta = cv - bv
                if abs(delta) > 0.01:  # ponytail: 1% threshold, tune if noisy
                    drifts.append({
                        "tool": tool,
                        "metric": metric,
                        "baseline": bv,
                        "current": cv,
                        "delta": round(delta, 4),
                    })

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "benchmark_drift",
        "has_drift": len(drifts) > 0,
        "drifts": drifts,
    }


def threat_intelligence_changes(
    baseline_enrichments: list[dict[str, Any]],
    current_enrichments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarise changes in threat intelligence enrichments between runs.

    Each enrichment has 'cve_id' and 'epss_score' / 'kev' / 'severity'.
    """
    baseline_by_cve = {e["cve_id"]: e for e in baseline_enrichments if "cve_id" in e}
    current_by_cve = {e["cve_id"]: e for e in current_enrichments if "cve_id" in e}

    new_cves = sorted(set(current_by_cve) - set(baseline_by_cve))
    removed_cves = sorted(set(baseline_by_cve) - set(current_by_cve))

    changed = []
    for cve in sorted(set(baseline_by_cve) & set(current_by_cve)):
        b, c = baseline_by_cve[cve], current_by_cve[cve]
        diffs = {}
        for field in ("epss_score", "kev", "severity"):
            bv, cv = b.get(field), c.get(field)
            if bv != cv:
                diffs[field] = {"was": bv, "now": cv}
        if diffs:
            changed.append({"cve_id": cve, "changes": diffs})

    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "threat_intelligence_changes",
        "new_cves": new_cves,
        "removed_cves": removed_cves,
        "changed": changed,
        "total_changes": len(new_cves) + len(removed_cves) + len(changed),
    }


# ── Success metrics ──────────────────────────────────────────────


def suppression_expiry_rate(
    suppressions: list[dict[str, Any]],
    *,
    current_time: float | None = None,
) -> dict[str, Any]:
    """Fraction of suppressions that expired without renewal."""
    now = current_time if current_time is not None else 0.0
    total = len(suppressions)
    expired = sum(
        1
        for s in suppressions
        if s.get("expires_at") is not None and s["expires_at"] <= now
    )
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "suppression_expiry_rate",
        "total": total,
        "expired": expired,
        "rate": expired / total if total else 0.0,
    }


def reopened_finding_rate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Fraction of resolved findings that were reopened.

    Each finding may have a 'state_history' list with 'to_state' entries.
    A finding counts as reopened if it transitioned from a closed state
    (resolved/false_positive) back to open/acknowledged.
    """
    _CLOSED = {"resolved", "false_positive", "closed"}
    _OPEN = {"open", "acknowledged"}
    resolved = 0
    reopened = 0
    for f in findings:
        history = f.get("state_history", [])
        was_closed = False
        was_reopened = False
        for entry in history:
            ts = entry.get("to_state", "").lower()
            if ts in _CLOSED:
                was_closed = True
            elif ts in _OPEN and was_closed:
                was_reopened = True
        if was_closed:
            resolved += 1
        if was_reopened:
            reopened += 1
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "reopened_finding_rate",
        "resolved": resolved,
        "reopened": reopened,
        "rate": reopened / resolved if resolved else 0.0,
    }


def autofix_acceptance_rate(
    remediations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fraction of proposed automated fixes that were accepted.

    Each remediation has 'proposed' (bool) and 'accepted' (bool).
    """
    proposed = [r for r in remediations if r.get("proposed")]
    accepted = [r for r in proposed if r.get("accepted")]
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "autofix_acceptance_rate",
        "proposed": len(proposed),
        "accepted": len(accepted),
        "rate": len(accepted) / len(proposed) if proposed else 0.0,
    }


def autofix_verification_rate(
    remediations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fraction of accepted fixes that passed post-fix verification.

    Each remediation has 'accepted' (bool) and 'verified' (bool).
    """
    accepted = [r for r in remediations if r.get("accepted")]
    verified = [r for r in accepted if r.get("verified")]
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "autofix_verification_rate",
        "accepted": len(accepted),
        "verified": len(verified),
        "rate": len(verified) / len(accepted) if accepted else 0.0,
    }


def developer_hours_saved(
    remediations: list[dict[str, Any]],
    *,
    manual_hours_per_fix: float = 2.0,
) -> dict[str, Any]:
    """Estimate developer hours saved by automated remediation.

    Counts accepted+verified fixes and multiplies by the average manual
    remediation time.
    """
    # ponytail: simple multiplier, replace with per-rule estimates if needed
    auto_fixed = sum(
        1 for r in remediations if r.get("accepted") and r.get("verified")
    )
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "developer_hours_saved",
        "auto_fixed_count": auto_fixed,
        "manual_hours_per_fix": manual_hours_per_fix,
        "estimated_hours_saved": round(auto_fixed * manual_hours_per_fix, 1),
    }


def security_engineer_hours_saved(
    scan_runs: list[dict[str, Any]],
    *,
    manual_hours_per_triage: float = 0.5,
) -> dict[str, Any]:
    """Estimate security engineer hours saved by automated triage.

    Counts findings that were auto-triaged (scored, deduplicated, or
    policy-evaluated) without manual intervention.
    """
    # ponytail: simple multiplier, refine with activity-log data if available
    triaged = sum(
        f.get("findings_count", 0)
        for f in scan_runs
        if f.get("auto_triaged", True)
    )
    return {
        "schema_version": MANAGEMENT_SCHEMA_VERSION,
        "type": "security_engineer_hours_saved",
        "auto_triaged_findings": triaged,
        "manual_hours_per_triage": manual_hours_per_triage,
        "estimated_hours_saved": round(triaged * manual_hours_per_triage, 1),
    }
