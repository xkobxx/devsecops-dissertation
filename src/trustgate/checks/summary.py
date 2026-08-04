"""Bounded, evidence-aware Markdown for GitHub Actions Check Runs."""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlsplit

from trustgate.schema import validate_instance


_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}
_MAX_FINDING_ROWS = 10


def _cell(value: object) -> str:
    entities = {
        "\\": "&#92;",
        "*": "&#42;",
        "_": "&#95;",
        "[": "&#91;",
        "]": "&#93;",
        "#": "&#35;",
        "!": "&#33;",
        "`": "&#96;",
        "|": "&#124;",
        "~": "&#126;",
        "\r": " ",
        "\n": " ",
    }
    return "".join(
        entities.get(character, escape(character, quote=False))
        for character in str(value)
    )


def _artifact_url(value: str | None) -> str | None:
    if value is None or not value:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or any(character in value for character in "<>[]() \t\r\n")
    ):
        raise ValueError("artifact URL must be an absolute safe HTTPS URL")
    return value


def _validate_documents(
    scan_run: Mapping[str, Any],
    policy_result: Mapping[str, Any],
    baseline_difference: Mapping[str, Any] | None,
    baseline_gate: Mapping[str, Any] | None,
) -> None:
    validate_instance("scan-run", scan_run)
    validate_instance("policy-result", policy_result)
    if policy_result["run_id"] != scan_run["run_id"]:
        raise ValueError("policy result belongs to a different scan run")
    if baseline_difference is not None:
        validate_instance("baseline-diff", baseline_difference)
        if baseline_difference["current_run_id"] != scan_run["run_id"]:
            raise ValueError("baseline difference belongs to a different scan run")
    if baseline_gate is not None:
        validate_instance("baseline-gate", baseline_gate)
        if baseline_gate["current_run_id"] != scan_run["run_id"]:
            raise ValueError("baseline gate belongs to a different scan run")
        if (
            baseline_difference is not None
            and baseline_gate["comparison_digest"]
            != baseline_difference["comparison_digest"]
        ):
            raise ValueError("baseline gate does not match the baseline difference")


def _decision(
    policy_result: Mapping[str, Any],
    baseline_gate: Mapping[str, Any] | None,
) -> str:
    if policy_result["outcome"] in {"fail", "error"}:
        return "FAIL"
    if baseline_gate is not None and not baseline_gate["passed"]:
        return "FAIL"
    if policy_result["outcome"] == "warn":
        return "WARN"
    return "PASS"


def _finding_index(scan_run: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_id = {
        str(finding["finding_id"]): finding
        for finding in scan_run["findings"]
    }
    by_fingerprint = {
        str(finding["fingerprint"]): finding
        for finding in scan_run["findings"]
    }
    return by_id, by_fingerprint


def _blocking_ids(
    policy_result: Mapping[str, Any],
    baseline_gate: Mapping[str, Any] | None,
) -> set[str]:
    identifiers = {str(value) for value in policy_result["matched_finding_ids"]}
    if baseline_gate is not None:
        identifiers.update(
            str(finding["finding_id"])
            for finding in baseline_gate["blocked_findings"]
        )
    return identifiers


def _finding_order(finding: Mapping[str, Any]) -> tuple[int, str]:
    return (
        -_SEVERITY_RANK.get(str(finding["normalised_severity"]), 0),
        str(finding["finding_id"]),
    )


def _location(finding: Mapping[str, Any]) -> str:
    path = finding.get("file")
    if not isinstance(path, str) or not path:
        return "repository-level"
    line = finding.get("start_line")
    return f"{path}:{line}" if isinstance(line, int) else path


def _finding_table(findings: list[Mapping[str, Any]]) -> list[str]:
    lines = [
        "| Finding | Severity | Rule | Location |",
        "| --- | --- | --- | --- |",
    ]
    for finding in sorted(findings, key=_finding_order)[:_MAX_FINDING_ROWS]:
        lines.append(
            "| "
            + " | ".join(
                (
                    _cell(finding["finding_id"]),
                    _cell(finding["normalised_severity"]),
                    _cell(f"{finding['scanner']}/{finding['rule_id']}"),
                    _cell(_location(finding)),
                )
            )
            + " |"
        )
    if len(findings) > _MAX_FINDING_ROWS:
        lines.append(
            f"\n_{len(findings) - _MAX_FINDING_ROWS} additional finding(s) are "
            "available in the detailed artifacts._"
        )
    return lines


def _evidence_explanation(finding: Mapping[str, Any]) -> str:
    remediation = finding.get("remediation")
    has_remediation = isinstance(remediation, Mapping) and bool(
        remediation.get("summary")
    )
    return "; ".join(
        (
            f"{finding['normalised_severity']} severity",
            f"{finding['reachability']} reachability",
            f"{finding['category']} evidence from {finding['scanner']}",
            "remediation available" if has_remediation else "remediation unavailable",
        )
    )


def render_check_summary(
    scan_run: Mapping[str, Any],
    policy_result: Mapping[str, Any],
    *,
    baseline_difference: Mapping[str, Any] | None = None,
    baseline_gate: Mapping[str, Any] | None = None,
    artifact_url: str | None = None,
) -> str:
    """Render one deterministic, bounded GitHub Check job summary."""

    _validate_documents(scan_run, policy_result, baseline_difference, baseline_gate)
    safe_artifact_url = _artifact_url(artifact_url)
    by_id, by_fingerprint = _finding_index(scan_run)
    blocking_ids = _blocking_ids(policy_result, baseline_gate)
    blocking = [by_id[value] for value in blocking_ids if value in by_id]
    new_findings = (
        [
            by_fingerprint[value]
            for value in baseline_difference["new_findings"]
            if value in by_fingerprint
        ]
        if baseline_difference is not None
        else []
    )
    suppressed = [
        finding for finding in scan_run["findings"] if finding["status"] == "suppressed"
    ]
    unscored = [
        finding for finding in scan_run["findings"] if finding.get("confidence") is None
    ]
    decision = _decision(policy_result, baseline_gate)

    lines = [
        "# Trust Gate check",
        "",
        f"**Release decision: {decision}**",
        "",
        _cell(policy_result["reason"]),
        "",
        "## Scanner health",
        "",
        "| Scanner | Required | State | Healthy | Findings | Version |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for scanner in sorted(scan_run["scanners"], key=lambda item: item["scanner"]):
        lines.append(
            "| "
            + " | ".join(
                (
                    _cell(scanner["scanner"]),
                    "yes" if scanner["required"] else "no",
                    _cell(scanner["state"]),
                    "yes" if scanner["healthy"] else "no",
                    _cell(scanner["finding_count"]),
                    _cell(scanner.get("scanner_version") or "unknown"),
                )
            )
            + " |"
        )

    new_count: object = (
        baseline_difference["summary"]["new_findings"]
        if baseline_difference is not None
        else "not compared"
    )
    lines.extend(
        [
            "",
            "## Finding overview",
            "",
            "| Classification | Count |",
            "| --- | ---: |",
            f"| Total | {len(scan_run['findings'])} |",
            f"| New | {_cell(new_count)} |",
            f"| Blocking | {len(blocking)} |",
            f"| Suppressed | {len(suppressed)} |",
            f"| Unscored | {len(unscored)} |",
            "",
            "## New findings",
            "",
        ]
    )
    if baseline_difference is None:
        lines.append("No baseline comparison was supplied for this run.")
    elif new_findings:
        lines.extend(_finding_table(new_findings))
    else:
        lines.append("No new findings were identified.")

    lines.extend(["", "## Blocking findings", ""])
    if blocking:
        lines.extend(_finding_table(blocking))
    else:
        lines.append("No findings blocked the release decision.")

    lines.extend(["", "## Suppressed findings", ""])
    if suppressed:
        lines.extend(_finding_table(suppressed))
    else:
        lines.append("No findings are currently suppressed.")

    lines.extend(["", "## Unscored findings", ""])
    if unscored:
        lines.extend(_finding_table(unscored))
    else:
        lines.append("Every finding has a confidence score.")

    explained = {str(item["finding_id"]): item for item in [*blocking, *new_findings]}
    lines.extend(["", "## Evidence explanations", ""])
    if explained:
        lines.extend(
            [
                "| Finding | Explanation |",
                "| --- | --- |",
                *(
                    f"| {_cell(finding['finding_id'])} | "
                    f"{_cell(_evidence_explanation(finding))} |"
                    for finding in sorted(explained.values(), key=_finding_order)[
                        :_MAX_FINDING_ROWS
                    ]
                ),
            ]
        )
    else:
        lines.append("No new or blocking finding required an explanation.")

    lines.extend(
        [
            "",
            "## Policy",
            "",
            f"- Policy: `{_cell(policy_result['policy_name'])}@"
            f"{_cell(policy_result['policy_version'])}`",
            f"- Outcome: `{_cell(policy_result['outcome'])}`",
            "- Severity basis: `"
            + _cell(policy_result["metadata"].get("severity_basis", "normalised"))
            + "`",
            f"- Threshold: `{_cell(policy_result['fail_on'])}`",
            f"- Scanner failure policy: `{_cell(policy_result['scanner_failure_policy'])}`",
            f"- Waivers: {len(policy_result['waivers'])}",
            "",
            "## Baseline comparison",
            "",
        ]
    )
    if baseline_difference is None:
        lines.append("No baseline comparison was supplied for this run.")
    else:
        baseline_rows = (
            ("New", "new_findings"),
            ("Removed", "removed_findings"),
            ("Persisting", "persisting_findings"),
            ("Worsened", "worsened_findings"),
            ("Newly reachable", "newly_reachable_findings"),
            ("Newly exploited", "newly_exploited_dependencies"),
            ("Expired suppressions", "expired_suppressions"),
            ("Scanner coverage regressions", "scanner_coverage_regressions"),
        )
        lines.extend(["| Change | Count |", "| --- | ---: |"])
        for label, key in baseline_rows:
            lines.append(f"| {label} | {baseline_difference['summary'][key]} |")
        if baseline_gate is not None:
            lines.append(
                f"\nDifferential gate: **{'PASS' if baseline_gate['passed'] else 'FAIL'}** "
                f"(`{_cell(baseline_gate['gate_mode'])}` mode)."
            )

    lines.extend(["", "## Detailed artifacts", ""])
    if safe_artifact_url is not None:
        lines.append(f"[Detailed workflow artifacts]({safe_artifact_url})")
    else:
        lines.append("Use this workflow run's artifacts for the complete evidence bundle.")
    lines.extend(
        [
            "",
            "Expected files: `reports/findings.json`, `reports/policy-result.json`, "
            "`reports/trustgate.sarif`, and `reports/dashboard.html`.",
            "",
        ]
    )
    return "\n".join(lines)


def write_check_summary(output: str | Path, content: str) -> Path:
    """Atomically publish a bounded UTF-8 Check summary."""

    encoded = content.encode("utf-8")
    if len(encoded) >= 65_536:
        raise ValueError("GitHub Check summary must be smaller than 65536 bytes")
    output_path = Path(output)
    if output_path.is_symlink():
        raise OSError(f"refusing to replace symlinked output: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary_path = Path(temporary.name)
        temporary_path.replace(output_path)
    except BaseException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    return output_path
