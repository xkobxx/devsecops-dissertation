"""Render a concise PR summary without source or finding excerpts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any
from urllib.parse import quote

from trustgate.checks.summary import (
    _artifact_url,
    _blocking_ids,
    _cell,
    _decision,
    _finding_index,
    _finding_order,
    _validate_documents,
)


MARKER = "<!-- trustgate-pr-summary -->"
_MAX_COMMENT_BYTES = 32_768
_MAX_FINDING_ROWS = 10
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_COMMIT = re.compile(r"[0-9a-fA-F]{7,64}\Z")


def _repository(value: str) -> str:
    if not _REPOSITORY.fullmatch(value):
        raise ValueError("repository must use a safe owner/name value")
    return value


def _commit(value: str) -> str:
    if not _COMMIT.fullmatch(value):
        raise ValueError("commit must be a 7-64 character hexadecimal revision")
    return value


def _safe_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if any(ord(character) < 32 or character in "<>" for character in value):
        return None
    return value


def _location_link(
    finding: Mapping[str, Any],
    repository: str,
    commit: str,
) -> str:
    path = _safe_path(finding.get("file"))
    if path is None:
        return "repository-level"
    start = finding.get("start_line")
    end = finding.get("end_line")
    label = path
    fragment = ""
    if isinstance(start, int) and start > 0:
        label += f":{start}"
        fragment = f"#L{start}"
        if isinstance(end, int) and end > start:
            fragment += f"-L{end}"
    url = (
        f"https://github.com/{repository}/blob/{commit}/"
        f"{quote(path, safe='/')}{fragment}"
    )
    return f"[{_cell(label)}]({url})"


def _remediation_status(finding: Mapping[str, Any]) -> str:
    remediation = finding.get("remediation")
    if not isinstance(remediation, Mapping):
        return "not supplied"
    return (
        "available"
        if any(remediation.get(key) for key in ("summary", "guidance", "references"))
        else "not supplied"
    )


def render_pr_comment(
    scan_run: Mapping[str, Any],
    policy_result: Mapping[str, Any],
    *,
    repository: str,
    commit: str,
    baseline_difference: Mapping[str, Any] | None = None,
    baseline_gate: Mapping[str, Any] | None = None,
    artifact_url: str | None = None,
    dashboard_url: str | None = None,
) -> str:
    """Render one deterministic PR comment containing no free-form evidence text."""

    _validate_documents(scan_run, policy_result, baseline_difference, baseline_gate)
    safe_repository = _repository(repository)
    safe_commit = _commit(commit)
    safe_artifact_url = _artifact_url(artifact_url)
    safe_dashboard_url = _artifact_url(dashboard_url)

    by_id, by_fingerprint = _finding_index(scan_run)
    blocking_ids = _blocking_ids(policy_result, baseline_gate)
    new_fingerprints = (
        {str(value) for value in baseline_difference["new_findings"]}
        if baseline_difference is not None
        else set()
    )
    new_ids = {
        str(by_fingerprint[value]["finding_id"])
        for value in new_fingerprints
        if value in by_fingerprint
    }
    suppressed_ids = {
        str(finding["finding_id"])
        for finding in scan_run["findings"]
        if finding["status"] == "suppressed"
    }
    unscored_ids = {
        str(finding["finding_id"])
        for finding in scan_run["findings"]
        if finding.get("confidence") is None
    }
    visible_ids = blocking_ids | new_ids | suppressed_ids
    visible = [by_id[value] for value in visible_ids if value in by_id]

    new_count: object = (
        baseline_difference["summary"]["new_findings"]
        if baseline_difference is not None
        else "not compared"
    )
    lines = [
        MARKER,
        "## Trust Gate",
        "",
        f"**Release decision: {_decision(policy_result, baseline_gate)}**",
        "",
        "| Finding state | Count |",
        "| --- | ---: |",
        f"| Total | {len(scan_run['findings'])} |",
        f"| New | {_cell(new_count)} |",
        f"| Blocking | {len([value for value in blocking_ids if value in by_id])} |",
        f"| Suppressed | {len(suppressed_ids)} |",
        f"| Unscored | {len(unscored_ids)} |",
        "",
        "<details>",
        "<summary>Finding details</summary>",
        "",
    ]
    if visible:
        lines.extend(
            [
                "| Finding | State | Severity | Rule | Location | Remediation |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        ordered = sorted(visible, key=_finding_order)
        for finding in ordered[:_MAX_FINDING_ROWS]:
            finding_id = str(finding["finding_id"])
            states = [
                label
                for label, identifiers in (
                    ("new", new_ids),
                    ("blocking", blocking_ids),
                    ("suppressed", suppressed_ids),
                    ("unscored", unscored_ids),
                )
                if finding_id in identifiers
            ]
            lines.append(
                "| "
                + " | ".join(
                    (
                        _cell(finding_id),
                        _cell(", ".join(states)),
                        _cell(finding["normalised_severity"]),
                        _cell(f"{finding['scanner']}/{finding['rule_id']}"),
                        _location_link(finding, safe_repository, safe_commit),
                        _remediation_status(finding),
                    )
                )
                + " |"
            )
        if len(ordered) > _MAX_FINDING_ROWS:
            lines.extend(
                [
                    "",
                    f"_{len(ordered) - _MAX_FINDING_ROWS} additional finding(s) "
                    "are available in the workflow artifacts._",
                ]
            )
    else:
        lines.append("No new, blocking, or suppressed findings require review.")
    lines.extend(
        [
            "",
            "</details>",
            "",
            "<details>",
            "<summary>Policy and baseline</summary>",
            "",
        ]
    )
    lines.extend(
        [
            f"- Policy: `{_cell(policy_result['policy_name'])}@"
            f"{_cell(policy_result['policy_version'])}`",
            f"- Outcome: `{_cell(policy_result['outcome'])}`",
            f"- Threshold: `{_cell(policy_result['fail_on'])}`",
            "- Scanner failure policy: `"
            + _cell(policy_result["scanner_failure_policy"])
            + "`",
        ]
    )
    if baseline_difference is None:
        lines.append("- Baseline: not compared")
    else:
        lines.extend(
            [
                f"- New: {baseline_difference['summary']['new_findings']}",
                f"- Removed: {baseline_difference['summary']['removed_findings']}",
                f"- Worsened: {baseline_difference['summary']['worsened_findings']}",
                "- Differential gate: "
                + (
                    "not evaluated"
                    if baseline_gate is None
                    else ("pass" if baseline_gate["passed"] else "fail")
                ),
            ]
        )
    lines.extend(["", "</details>", ""])
    links = []
    if safe_artifact_url is not None:
        links.append(f"[Detailed workflow artifacts]({safe_artifact_url})")
    if safe_dashboard_url is not None:
        links.append(f"[Open dashboard]({safe_dashboard_url})")
    if links:
        lines.extend([" · ".join(links), ""])
    lines.append(
        "_This summary intentionally omits source, evidence, secret, and "
        "remediation excerpts._"
    )
    lines.append("")
    return "\n".join(lines)


def write_pr_comment(output: str | Path, content: str) -> Path:
    """Atomically write a comment that stays below GitHub's body limit."""

    if len(content.encode("utf-8")) >= _MAX_COMMENT_BYTES:
        raise ValueError("pull-request comment must be smaller than 32768 bytes")
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
