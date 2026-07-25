"""
Trust Gate legacy confidence scoring.

PROPRIETARY -- not covered by this repository's MIT LICENSE. See
LICENSE-COMMERCIAL. Requires a valid, unexpired license key to run.

Runtime tool: joins each finding against the generated, versioned confidence
artifact and attaches six explainable confidence concepts. The displayed value
is the posterior mean; prioritisation uses the lower credible bound and sample
maturity. Small samples remain Experimental or Directional.

A rule with no direct entry falls back to its tool's overall baseline
precision; every finding carries the sample_size and source ('rule' vs
'tool_baseline' vs 'unscored') it was estimated from, so low-confidence
estimates are visible rather than hidden behind a single misleading number.

Note on the license check below: action.yml already gates whether this
script gets invoked at all (see the "Check license" / "Score findings"
steps), so for anyone using the published Action this check never fails.
It exists for defense in depth -- so running this file directly, outside
the Action, doesn't hand out the paid feature for free.
"""

import argparse
import json
import sys

from trustgate.benchmarks.statistics import posterior_precision
from trustgate.confidence import build_confidence_components
from trustgate.licensing import verify
from trustgate.schema import migrate_scan_run, write_validated_json

HIGH_THRESHOLD = 0.7
LIKELY_THRESHOLD = 0.3


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Attach confidence scores/tiers to findings.json.')
    parser.add_argument('--input', default='reports/findings.json', help='findings.json to score')
    parser.add_argument('--output', default=None, help='Where to write the scored findings (default: overwrite --input)')
    parser.add_argument(
        '--confidence-table',
        default='benchmarks/reports/flask-vulnerable-v1.confidence.json',
        help='Path to the generated benchmark confidence artifact',
    )
    parser.add_argument('--license-key', default='', help='Required: a valid license key for this paid feature')
    return parser.parse_args(argv)


def tier_for(confidence):
    if confidence >= HIGH_THRESHOLD:
        return 'High'
    if confidence >= LIKELY_THRESHOLD:
        return 'Likely'
    return 'Noise'


def _reliability_score(entry):
    if not entry:
        return None
    if "displayed_estimate" in entry and "gating_estimate" in entry:
        return entry
    true_positives = entry.get("tp")
    false_positives = entry.get("fp")
    if (
        isinstance(true_positives, int)
        and not isinstance(true_positives, bool)
        and isinstance(false_positives, int)
        and not isinstance(false_positives, bool)
    ):
        return posterior_precision(true_positives, false_positives)
    precision = entry.get("precision")
    sample_size = entry.get("sample_size")
    if not isinstance(precision, (int, float)) or isinstance(precision, bool):
        return None
    if not isinstance(sample_size, int) or isinstance(sample_size, bool):
        sample_size = 0
    estimated_true = round(float(precision) * sample_size)
    return posterior_precision(
        estimated_true,
        max(0, sample_size - estimated_true),
    )


def score_finding(finding, rules, tool_baseline):
    tool = finding.get('scanner', finding.get('tool'))
    key = f"{tool}:{finding.get('rule_id')}"

    if key in rules:
        source = 'rule'
        reliability = _reliability_score(rules[key])
    elif tool in tool_baseline:
        source = 'tool_baseline'
        reliability = _reliability_score(tool_baseline[tool])
    else:
        source = 'unscored'
        reliability = None
    components = build_confidence_components(finding, reliability)
    overall = components["overall_decision_confidence"]
    interval = (
        reliability.get("interval")
        if reliability is not None
        else None
    )
    return {
        'confidence': overall["estimate"],
        'confidence_sample_size': overall["sample_size"],
        'confidence_method': (
            f"{source}:beta-binomial:{reliability['methodology_version']}"
            if reliability is not None
            else 'unscored'
        ),
        'confidence_interval': interval,
        **components,
    }


def decision_tier(finding):
    component = finding.get("overall_decision_confidence")
    if isinstance(component, dict):
        return str(component.get("decision_tier") or "Unscored")
    confidence = finding.get("confidence")
    return "Unscored" if confidence is None else tier_for(confidence)


def main(argv=None):
    args = parse_args(argv)
    output_path = args.output or args.input

    valid, reason, _payload = verify(args.license_key)
    if not valid:
        print(f"score_findings.py requires a valid license key ({reason}). "
              f"Subscribe at https://buy.stripe.com/3cIfZgaf2eTrb627pBb7y00 -- "
              f"see README.md for details.", file=sys.stderr)
        sys.exit(1)

    with open(args.confidence_table) as f:
        table = json.load(f)
    rules = table.get('rules', {})
    tool_baseline = table.get('tool_baseline', {})

    with open(args.input) as f:
        data = migrate_scan_run(json.load(f))

    findings = data.get('findings', [])
    for finding in findings:
        finding.update(score_finding(finding, rules, tool_baseline))

    data['findings'] = findings
    write_validated_json(output_path, data, schema_name='scan-run')

    counts = {
        'High': 0,
        'Likely': 0,
        'Noise': 0,
        'Experimental': 0,
        'Directional': 0,
        'Unscored': 0,
    }
    for finding in findings:
        tier = decision_tier(finding)
        if tier not in counts:
            tier = 'Unscored'
        counts[tier] += 1

    print(f"Scored {len(findings)} findings -> {output_path}")
    print(
        "  "
        + "  ".join(
            f"{tier}: {count}"
            for tier, count in counts.items()
        )
    )
    print("Act on these first:")
    for finding in sorted(
        findings,
        key=lambda f: (
            decision_tier(f) != 'High',
            -(f['confidence'] or 0),
        ),
    ):
        if decision_tier(finding) != 'High':
            break
        print(
            f"  [{finding['scanner']}] {finding.get('rule_id')} - "
            f"{finding.get('description')} "
            f"({finding.get('file')} line {finding.get('start_line')})"
        )


if __name__ == '__main__':
    main()
