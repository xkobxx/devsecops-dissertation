"""
score_findings.py

PROPRIETARY -- not covered by this repository's MIT LICENSE. See
LICENSE-COMMERCIAL. Requires a valid, unexpired license key to run.

Runtime tool: joins each finding in findings.json against confidence_table.json
(built by build_confidence_table.py) and attaches a confidence score + tier, so
a team can act on the findings likely to be real and deprioritise likely noise.

Tiering:
  High    -- confidence >= 0.7
  Likely  -- 0.3 <= confidence < 0.7
  Noise   -- confidence < 0.3
  Unscored -- the tool has no ground-truth coverage in confidence_table.json
              (today: pip-audit, Trivy, Gitleaks) -- shown as-is, not scored.

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

# scripts/ is on sys.path[0] when this file is run directly (python's
# default behaviour), so this resolves regardless of the caller's cwd.
from verify_license import verify

HIGH_THRESHOLD = 0.7
LIKELY_THRESHOLD = 0.3


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Attach confidence scores/tiers to findings.json.')
    parser.add_argument('--input', default='reports/findings.json', help='findings.json to score')
    parser.add_argument('--output', default=None, help='Where to write the scored findings (default: overwrite --input)')
    parser.add_argument('--confidence-table', default='confidence_table.json', help='Path to confidence_table.json')
    parser.add_argument('--license-key', default='', help='Required: a valid license key for this paid feature')
    return parser.parse_args(argv)


def tier_for(confidence):
    if confidence >= HIGH_THRESHOLD:
        return 'High'
    if confidence >= LIKELY_THRESHOLD:
        return 'Likely'
    return 'Noise'


def score_finding(finding, rules, tool_baseline):
    tool = finding.get('tool')
    key = f"{tool}:{finding.get('rule_id')}"

    if key in rules:
        entry = rules[key]
        return {
            'confidence': entry['precision'],
            'confidence_tier': tier_for(entry['precision']),
            'confidence_sample_size': entry['sample_size'],
            'confidence_source': 'rule',
        }
    if tool in tool_baseline:
        entry = tool_baseline[tool]
        return {
            'confidence': entry['precision'],
            'confidence_tier': tier_for(entry['precision']),
            'confidence_sample_size': entry['sample_size'],
            'confidence_source': 'tool_baseline',
        }
    return {
        'confidence': None,
        'confidence_tier': 'Unscored',
        'confidence_sample_size': 0,
        'confidence_source': 'unscored',
    }


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
        data = json.load(f)

    findings = data.get('findings', [])
    for finding in findings:
        finding.update(score_finding(finding, rules, tool_baseline))

    data['findings'] = findings
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    counts = {'High': 0, 'Likely': 0, 'Noise': 0, 'Unscored': 0}
    for finding in findings:
        counts[finding['confidence_tier']] += 1

    print(f"Scored {len(findings)} findings -> {output_path}")
    print(f"  High: {counts['High']}  Likely: {counts['Likely']}  Noise: {counts['Noise']}  Unscored: {counts['Unscored']}")
    print("Act on these first:")
    for finding in sorted(findings, key=lambda f: (f['confidence_tier'] != 'High', -(f['confidence'] or 0))):
        if finding['confidence_tier'] != 'High':
            break
        print(f"  [{finding['tool']}] {finding.get('rule_id')} - {finding.get('description')} ({finding.get('file')} line {finding.get('line')})")


if __name__ == '__main__':
    main()
