"""Command-line interface for Trust Gate."""

from argparse import ArgumentParser
from collections.abc import Sequence

from trustgate import __version__
from trustgate.adapters.cli import add_list_arguments as add_adapter_list_arguments
from trustgate.adapters.cli import add_run_arguments as add_adapter_run_arguments
from trustgate.adapters.cli import run_adapter
from trustgate.adapters.cli import run_list as list_adapters
from trustgate.aggregation import add_arguments as add_aggregation_arguments
from trustgate.aggregation import run as run_aggregation
from trustgate.baselines.cli import add_arguments as add_baseline_arguments
from trustgate.baselines.cli import run as run_baseline
from trustgate.benchmarks.cli import add_arguments as add_benchmark_arguments
from trustgate.benchmarks.cli import run as run_benchmark
from trustgate.checks.cli import add_arguments as add_check_arguments
from trustgate.checks.cli import run as run_checks
from trustgate.comments.cli import add_arguments as add_comment_arguments
from trustgate.comments.cli import run as run_comment
from trustgate.dast.cli import add_arguments as add_dast_arguments
from trustgate.dast.cli import run as run_dast
from trustgate.decisions.cli import add_arguments as add_decision_arguments
from trustgate.decisions.cli import run as run_decision
from trustgate.evidence.cli import add_arguments as add_evidence_arguments
from trustgate.evidence.cli import run as run_evidence
from trustgate.lifecycle.cli import add_arguments as add_suppression_arguments
from trustgate.lifecycle.cli import run as run_suppression
from trustgate.planning.cli import add_arguments as add_plan_arguments
from trustgate.planning.cli import run as run_plan
from trustgate.policy.cli import add_arguments as add_policy_arguments
from trustgate.policy.cli import run as run_policy
from trustgate.reachability.cli import add_arguments as add_reachability_arguments
from trustgate.reachability.cli import run as run_reachability
from trustgate.remediation.cli import add_arguments as add_remediation_arguments
from trustgate.remediation.cli import run as run_remediation
from trustgate.reporting import add_arguments as add_reporting_arguments
from trustgate.reporting import run as run_reporting
from trustgate.sarif.cli import add_arguments as add_sarif_arguments
from trustgate.sarif.cli import run as run_sarif
from trustgate.scanners.cli import add_arguments as add_scanner_arguments
from trustgate.scanners.cli import add_record_arguments
from trustgate.scanners.cli import run as run_scanner
from trustgate.scanners.cli import run_record as record_scanner
from trustgate.supply_chain.cli import add_arguments as add_sbom_arguments
from trustgate.supply_chain.cli import run as run_sbom
from trustgate.threat_intelligence.cli import (
    add_arguments as add_enrichment_arguments,
)
from trustgate.threat_intelligence.cli import run as run_enrichment
from trustgate.release_verify import add_arguments as add_verify_arguments
from trustgate.release_verify import run as run_verify
from trustgate.vex.cli import add_arguments as add_vex_arguments
from trustgate.vex.cli import run as run_vex


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="trustgate",
        description="Trust Gate: a local-first application-security decision platform.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")
    adapter_list = commands.add_parser(
        "adapter-list",
        help="List scanner adapters and repository applicability.",
    )
    add_adapter_list_arguments(adapter_list)
    adapter_list.set_defaults(handler=list_adapters)
    adapter_run = commands.add_parser(
        "adapter-run",
        help="Run an applicable scanner through its adapter lifecycle.",
    )
    add_adapter_run_arguments(adapter_run)
    adapter_run.set_defaults(handler=run_adapter)
    plan = commands.add_parser(
        "plan",
        help="Explain scanner selection and execution inputs without scanning.",
    )
    add_plan_arguments(plan)
    plan.set_defaults(handler=run_plan)
    aggregate = commands.add_parser(
        "aggregate",
        help="Aggregate scanner reports and evaluate the legacy severity gate.",
    )
    add_aggregation_arguments(aggregate)
    aggregate.set_defaults(handler=run_aggregation)
    enrich = commands.add_parser(
        "enrich",
        help="Enrich a canonical scan run with cached or live threat metadata.",
    )
    add_enrichment_arguments(enrich)
    enrich.set_defaults(handler=run_enrichment)
    reachability = commands.add_parser(
        "reachability",
        help="Analyze dependency, source-to-sink, and dynamic reachability evidence.",
    )
    add_reachability_arguments(reachability)
    reachability.set_defaults(handler=run_reachability)
    dast = commands.add_parser(
        "dast",
        help="Build or execute a scope- and resource-bounded DAST plan.",
    )
    add_dast_arguments(dast)
    dast.set_defaults(handler=run_dast)
    decide = commands.add_parser(
        "decide",
        help="Evaluate findings with an explainable contextual policy.",
    )
    add_decision_arguments(decide)
    decide.set_defaults(handler=run_decision)
    policy = commands.add_parser(
        "policy",
        help="Validate, test, explain, or simulate policy-as-code.",
    )
    add_policy_arguments(policy)
    policy.set_defaults(handler=run_policy)
    baseline = commands.add_parser(
        "baseline",
        help="Create or compare a default-branch finding baseline.",
    )
    add_baseline_arguments(baseline)
    baseline.set_defaults(handler=run_baseline)
    suppression = commands.add_parser(
        "suppression",
        help="Create, lint, apply, or revalidate finding suppressions.",
    )
    add_suppression_arguments(suppression)
    suppression.set_defaults(handler=run_suppression)
    sarif = commands.add_parser(
        "sarif",
        help="Generate validated SARIF 2.1.0 from canonical findings.",
    )
    add_sarif_arguments(sarif)
    sarif.set_defaults(handler=run_sarif)
    checks = commands.add_parser(
        "checks",
        help="Generate a bounded GitHub Check job summary.",
    )
    add_check_arguments(checks)
    checks.set_defaults(handler=run_checks)
    comment = commands.add_parser(
        "pr-comment",
        help="Generate a safe, consolidated pull-request comment.",
    )
    add_comment_arguments(comment)
    comment.set_defaults(handler=run_comment)
    sbom = commands.add_parser(
        "sbom",
        help="Generate deterministic CycloneDX and SPDX product SBOMs.",
    )
    add_sbom_arguments(sbom)
    sbom.set_defaults(handler=run_sbom)
    vex = commands.add_parser(
        "vex",
        help="Generate and optionally sign approved CycloneDX VEX.",
    )
    add_vex_arguments(vex)
    vex.set_defaults(handler=run_vex)
    evidence = commands.add_parser(
        "evidence",
        help="Generate or verify reproducible audit-evidence manifests.",
    )
    add_evidence_arguments(evidence)
    evidence.set_defaults(handler=run_evidence)
    remediate = commands.add_parser(
        "remediate",
        help="List, apply, or roll back deterministic source remediations.",
    )
    add_remediation_arguments(remediate)
    remediate.set_defaults(handler=run_remediation)
    report = commands.add_parser(
        "report",
        help="Generate a static HTML report from normalised findings.",
    )
    add_reporting_arguments(report)
    report.set_defaults(handler=run_reporting)
    benchmark = commands.add_parser(
        "benchmark",
        help="Generate or verify versioned benchmark publications.",
    )
    add_benchmark_arguments(benchmark)
    benchmark.set_defaults(handler=run_benchmark)
    scanner_run = commands.add_parser(
        "scanner-run",
        help="Run one scanner and persist authoritative health metadata.",
    )
    add_scanner_arguments(scanner_run)
    scanner_run.set_defaults(handler=run_scanner)
    scanner_record = commands.add_parser(
        "scanner-record",
        help="Record health metadata for a scanner run by an external Action.",
    )
    add_record_arguments(scanner_record)
    scanner_record.set_defaults(handler=record_scanner)
    verify = commands.add_parser(
        "verify-release",
        help="Verify all release gates pass before publishing.",
    )
    add_verify_arguments(verify)
    verify.set_defaults(handler=run_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


__all__ = ["build_parser", "main"]
