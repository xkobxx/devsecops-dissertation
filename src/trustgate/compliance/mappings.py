"""Compliance framework mappings and evidence reports.

Each framework mapping records:
- Which controls Trust Gate can provide automated evidence for
- Which controls still require manual verification
- A version string so mappings can be reviewed and updated

Reports say "evidence available" — never "compliant".
"""

from __future__ import annotations

import json
from typing import Any

COMPLIANCE_SCHEMA_VERSION = "1.0.0"


class ComplianceMappingError(ValueError):
    """Raised when a compliance mapping or query is invalid."""


# --- Framework definitions ---
# Each framework has: id, name, version (of the mapping), controls.
# Controls list what TrustGate can provide evidence for (automated)
# vs what requires human review (manual_verification_required).

_OWASP_TOP_10 = {
    "id": "owasp-top-10",
    "name": "OWASP Top 10",
    "mapping_version": "2021.1",
    "controls": [
        {
            "control_id": "A01",
            "title": "Broken Access Control",
            "automated_evidence": [
                "SAST findings for access control flaws",
                "DAST testing of authentication endpoints",
            ],
            "manual_verification_required": [
                "Business logic access control review",
                "Role-based access control completeness",
            ],
        },
        {
            "control_id": "A02",
            "title": "Cryptographic Failures",
            "automated_evidence": [
                "SAST detection of weak cryptographic algorithms",
                "Dependency scanning for vulnerable crypto libraries",
            ],
            "manual_verification_required": [
                "Key management process review",
                "Data classification alignment",
            ],
        },
        {
            "control_id": "A03",
            "title": "Injection",
            "automated_evidence": [
                "SAST detection of SQL/NoSQL/OS/LDAP injection",
                "DAST injection testing",
                "Reachability analysis for injection sinks",
            ],
            "manual_verification_required": [
                "Custom query builder review",
            ],
        },
        {
            "control_id": "A04",
            "title": "Insecure Design",
            "automated_evidence": [],
            "manual_verification_required": [
                "Threat modelling review",
                "Secure design pattern verification",
            ],
        },
        {
            "control_id": "A05",
            "title": "Security Misconfiguration",
            "automated_evidence": [
                "IaC scanning for misconfigurations",
                "Container security scanning",
                "Kubernetes manifest analysis",
            ],
            "manual_verification_required": [
                "Runtime configuration audit",
            ],
        },
        {
            "control_id": "A06",
            "title": "Vulnerable and Outdated Components",
            "automated_evidence": [
                "SCA/dependency scanning",
                "SBOM generation",
                "VEX advisories",
                "Threat intelligence enrichment",
            ],
            "manual_verification_required": [
                "Component update feasibility assessment",
            ],
        },
        {
            "control_id": "A07",
            "title": "Identification and Authentication Failures",
            "automated_evidence": [
                "SAST detection of hardcoded credentials",
                "DAST authentication testing",
            ],
            "manual_verification_required": [
                "MFA implementation review",
                "Session management audit",
            ],
        },
        {
            "control_id": "A08",
            "title": "Software and Data Integrity Failures",
            "automated_evidence": [
                "Supply chain analysis",
                "SBOM integrity verification",
            ],
            "manual_verification_required": [
                "CI/CD pipeline security review",
                "Code signing process verification",
            ],
        },
        {
            "control_id": "A09",
            "title": "Security Logging and Monitoring Failures",
            "automated_evidence": [
                "SAST detection of missing logging",
            ],
            "manual_verification_required": [
                "Log completeness review",
                "Alerting coverage audit",
                "Incident response process review",
            ],
        },
        {
            "control_id": "A10",
            "title": "Server-Side Request Forgery (SSRF)",
            "automated_evidence": [
                "SAST detection of SSRF patterns",
                "DAST SSRF testing",
            ],
            "manual_verification_required": [
                "Network segmentation review",
            ],
        },
    ],
}

_OWASP_ASVS = {
    "id": "owasp-asvs",
    "name": "OWASP Application Security Verification Standard",
    "mapping_version": "4.0.3",
    "controls": [
        {
            "control_id": "V1",
            "title": "Architecture, Design and Threat Modelling",
            "automated_evidence": ["Dependency graph analysis"],
            "manual_verification_required": [
                "Architecture review", "Threat model validation",
            ],
        },
        {
            "control_id": "V5",
            "title": "Validation, Sanitization and Encoding",
            "automated_evidence": [
                "SAST input validation findings",
                "Injection detection results",
            ],
            "manual_verification_required": [
                "Custom validation logic review",
            ],
        },
        {
            "control_id": "V14",
            "title": "Configuration",
            "automated_evidence": [
                "IaC scanning results",
                "Container security findings",
            ],
            "manual_verification_required": [
                "Runtime configuration audit",
            ],
        },
    ],
}

_OWASP_SAMM = {
    "id": "owasp-samm",
    "name": "OWASP Software Assurance Maturity Model",
    "mapping_version": "2.0",
    "controls": [
        {
            "control_id": "Implementation:Secure Build",
            "title": "Secure Build",
            "automated_evidence": [
                "CI pipeline security scanning evidence",
                "SBOM generation",
                "Reproducible build evidence",
            ],
            "manual_verification_required": [
                "Build process integrity review",
            ],
        },
        {
            "control_id": "Verification:Security Testing",
            "title": "Security Testing",
            "automated_evidence": [
                "SAST/DAST/SCA scan results",
                "Benchmark evaluation metrics",
                "Scanner health data",
            ],
            "manual_verification_required": [
                "Penetration testing scope review",
            ],
        },
    ],
}

_NIST_SSDF = {
    "id": "nist-ssdf",
    "name": "NIST Secure Software Development Framework",
    "mapping_version": "1.1",
    "controls": [
        {
            "control_id": "PW.7",
            "title": "Review and/or Analyze Human-Readable Code",
            "automated_evidence": [
                "SAST scan results with rule coverage",
                "Reachability analysis evidence",
            ],
            "manual_verification_required": [
                "Code review process documentation",
            ],
        },
        {
            "control_id": "PW.8",
            "title": "Test Executable Code",
            "automated_evidence": [
                "DAST scan results",
                "Security test coverage reports",
            ],
            "manual_verification_required": [
                "Test adequacy assessment",
            ],
        },
        {
            "control_id": "PS.3",
            "title": "Archive and Protect Software Releases",
            "automated_evidence": [
                "SBOM generation evidence",
                "VEX advisory records",
            ],
            "manual_verification_required": [
                "Release process security review",
            ],
        },
    ],
}

_CWE = {
    "id": "cwe",
    "name": "Common Weakness Enumeration",
    "mapping_version": "4.14",
    "controls": [
        {
            "control_id": "CWE-Mapping",
            "title": "CWE ID Mapping",
            "automated_evidence": [
                "SAST findings mapped to CWE IDs",
                "SCA vulnerabilities with CWE references",
                "Finding normalisation with CWE taxonomy",
            ],
            "manual_verification_required": [
                "CWE mapping accuracy review",
            ],
        },
    ],
}

_PCI_DSS = {
    "id": "pci-dss",
    "name": "PCI Data Security Standard",
    "mapping_version": "4.0",
    "controls": [
        {
            "control_id": "6.2",
            "title": "Bespoke and Custom Software Security",
            "automated_evidence": [
                "SAST/DAST scan results",
                "Vulnerability remediation tracking",
                "Suppression audit trail",
            ],
            "manual_verification_required": [
                "Code review process documentation",
                "Developer security training records",
            ],
        },
        {
            "control_id": "6.3",
            "title": "Security Vulnerabilities Identified and Addressed",
            "automated_evidence": [
                "SCA vulnerability reports",
                "Threat intelligence enrichment data",
                "Patch management evidence",
            ],
            "manual_verification_required": [
                "Vulnerability management process review",
            ],
        },
    ],
}

_ISO_27001 = {
    "id": "iso-27001",
    "name": "ISO/IEC 27001",
    "mapping_version": "2022",
    "controls": [
        {
            "control_id": "A.8.28",
            "title": "Secure Coding",
            "automated_evidence": [
                "SAST scan results",
                "Secure coding rule coverage",
                "Calibration feedback showing rule accuracy",
            ],
            "manual_verification_required": [
                "Secure coding standard documentation",
                "Developer training evidence",
            ],
        },
        {
            "control_id": "A.8.8",
            "title": "Management of Technical Vulnerabilities",
            "automated_evidence": [
                "SCA/dependency scanning results",
                "SBOM and VEX records",
                "MTTR metrics",
            ],
            "manual_verification_required": [
                "Vulnerability management policy review",
            ],
        },
    ],
}

_SOC_2 = {
    "id": "soc-2",
    "name": "SOC 2",
    "mapping_version": "2024",
    "controls": [
        {
            "control_id": "CC7.1",
            "title": "Monitoring Activities",
            "automated_evidence": [
                "Continuous scanning evidence",
                "Scanner health dashboards",
                "Benchmark regression detection",
            ],
            "manual_verification_required": [
                "Monitoring completeness review",
                "Incident response documentation",
            ],
        },
        {
            "control_id": "CC8.1",
            "title": "Change Management",
            "automated_evidence": [
                "Baseline comparison results",
                "Policy evaluation evidence",
                "Gate decision audit trail",
            ],
            "manual_verification_required": [
                "Change management process review",
            ],
        },
    ],
}

_CYBER_ESSENTIALS = {
    "id": "cyber-essentials",
    "name": "Cyber Essentials",
    "mapping_version": "3.1",
    "controls": [
        {
            "control_id": "Secure Configuration",
            "title": "Secure Configuration",
            "automated_evidence": [
                "IaC scanning results",
                "Container security scanning",
            ],
            "manual_verification_required": [
                "System configuration baseline review",
            ],
        },
        {
            "control_id": "Patch Management",
            "title": "Security Update Management",
            "automated_evidence": [
                "SCA vulnerability scanning",
                "Dependency freshness reports",
            ],
            "manual_verification_required": [
                "Patch deployment verification",
            ],
        },
    ],
}

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "owasp-top-10": _OWASP_TOP_10,
    "owasp-asvs": _OWASP_ASVS,
    "owasp-samm": _OWASP_SAMM,
    "nist-ssdf": _NIST_SSDF,
    "cwe": _CWE,
    "pci-dss": _PCI_DSS,
    "iso-27001": _ISO_27001,
    "soc-2": _SOC_2,
    "cyber-essentials": _CYBER_ESSENTIALS,
}


# --- Public API ---


def list_frameworks() -> list[dict[str, str]]:
    """List all supported compliance frameworks."""
    return [
        {
            "id": fw["id"],
            "name": fw["name"],
            "mapping_version": fw["mapping_version"],
        }
        for fw in FRAMEWORKS.values()
    ]


def framework_mapping(framework_id: str) -> dict[str, Any]:
    """Get the full mapping for a compliance framework."""
    fw = FRAMEWORKS.get(framework_id)
    if fw is None:
        raise ComplianceMappingError(
            f"unknown framework: {framework_id}; "
            f"expected one of {', '.join(sorted(FRAMEWORKS))}"
        )
    return {
        "schema_version": COMPLIANCE_SCHEMA_VERSION,
        "framework": fw["name"],
        "framework_id": fw["id"],
        "mapping_version": fw["mapping_version"],
        "disclaimer": (
            "This mapping provides evidence availability only. "
            "It does not claim or imply compliance with this framework."
        ),
        "controls": fw["controls"],
    }


def build_evidence_report(
    framework_id: str,
    *,
    scan_results: list[dict[str, Any]] | None = None,
    organisation: str = "default",
) -> dict[str, Any]:
    """Build an exportable evidence report for a framework.

    The report states what automated evidence is available and what
    still requires manual verification.  It never declares compliance.
    """
    mapping = framework_mapping(framework_id)

    controls_with_evidence = []
    for control in mapping["controls"]:
        evidence_items = []
        if scan_results:
            # Match scan results to the control's automated evidence categories
            for desc in control["automated_evidence"]:
                matching = [
                    r for r in scan_results
                    if r.get("category", "").lower() in desc.lower()
                    or r.get("scanner", "").lower() in desc.lower()
                ]
                evidence_items.append({
                    "evidence_type": desc,
                    "status": "evidence_available" if matching else "no_evidence",
                    "count": len(matching),
                })
        else:
            evidence_items = [
                {"evidence_type": desc, "status": "not_evaluated"}
                for desc in control["automated_evidence"]
            ]

        controls_with_evidence.append({
            "control_id": control["control_id"],
            "title": control["title"],
            "automated_evidence": evidence_items,
            "manual_verification_required": control["manual_verification_required"],
            "automated_coverage": (
                sum(1 for e in evidence_items if e["status"] == "evidence_available")
            ),
            "total_automated_checks": len(evidence_items),
        })

    return {
        "schema_version": COMPLIANCE_SCHEMA_VERSION,
        "type": "compliance_evidence_report",
        "framework": mapping["framework"],
        "framework_id": mapping["framework_id"],
        "mapping_version": mapping["mapping_version"],
        "organisation": organisation,
        "disclaimer": mapping["disclaimer"],
        "controls": controls_with_evidence,
        "summary": {
            "total_controls": len(controls_with_evidence),
            "controls_with_any_evidence": sum(
                1 for c in controls_with_evidence if c["automated_coverage"] > 0
            ),
            "manual_verification_items": sum(
                len(c["manual_verification_required"])
                for c in controls_with_evidence
            ),
        },
    }
