"""Framework-specific guided-remediation content."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


_PROFILES: dict[str, dict[str, Any]] = {
    "TG-DEP-PY-001": {
        "applicable_cwe": ["CWE-1104"],
        "why_vulnerable": (
            "An outdated dependency can retain a publicly known weakness in "
            "code the application installs or executes."
        ),
        "exploit_scenario": (
            "An attacker reaches the vulnerable dependency behaviour through "
            "an application feature and triggers the published weakness."
        ),
        "secure_coding_pattern": (
            "Upgrade to an exact reviewed version, retain distribution hashes, "
            "and test the complete resolved dependency graph."
        ),
        "framework_specific_example": (
            "package-name==2.0.0 \\\n"
            "    --hash=sha256:<reviewed-distribution-digest>"
        ),
        "testing_guidance": [
            "Install from the updated lock file in a clean environment.",
            "Run unit, integration, and compatibility tests that exercise the package.",
        ],
        "regression_risks": [
            "The upgraded dependency can change APIs, defaults, or transitive versions."
        ],
    },
    "TG-DOCKER-USER-001": {
        "applicable_cwe": ["CWE-250"],
        "why_vulnerable": (
            "A container running as root grants compromised application code "
            "unnecessary privileges inside the container."
        ),
        "exploit_scenario": (
            "An attacker exploiting the service writes protected paths, changes "
            "process configuration, or amplifies a container-runtime weakness."
        ),
        "secure_coding_pattern": (
            "Run the final image with a dedicated numeric non-root UID and grant "
            "only required filesystem permissions."
        ),
        "framework_specific_example": "USER 10001",
        "testing_guidance": [
            "Build the final image and assert its configured user is non-root.",
            "Run startup and writable-directory smoke tests as that user.",
        ],
        "regression_risks": [
            "The application may lose required access to files, ports, or directories."
        ],
    },
    "TG-FLASK-HEADERS-001": {
        "applicable_cwe": ["CWE-693"],
        "why_vulnerable": (
            "Missing browser security headers leaves content handling, framing, "
            "and referrer behaviour more permissive than intended."
        ),
        "exploit_scenario": (
            "An attacker frames the application or injects content that a browser "
            "would have blocked under an explicit response policy."
        ),
        "secure_coding_pattern": (
            "Set a reviewed response policy centrally and preserve stricter "
            "route-specific headers."
        ),
        "framework_specific_example": (
            "@app.after_request\n"
            "def security_headers(response):\n"
            "    response.headers.setdefault(\"X-Content-Type-Options\", \"nosniff\")\n"
            "    return response"
        ),
        "testing_guidance": [
            "Request every response class and assert the intended headers.",
            "Exercise scripts, styles, framing, downloads, and reverse-proxy paths.",
        ],
        "regression_risks": [
            "A restrictive policy can block required third-party content or embedding."
        ],
    },
    "TG-PY-HASH-001": {
        "applicable_cwe": ["CWE-328"],
        "why_vulnerable": (
            "MD5 and SHA-1 do not provide collision resistance suitable for "
            "security-sensitive integrity decisions."
        ),
        "exploit_scenario": (
            "An attacker supplies distinct content with the same weak digest and "
            "bypasses an integrity or identity comparison."
        ),
        "secure_coding_pattern": (
            "Use SHA-256 or stronger for integrity; use a password KDF for passwords "
            "and HMAC when authenticity requires a secret key."
        ),
        "framework_specific_example": "digest = hashlib.sha256(content).hexdigest()",
        "testing_guidance": [
            "Update known-answer vectors and assert the new digest length.",
            "Test every producer and consumer of the digest together.",
        ],
        "regression_risks": [
            "Stored digests and external protocols may be incompatible with "
            "the new algorithm."
        ],
    },
    "TG-PY-SECRET-001": {
        "applicable_cwe": ["CWE-798"],
        "why_vulnerable": (
            "A literal credential in source can be copied through clones, logs, "
            "packages, caches, and repository history."
        ),
        "exploit_scenario": (
            "A person or process with read access extracts the credential and uses "
            "it against the protected service."
        ),
        "secure_coding_pattern": (
            "Read the credential from an injected environment or secret provider, "
            "restrict access, and rotate the exposed value."
        ),
        "framework_specific_example": "API_KEY = os.environ[\"SERVICE_API_KEY\"]",
        "testing_guidance": [
            "Test startup with the secret present and confirm safe failure "
            "when absent.",
            "Search the current tree and built artifacts for the revoked literal.",
        ],
        "regression_risks": [
            "Deployments without the new secret configuration will fail to start.",
            "Removing the current literal does not erase repository history.",
        ],
    },
    "TG-PY-SHELL-001": {
        "applicable_cwe": ["CWE-78"],
        "why_vulnerable": (
            "A shell interprets metacharacters and expansions in command text, so "
            "untrusted values can become additional commands."
        ),
        "exploit_scenario": (
            "An attacker injects a separator or expansion through command input and "
            "executes a second program with the application's privileges."
        ),
        "secure_coding_pattern": (
            "Invoke a fixed executable with an argument list and validate values "
            "against the command's expected input domain."
        ),
        "framework_specific_example": (
            "subprocess.run([\"git\", \"status\", \"--short\"], check=True)"
        ),
        "testing_guidance": [
            "Assert the exact argv received by the child process.",
            "Test spaces, quotes, separators, and option-like attacker input.",
        ],
        "regression_risks": [
            "Pipelines, redirection, globbing, and environment expansion need "
            "explicit redesign."
        ],
    },
    "TG-PY-SQL-001": {
        "applicable_cwe": ["CWE-89"],
        "why_vulnerable": (
            "Untrusted data interpolated into SQL is parsed as query syntax instead "
            "of being bound as a value."
        ),
        "exploit_scenario": (
            "An attacker supplies SQL operators through the request source and changes "
            "the query executed by the database sink."
        ),
        "secure_coding_pattern": (
            "Keep SQL structure constant and bind every value through driver "
            "placeholders. Allowlist any identifier that cannot be parameterised."
        ),
        "framework_specific_example": (
            "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
        ),
        "testing_guidance": [
            "Test ordinary, missing, boundary, and malicious parameter values.",
            "Assert injected quotes and SQL operators remain data, not syntax.",
        ],
        "regression_risks": [
            "Changing placeholder style can break drivers with a different paramstyle.",
            "Dynamic table or column identifiers require a separate allowlist.",
        ],
    },
    "TG-PY-YAML-001": {
        "applicable_cwe": ["CWE-502"],
        "why_vulnerable": (
            "Unsafe YAML construction can instantiate attacker-selected Python "
            "objects while parsing untrusted configuration."
        ),
        "exploit_scenario": (
            "An attacker supplies a Python object tag whose constructor executes "
            "code or performs an unsafe side effect during loading."
        ),
        "secure_coding_pattern": (
            "Use safe_load for data-only YAML and validate the resulting primitive "
            "structure against an application schema."
        ),
        "framework_specific_example": "config = yaml.safe_load(payload)",
        "testing_guidance": [
            "Parse every supported configuration shape with safe_load.",
            "Assert Python object tags and unexpected types are rejected.",
        ],
        "regression_risks": [
            "Configuration relying on custom Python object tags will no longer load."
        ],
    },
}


def guidance_profiles() -> dict[str, dict[str, Any]]:
    """Return defensive copies of guided-remediation content."""

    return deepcopy(_PROFILES)


__all__ = ["guidance_profiles"]
