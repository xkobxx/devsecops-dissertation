"""Published contracts for deterministic remediation rules."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


_ROLLBACK = (
    "Verify the current file matches the receipt's after-digest, then restore "
    "the protected content-bound backup."
)

_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "TG-DEP-PY-001",
        "title": "Upgrade an exactly pinned Python dependency",
        "framework": "python-requirements",
        "preconditions": [
            "The requirement is an exact name==version pin.",
            "The request names the current and replacement versions.",
            "Hash-locked entries provide replacement SHA-256 hashes.",
        ],
        "transformation": (
            "Replace one exact requirement block while preserving the "
            "surrounding file."
        ),
        "tests": ["Install and run the project's dependency and regression tests."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "An upgraded dependency can contain breaking API or behaviour changes."
        ],
    },
    {
        "rule_id": "TG-DOCKER-USER-001",
        "title": "Configure a numeric non-root Docker user",
        "framework": "dockerfile",
        "preconditions": [
            "The Dockerfile has one final stage and no USER instruction.",
            "The requested UID is numeric and at least 10000.",
        ],
        "transformation": "Insert USER before the final CMD or ENTRYPOINT.",
        "tests": ["Build the image and run its container smoke tests."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "The image may need ownership or writable-directory changes before it runs."
        ],
    },
    {
        "rule_id": "TG-FLASK-HEADERS-001",
        "title": "Install conservative Flask response security headers",
        "framework": "python-flask",
        "preconditions": [
            "A simple module-level Flask application assignment is present.",
            "No Trust Gate header hook or existing after_request hook is present.",
        ],
        "transformation": (
            "Add one after_request hook using setdefault for CSP, frame, MIME, "
            "referrer, and permissions policy headers."
        ),
        "tests": ["Exercise every route and assert the response header policy."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Content Security Policy can block required third-party scripts or styles."
        ],
    },
    {
        "rule_id": "TG-PY-HASH-001",
        "title": "Replace a security-sensitive weak hash",
        "framework": "python-hashlib",
        "preconditions": [
            "The call is exactly hashlib.md5(...) or hashlib.sha1(...).",
            "The request explicitly declares a security purpose.",
        ],
        "transformation": "Replace only the selected constructor with hashlib.sha256.",
        "tests": ["Update and run digest, authentication, or integrity test vectors."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Digest length and interoperability change; password storage "
            "still needs a KDF."
        ],
    },
    {
        "rule_id": "TG-PY-SECRET-001",
        "title": "Replace a module-level literal secret with an environment lookup",
        "framework": "python-environment",
        "preconditions": [
            "The selected module-level symbol has one non-empty string literal value.",
            "The requested environment-variable name is explicit.",
        ],
        "transformation": (
            "Replace the literal with os.environ[...] and add import os when absent."
        ),
        "tests": ["Run startup tests with the variable present and absent."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Startup fails with KeyError when the deployment does not supply "
            "the variable.",
            "The exposed credential must still be revoked or rotated.",
        ],
    },
    {
        "rule_id": "TG-PY-SHELL-001",
        "title": "Remove shell execution from a static subprocess call",
        "framework": "python-subprocess",
        "preconditions": [
            "The subprocess API and command are statically supported.",
            "The command contains no shell operators, expansions, or redirections.",
        ],
        "transformation": (
            "Tokenize the literal command into an argv list and remove shell=True."
        ),
        "tests": ["Run the command-path unit test and verify argv semantics."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Shell quoting semantics differ from direct process argv semantics."
        ],
    },
    {
        "rule_id": "TG-PY-SQL-001",
        "title": "Parameterise a supported SQLite f-string query",
        "framework": "python-sqlite3",
        "preconditions": [
            "The call is cursor.execute(...) with one f-string argument.",
            "Formatted values have no conversion or format specification.",
        ],
        "transformation": (
            "Replace formatted values with SQLite placeholders and pass a value tuple."
        ),
        "tests": ["Run the query test with malicious and ordinary parameter values."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Only values can be bound; SQL identifiers still require an allowlist."
        ],
    },
    {
        "rule_id": "TG-PY-YAML-001",
        "title": "Use PyYAML safe loading",
        "framework": "python-pyyaml",
        "preconditions": [
            "The call is exactly yaml.load(value) with no Loader argument.",
        ],
        "transformation": "Replace yaml.load with yaml.safe_load.",
        "tests": ["Parse expected configuration and reject Python object tags."],
        "rollback": _ROLLBACK,
        "risk_notes": [
            "Applications relying on custom Python object construction will "
            "stop loading."
        ],
    },
)


def supported_rules() -> list[dict[str, Any]]:
    """Return defensive copies of every automatic remediation contract."""

    return deepcopy(sorted(_RULES, key=lambda rule: rule["rule_id"]))


__all__ = ["supported_rules"]
