"""Build reusable, bounded OWASP ZAP Automation Framework plans."""

from __future__ import annotations

from dataclasses import replace
import ipaddress
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

from trustgate.security import InputValidationError, validate_dast_url
from trustgate.security.inputs import validate_workspace_path

from .models import (
    DastConfig,
    DastConfigurationError,
    DastMode,
    DastPlan,
    ScanMode,
    TargetEnvironment,
)


_AUTH_TYPES = frozenset({"none", "bearer", "basic", "header"})
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PRODUCTION_LABELS = frozenset({"prod", "production"})


def build_dast_plan(
    config: DastConfig,
    *,
    workspace: Path,
    report_path: Path = Path("reports/zap_report.json"),
) -> DastPlan:
    """Validate safety invariants and return a secret-free ZAP plan."""

    config = _normalise_enums(config)
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise DastConfigurationError("DAST workspace must be an existing directory.")
    _validate_limits(config)
    try:
        target_url = validate_dast_url(
            config.target_url,
            allow_private=config.allow_private_target,
        )
    except InputValidationError as error:
        raise DastConfigurationError(str(error)) from error
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").rstrip(".").lower()
    allowlist = _scope_allowlist(config.scope_allowlist)
    if not _host_allowed(host, allowlist):
        raise DastConfigurationError(
            f"DAST target host {host!r} is not allowlisted."
        )
    if _is_public_host(host) and not config.public_target_acknowledged:
        raise DastConfigurationError(
            "Scanning a public target requires explicit public-target acknowledgement."
        )
    looks_production = bool(set(host.split(".")) & _PRODUCTION_LABELS)
    if looks_production and config.environment is not TargetEnvironment.PRODUCTION:
        raise DastConfigurationError(
            "A production-like hostname must be declared as production."
        )
    if (
        config.environment is TargetEnvironment.PRODUCTION
        and not config.production_scan_acknowledged
    ):
        raise DastConfigurationError(
            "Production scanning is disabled without explicit production acknowledgement."
        )
    if config.scan_mode is ScanMode.ACTIVE and not config.active_scan_acknowledged:
        raise DastConfigurationError(
            "Active scanning requires explicit active-scan acknowledgement."
        )
    if config.auth_type not in _AUTH_TYPES:
        raise DastConfigurationError(
            "DAST auth type must be one of: none, bearer, basic, header."
        )
    if not _HEADER_NAME.fullmatch(config.auth_header_name):
        raise DastConfigurationError("DAST authentication header name is invalid.")
    if not _ENVIRONMENT_NAME.fullmatch(config.auth_secret_environment):
        raise DastConfigurationError(
            "DAST authentication secret environment name is invalid."
        )

    specification = _api_specification(config, root)
    normalized = replace(
        config,
        target_url=target_url,
        scope_allowlist=allowlist,
        openapi_path=specification,
    )
    sender_gate = _sender_gate_script(normalized, host)
    automation = _automation_plan(
        normalized,
        sender_gate=sender_gate,
        report_path=report_path,
    )
    return DastPlan(
        config=normalized,
        target_host=host,
        automation=automation,
        sender_gate_script=sender_gate,
    )


def _normalise_enums(config: DastConfig) -> DastConfig:
    try:
        return replace(
            config,
            mode=DastMode(config.mode),
            scan_mode=ScanMode(config.scan_mode),
            environment=TargetEnvironment(config.environment),
            auth_type=config.auth_type.strip().lower(),
        )
    except (TypeError, ValueError) as error:
        raise DastConfigurationError(f"Invalid DAST mode: {error}") from error


def _validate_limits(config: DastConfig) -> None:
    limits = (
        ("rate limit", config.rate_limit_per_second, 100),
        ("request limit", config.request_limit, 100_000),
        ("maximum scan duration", config.max_duration_seconds, 3_600),
    )
    for label, value, maximum in limits:
        if isinstance(value, bool) or not isinstance(value, int):
            raise DastConfigurationError(f"DAST {label} must be an integer.")
        if value <= 0 or value > maximum:
            raise DastConfigurationError(
                f"DAST {label} must be between 1 and {maximum}."
            )


def _scope_allowlist(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = []
    for original in values:
        value = original.strip().rstrip(".").lower()
        wildcard = value.startswith("*.")
        suffix = value[2:] if wildcard else value
        if (
            not value
            or value == "*"
            or "://" in value
            or "/" in value
            or ":" in value
            or "*" in suffix
            or ("." not in suffix and suffix != "localhost")
        ):
            raise DastConfigurationError(
                "DAST scope allowlist requires explicit hosts or *.domain entries."
            )
        normalized.append(f"*.{suffix}" if wildcard else suffix)
    result = tuple(dict.fromkeys(normalized))
    if not result:
        raise DastConfigurationError("DAST scope allowlist cannot be empty.")
    return result


def _host_allowed(host: str, allowlist: tuple[str, ...]) -> bool:
    return any(
        host == entry
        or (entry.startswith("*.") and host.endswith(entry[1:]) and host != entry[2:])
        for entry in allowlist
    )


def _is_public_host(host: str) -> bool:
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def _api_specification(config: DastConfig, workspace: Path) -> str | None:
    if config.mode is not DastMode.API:
        return None
    if not config.openapi_path:
        raise DastConfigurationError("API mode requires an OpenAPI specification.")
    try:
        return validate_workspace_path(
            workspace,
            config.openapi_path,
            label="DAST OpenAPI specification",
            require_file=True,
        )
    except InputValidationError as error:
        raise DastConfigurationError(str(error)) from error


def _automation_plan(
    config: DastConfig,
    *,
    sender_gate: str,
    report_path: Path,
) -> dict[str, object]:
    context: dict[str, object] = {
        "name": "trustgate",
        "urls": [config.target_url],
        "includePaths": [_scope_pattern(config.target_url)],
    }
    if config.auth_type != "none":
        prefix = {
            "bearer": "Bearer ",
            "basic": "Basic ",
            "header": "",
        }[config.auth_type]
        context["sessionManagement"] = {
            "method": "headers",
            "parameters": {
                config.auth_header_name: (
                    f"{prefix}{{%env:{config.auth_secret_environment}%}}"
                )
            },
        }

    duration_minutes = max(1, math.ceil(config.max_duration_seconds / 60))
    jobs: list[dict[str, object]] = [
        {
            "type": "script",
            "parameters": {
                "action": "add",
                "type": "httpsender",
                "engine": "ECMAScript : Graal.js",
                "name": "trustgate-request-gate.js",
                "inline": sender_gate,
            },
        }
    ]
    if config.mode is DastMode.BASELINE:
        jobs.append(
            {
                "type": "spider",
                "parameters": {
                    "context": "trustgate",
                    "url": config.target_url,
                    "maxDuration": duration_minutes,
                    "maxChildren": min(config.request_limit, 10_000),
                    "threadCount": 1,
                },
            }
        )
    else:
        jobs.append(
            {
                "type": "openapi",
                "parameters": {
                    "context": "trustgate",
                    "apiFile": config.openapi_path,
                    "targetUrl": config.target_url,
                },
            }
        )
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": duration_minutes}})
    if config.scan_mode is ScanMode.ACTIVE:
        jobs.append(
            {
                "type": "activeScan",
                "parameters": {
                    "context": "trustgate",
                    "maxScanDurationInMins": duration_minutes,
                    "maxRuleDurationInMins": duration_minutes,
                    "threadPerHost": 1,
                    "delayInMs": max(1, math.ceil(1000 / config.rate_limit_per_second)),
                },
            }
        )
    jobs.extend(
        [
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": str(report_path.parent),
                    "reportFile": report_path.name,
                    "displayReport": False,
                },
            },
            {
                "type": "exitStatus",
                "parameters": {"errorLevel": "High", "warnLevel": "Medium"},
            },
        ]
    )
    return {
        "env": {
            "contexts": [context],
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "continueOnFailure": False,
                "progressToStdout": True,
            },
        },
        "jobs": jobs,
    }


def _scope_pattern(target_url: str) -> str:
    parsed = urlsplit(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    return re.escape(origin + path) + r"(?:/.*)?"


def _sender_gate_script(config: DastConfig, target_host: str) -> str:
    allowlist = json.dumps(list(config.scope_allowlist))
    auth = json.dumps(
        {
            "type": config.auth_type,
            "header": config.auth_header_name,
            "environment": config.auth_secret_environment,
        },
        separators=(",", ":"),
    )
    interval = math.ceil(1000 / config.rate_limit_per_second)
    return f'''var MAX_REQUESTS = {config.request_limit};
var MIN_INTERVAL_MS = {interval};
var ALLOWED_HOSTS = {allowlist};
var AUTH = {auth};
var requestCount = 0;
var lastRequestAt = 0;
var System = Java.type("java.lang.System");
var Thread = Java.type("java.lang.Thread");

function hostAllowed(host) {{
  host = String(host).toLowerCase();
  for (var index = 0; index < ALLOWED_HOSTS.length; index++) {{
    var entry = ALLOWED_HOSTS[index];
    if (entry.indexOf("*.") === 0) {{
      var suffix = entry.substring(1);
      if (host.endsWith(suffix) && host !== entry.substring(2)) return true;
    }} else if (host === entry) return true;
  }}
  return false;
}}

function sendingRequest(msg, initiator, helper) {{
  var host = msg.getRequestHeader().getURI().getHost();
  if (!hostAllowed(host)) throw "Trust Gate blocked out-of-scope host: " + host;
  requestCount += 1;
  if (requestCount > MAX_REQUESTS) throw "Trust Gate request limit exceeded";
  var now = System.currentTimeMillis();
  var wait = MIN_INTERVAL_MS - (now - lastRequestAt);
  if (wait > 0) Thread.sleep(wait);
  lastRequestAt = System.currentTimeMillis();
  if (AUTH.type !== "none") {{
    var secret = System.getenv(AUTH.environment);
    if (!secret) throw "Trust Gate authentication environment is missing";
    var prefix = AUTH.type === "bearer" ? "Bearer " :
                 (AUTH.type === "basic" ? "Basic " : "");
    msg.getRequestHeader().setHeader(AUTH.header, prefix + secret);
  }}
}}

function responseReceived(msg, initiator, helper) {{}}
'''


__all__ = ["build_dast_plan"]
