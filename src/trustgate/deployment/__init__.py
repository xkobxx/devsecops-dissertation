"""Deployment mode configuration for Trust Gate.

Three modes control data-handling behaviour:

- local: all data stays in CI, no network calls, no telemetry
- hybrid: source stays local, approved metadata may be uploaded
- full: all features enabled (default for SaaS, not recommended for
  sensitive environments without review)
"""

from .modes import (
    DEPLOYMENT_MODES,
    DeploymentConfig,
    DeploymentMode,
    DeploymentModeError,
    NetworkMode,
    validate_deployment_config,
)

__all__ = [
    "DEPLOYMENT_MODES",
    "DeploymentConfig",
    "DeploymentMode",
    "DeploymentModeError",
    "NetworkMode",
    "validate_deployment_config",
]
