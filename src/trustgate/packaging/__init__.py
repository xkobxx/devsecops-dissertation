"""Product packaging and edition definitions for Trust Gate.

Defines the feature sets available in each edition (Community,
Professional, Enterprise) and ensures licensing failures never
corrupt security results or block access to raw findings.
"""

from .editions import (
    PACKAGING_SCHEMA_VERSION,
    Edition,
    EditionFeature,
    PackagingError,
    check_feature_access,
    edition_features,
    list_editions,
)

__all__ = [
    "Edition",
    "EditionFeature",
    "PACKAGING_SCHEMA_VERSION",
    "PackagingError",
    "check_feature_access",
    "edition_features",
    "list_editions",
]
