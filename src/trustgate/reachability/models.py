"""Shared conservative reachability-analysis contracts."""

from __future__ import annotations

from enum import StrEnum


class ReachabilityStatus(StrEnum):
    CONFIRMED_REACHABLE = "CONFIRMED_REACHABLE"
    LIKELY_REACHABLE = "LIKELY_REACHABLE"
    NO_PATH_FOUND = "NO_PATH_FOUND"
    NOT_ANALYSED = "NOT_ANALYSED"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    DYNAMIC_BEHAVIOUR_UNKNOWN = "DYNAMIC_BEHAVIOUR_UNKNOWN"


class AnalysisSupport(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    INCOMPLETE = "incomplete"


class DynamicOutcome(StrEnum):
    CONFIRMED = "confirmed"
    FAILED_REPRODUCTION = "failed-reproduction"
    BLOCKED_AUTHENTICATION = "blocked-authentication"
    INCONCLUSIVE = "inconclusive"
    NOT_ATTEMPTED = "not-attempted"
