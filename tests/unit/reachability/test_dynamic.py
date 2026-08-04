from __future__ import annotations

import unittest

from trustgate.reachability.dynamic import correlate_dynamic_evidence

from tests.unit.schemas.test_schema_contracts import valid_finding


def static_finding() -> dict[str, object]:
    finding = valid_finding()
    finding.update(
        {
            "finding_id": "static-sqli",
            "file": "app.py",
            "source": "request.args['q']",
            "sink": "cursor.execute",
            "status": "open",
            "reachability": "reachable",
            "data_flow": [
                {
                    "order": 0,
                    "kind": "source",
                    "file": "app.py",
                    "line": 10,
                    "symbol": "request.args['q']",
                    "description": "Untrusted query parameter.",
                },
                {
                    "order": 1,
                    "kind": "sink",
                    "file": "app.py",
                    "line": 12,
                    "symbol": "cursor.execute",
                    "description": "SQL execution.",
                },
            ],
            "source_to_sink_analysis": {
                "support": "supported",
                "status": "path-found",
                "analysis_incomplete": False,
                "identified_sources": [
                    {
                        "file": "app.py",
                        "line": 10,
                        "symbol": "request.args['q']",
                        "description": "Untrusted query parameter.",
                    }
                ],
                "identified_sanitizers": [],
                "identified_sinks": [
                    {
                        "file": "app.py",
                        "line": 12,
                        "symbol": "cursor.execute",
                        "description": "SQL execution.",
                    }
                ],
                "intra_file": True,
                "cross_file": False,
                "framework_routes": [
                    {
                        "endpoint": "/search",
                        "methods": ["GET"],
                        "file": "app.py",
                        "line": 8,
                        "handler": "search",
                    }
                ],
                "authentication_required": False,
                "authorization_checks": [],
                "path_confidence": 0.95,
                "evidence": [],
                "limitations": ["Dynamic dispatch remains unknown."],
            },
        }
    )
    return finding


def observation(outcome: str, **overrides) -> dict[str, object]:
    value = {
        "observation_id": f"dast-{outcome}",
        "endpoint": "/search",
        "parameter": "q",
        "sink": "cursor.execute",
        "outcome": outcome,
        "authentication_state": "not-required",
        "evidence": ["HTTP 500 with database error signature"],
    }
    value.update(overrides)
    return value


class DynamicCorrelationTests(unittest.TestCase):
    def test_confirmed_dast_matches_endpoint_parameter_sink_and_increases_priority(self) -> None:
        correlated = correlate_dynamic_evidence(
            [static_finding()], [observation("confirmed")]
        )[0]

        dynamic = correlated["dynamic_correlation"]
        self.assertEqual(dynamic["status"], "confirmed")
        self.assertTrue(dynamic["endpoint_matched"])
        self.assertTrue(dynamic["parameter_matched"])
        self.assertTrue(dynamic["sink_matched"])
        self.assertEqual(dynamic["priority_adjustment"], "increased")
        self.assertTrue(dynamic["static_evidence"])
        self.assertTrue(dynamic["runtime_evidence"])
        self.assertEqual(dynamic["matched_observation_ids"], ["dast-confirmed"])

    def test_failed_reproduction_is_recorded_without_marking_finding_false(self) -> None:
        correlated = correlate_dynamic_evidence(
            [static_finding()], [observation("failed-reproduction")]
        )[0]

        dynamic = correlated["dynamic_correlation"]
        self.assertEqual(dynamic["status"], "failed-reproduction")
        self.assertEqual(dynamic["priority_adjustment"], "unchanged")
        self.assertEqual(len(dynamic["failed_reproduction_attempts"]), 1)
        self.assertEqual(correlated["status"], "open")
        self.assertEqual(correlated["reachability"], "reachable")

    def test_blocked_authentication_is_distinct_from_failed_exploitation(self) -> None:
        correlated = correlate_dynamic_evidence(
            [static_finding()],
            [
                observation(
                    "blocked-authentication",
                    authentication_state="blocked",
                )
            ],
        )[0]

        dynamic = correlated["dynamic_correlation"]
        self.assertEqual(dynamic["status"], "blocked-authentication")
        self.assertEqual(dynamic["authentication_state"], "blocked")
        self.assertEqual(dynamic["failed_reproduction_attempts"], [])

    def test_inconclusive_dast_does_not_suppress_static_finding(self) -> None:
        correlated = correlate_dynamic_evidence(
            [static_finding()], [observation("inconclusive")]
        )[0]

        dynamic = correlated["dynamic_correlation"]
        self.assertEqual(dynamic["status"], "inconclusive")
        self.assertEqual(dynamic["priority_adjustment"], "unchanged")
        self.assertEqual(correlated["status"], "open")
        self.assertEqual(correlated["reachability"], "reachable")

    def test_unmatched_runtime_observation_is_not_attached(self) -> None:
        correlated = correlate_dynamic_evidence(
            [static_finding()],
            [observation("confirmed", endpoint="/other", parameter="x", sink="eval")],
        )[0]

        self.assertNotIn("dynamic_correlation", correlated)


if __name__ == "__main__":
    unittest.main()
