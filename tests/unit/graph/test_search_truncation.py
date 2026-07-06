"""Unit test: search-result truncation is surfaced (vicinity-window-too-broad fix).

When OpenSearch caps total counting (track_total_hits off), total.relation="gte" and
the returned events are an arbitrary slice. summarize_result must flag this as
TRUNCATED so the agent narrows instead of trusting a sample that hides the key events.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.infra.logbus import summarize_result


class SearchTruncationTest(unittest.TestCase):
    def test_truncated_flag_is_surfaced(self):
        out = summarize_result("search", json.dumps({
            "total": 10000, "total_relation": "gte", "truncated": True,
            "events": [{"_id": "abc"}],
        }))
        self.assertIn("TRUNCATED", out)
        self.assertIn("10000", out)
        self.assertIn("first=abc", out)

    def test_gte_relation_alone_triggers_truncation(self):
        out = summarize_result("search", json.dumps({
            "total": 10000, "total_relation": "gte", "events": [],
        }))
        self.assertIn("TRUNCATED", out)

    def test_exact_count_not_marked_truncated(self):
        out = summarize_result("search", json.dumps({
            "total": 40, "total_relation": "eq", "truncated": False,
            "events": [{"_id": "y"}],
        }))
        self.assertNotIn("TRUNCATED", out)
        self.assertIn("40 hit(s)", out)

    def test_legacy_result_without_relation_unchanged(self):
        out = summarize_result("search", json.dumps({"total": 5, "events": [{"_id": "z"}]}))
        self.assertEqual(out, "5 hit(s) first=z")

    def test_output_is_ascii_safe(self):
        # summarize_result feeds logging/console on Windows (cp1252) — must not raise.
        out = summarize_result("search", json.dumps({
            "total": 10000, "total_relation": "gte", "events": [{"_id": "x"}]}))
        out.encode("cp1252")  # raises UnicodeEncodeError if a non-cp1252 char slipped in


if __name__ == "__main__":
    unittest.main(verbosity=2)
