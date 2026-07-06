"""Surfacing get_event_volume shape + search_keyword OR-fallback/too-broad in summaries.

These make the post-peak tail (where post-spike activity hides) and the OR-fallback
whole-host dump visible instead of collapsing both to a bare hit count.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.infra.logbus import summarize_result


class VolumeSummaryTest(unittest.TestCase):
    def _vol(self, post):
        return json.dumps({
            "interval": "15m", "total": 1252466,
            "bins": [{"time": "2022-01-18T12:15:00Z", "count": 750545}],
            "peak_bucket": {"time": "2022-01-18T12:15:00Z", "count": 750545},
            "post_spike_active_bins": post,
        })

    def test_post_peak_tail_is_surfaced(self):
        out = summarize_result("get_event_volume", self._vol([
            {"time": "2022-01-18T13:15:00Z", "count": 15},
            {"time": "2022-01-18T15:00:00Z", "count": 174},
        ]))
        self.assertIn("POST-PEAK", out)
        self.assertIn("13:15", out)
        self.assertIn("15:00", out)
        self.assertIn("peak 12:15", out)

    def test_no_tail_says_so(self):
        out = summarize_result("get_event_volume", self._vol([]))
        self.assertIn("no activity after peak", out)

    def test_tail_is_capped(self):
        post = [{"time": f"2022-01-18T{13 + i:02d}:00:00Z", "count": 5} for i in range(10)]
        out = summarize_result("get_event_volume", self._vol(post))
        self.assertIn("+4", out)  # 10 shown-capped at 6 → "+4"

    def test_saturated_window_summary_warns_and_dates(self):
        out = summarize_result("get_event_volume", json.dumps({
            "interval": "1h", "total": 1309364,
            "bins": [{"time": "2022-01-17T12:00:00Z", "count": 1584}],
            "peak_bucket": {"time": "2022-01-18T12:00:00Z", "count": 9000},
            "onset": {"time": "2022-01-17T12:00:00Z", "count": 1584},
            "cessation": {"time": "2022-01-19T12:00:00Z", "count": 576},
            "active_bins": [{"time": "x", "count": 1}] * 30,
            "saturated": True,
        }))
        self.assertIn("SPANS WHOLE WINDOW", out)
        self.assertIn("too broad", out)
        # Dated stamps so a 2-day span is not rendered as a misleading "12:00->12:00".
        self.assertIn("01-17 12:00", out)
        self.assertIn("01-19 12:00", out)
        self.assertNotIn("plateau", out)

    def test_multi_burst_summary_lists_bursts(self):
        out = summarize_result("get_event_volume", json.dumps({
            "interval": "1h", "total": 500000,
            "bins": [{"time": "2022-01-18T12:00:00Z", "count": 1}],
            "saturated": True,  # multi-burst takes priority over the saturated line
            "bursts": [
                {"start": "2022-01-18T12:15:00Z", "end": "2022-01-18T12:40:00Z", "total": 410000},
                {"start": "2022-01-19T09:20:00Z", "end": "2022-01-19T09:45:00Z", "total": 5000},
            ],
        }))
        self.assertIn("2 BURSTS", out)
        self.assertIn("01-18 12:15", out)
        self.assertIn("pick the one matching your objective", out)

    def test_output_is_cp1252_safe(self):
        summarize_result("get_event_volume", self._vol(
            [{"time": "2022-01-18T13:15:00Z", "count": 15}])).encode("cp1252")


class ProfileFieldSummaryTest(unittest.TestCase):
    def test_rare_values_surfaced_in_summary(self):
        out = summarize_result("profile_field", json.dumps({
            "field": "rule.id", "matched_docs": 1017364,
            "rare_values": [{"value": "80700", "count": 2}, {"value": "31108", "count": 4}],
            "max_doc_count": 10,
        }))
        self.assertIn("rule.id RARE:", out)
        self.assertIn("80700(2)", out)

    def test_empty_rare_says_none(self):
        out = summarize_result("profile_field", json.dumps({
            "field": "rule.id", "rare_values": [], "max_doc_count": 10}))
        self.assertIn("RARE: (none", out)

    def test_top_values_unchanged(self):
        out = summarize_result("profile_field", json.dumps({
            "field": "rule.id", "top_values": [{"value": "31101", "count": 940239}]}))
        self.assertIn("rule.id: 31101(940239)", out)


class KeywordFallbackSummaryTest(unittest.TestCase):
    def test_or_fallback_flagged(self):
        out = summarize_result("search_keyword", json.dumps({
            "total": 1019121, "events": [{"_id": "x"}], "broadened": True}))
        self.assertIn("OR-FALLBACK", out)
        self.assertIn("first=x", out)

    def test_too_broad_flagged(self):
        out = summarize_result("search_keyword", json.dumps({
            "total": 87855, "events": [{"_id": "y"}], "too_broad": True}))
        self.assertIn("TOO BROAD", out)

    def test_normal_keyword_result_unchanged(self):
        out = summarize_result("search_keyword", json.dumps({"total": 24, "events": [{"_id": "z"}]}))
        self.assertEqual(out, "24 hit(s) first=z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
