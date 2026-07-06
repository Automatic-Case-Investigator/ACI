"""Unit test: the unqueried post-peak-cluster signal (nodes_flow).

A `get_event_volume` profile is a to-do list of windows. This signal flags the
post-peak activity clusters it surfaced that no raw search/search_keyword later drilled,
so the task review keeps the agent working instead of concluding from the profile alone.
Reproduces the live failure on case ~449101824, where the agent profiled clusters at
12:33/13:34/14:34/... but only ever searched the 12:04-12:34 peak window.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402

from agent.runtime.graph.nodes_flow import (  # noqa: E402
    _unqueried_post_peak_clusters,
    _unqueried_time_ranges,
)


def _volume(*times):
    return ToolMessage(
        name="get_event_volume", tool_call_id="v",
        content=json.dumps({"post_spike_active_bins": [{"time": t, "count": 9} for t in times]}),
    )


def _volume_span(onset, cessation):
    return ToolMessage(
        name="get_event_volume", tool_call_id="v",
        content=json.dumps({
            "onset": {"time": onset, "count": 100},
            "cessation": {"time": cessation, "count": 50},
        }),
    )


def _search(frm, to, *, embedded=False):
    if embedded:
        args = {"query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": frm, "lte": to}}}]}}}
        return AIMessage(content="", tool_calls=[{"name": "search", "id": "s", "args": args}])
    return AIMessage(content="", tool_calls=[
        {"name": "search_keyword", "id": "k", "args": {"time_range": {"from": frm, "to": to}}}])


class UnqueriedClusterTest(unittest.TestCase):
    def test_flags_clusters_outside_the_searched_window(self):
        msgs = [
            _volume("2022-01-18T12:33:00Z", "2022-01-18T13:34:00Z", "2022-01-18T14:34:00Z"),
            _search("2022-01-18T12:04:10Z", "2022-01-18T12:34:10Z", embedded=True),
        ]
        # 12:33 is inside the searched peak; 13:34 and 14:34 are not.
        self.assertEqual(
            _unqueried_post_peak_clusters(msgs),
            ["2022-01-18T13:34:00Z", "2022-01-18T14:34:00Z"],
        )

    def test_drilling_a_cluster_clears_it(self):
        msgs = [
            _volume("2022-01-18T13:34:00Z", "2022-01-18T14:34:00Z"),
            _search("2022-01-18T13:30:00Z", "2022-01-18T13:40:00Z"),
        ]
        self.assertEqual(_unqueried_post_peak_clusters(msgs), ["2022-01-18T14:34:00Z"])

    def test_all_clusters_drilled_returns_empty(self):
        msgs = [
            _volume("2022-01-18T13:34:00Z"),
            _search("2022-01-18T12:00:00Z", "2022-01-18T18:00:00Z"),
        ]
        self.assertEqual(_unqueried_post_peak_clusters(msgs), [])

    def test_no_volume_profile_returns_empty(self):
        self.assertEqual(
            _unqueried_post_peak_clusters([_search("2022-01-18T12:00:00Z", "2022-01-18T12:30:00Z")]),
            [],
        )

    def test_malformed_volume_content_is_ignored(self):
        bad = ToolMessage(name="get_event_volume", tool_call_id="v", content="not json")
        self.assertEqual(_unqueried_post_peak_clusters([bad]), [])


class UnqueriedTimeRangesTest(unittest.TestCase):
    def test_dwelling_in_scan_slice_flags_the_unsearched_tail(self):
        # Reproduces session bbfe8f97: profiled an active span to 13:14 but every raw
        # search clustered in the 12:09-12:29 scan window.
        msgs = [
            _volume_span("2022-01-18T12:15:00Z", "2022-01-18T13:14:00Z"),
            _search("2022-01-18T12:09:00Z", "2022-01-18T12:29:00Z"),
        ]
        gaps = _unqueried_time_ranges(msgs)
        self.assertEqual(gaps, ["2022-01-18T12:29:00Z–2022-01-18T13:14:00Z"])

    def test_full_active_span_covered_returns_empty(self):
        msgs = [
            _volume_span("2022-01-18T12:15:00Z", "2022-01-18T13:14:00Z"),
            _search("2022-01-18T12:00:00Z", "2022-01-18T14:00:00Z"),
        ]
        self.assertEqual(_unqueried_time_ranges(msgs), [])

    def test_tiny_gap_below_threshold_is_ignored(self):
        # A <10min sliver between two searches is not worth flagging.
        msgs = [
            _volume_span("2022-01-18T12:00:00Z", "2022-01-18T13:00:00Z"),
            _search("2022-01-18T12:00:00Z", "2022-01-18T12:28:00Z"),
            _search("2022-01-18T12:33:00Z", "2022-01-18T13:00:00Z"),
        ]
        self.assertEqual(_unqueried_time_ranges(msgs), [])

    def test_no_volume_profile_returns_empty(self):
        msgs = [_search("2022-01-18T12:00:00Z", "2022-01-18T12:30:00Z")]
        self.assertEqual(_unqueried_time_ranges(msgs), [])

    def test_post_cessation_tail_flagged_when_unsearched(self):
        # Reproduces 0199b17b: profiled a burst ending at 12:35, searched only up to 12:35,
        # never the low-volume tail (12:35-12:45) where a webshell hides one bin later.
        vol = ToolMessage(
            name="get_event_volume", tool_call_id="v",
            content=json.dumps({
                "interval": "5m",
                "onset": {"time": "2022-01-18T12:15:00Z", "count": 100},
                "cessation": {"time": "2022-01-18T12:35:00Z", "count": 50},
            }),
        )
        msgs = [vol, _search("2022-01-18T12:15:00Z", "2022-01-18T12:35:00Z")]
        self.assertEqual(_unqueried_time_ranges(msgs),
                         ["2022-01-18T12:35:00Z–2022-01-18T12:45:00Z"])

    def test_saturated_profile_gets_no_tail_extension(self):
        vol = ToolMessage(
            name="get_event_volume", tool_call_id="v",
            content=json.dumps({
                "interval": "5m", "saturated": True,
                "onset": {"time": "2022-01-18T12:15:00Z", "count": 100},
                "cessation": {"time": "2022-01-18T12:35:00Z", "count": 50},
            }),
        )
        msgs = [vol, _search("2022-01-18T12:15:00Z", "2022-01-18T12:35:00Z")]
        self.assertEqual(_unqueried_time_ranges(msgs), [])

    def test_falls_back_to_bin_envelope_when_no_regime(self):
        vol = ToolMessage(
            name="get_event_volume", tool_call_id="v",
            content=json.dumps({"onset": None, "cessation": None, "bins": [
                {"time": "2022-01-18T12:00:00Z", "count": 1},
                {"time": "2022-01-18T13:00:00Z", "count": 1}]}),
        )
        msgs = [vol, _search("2022-01-18T12:00:00Z", "2022-01-18T12:20:00Z")]
        self.assertEqual(_unqueried_time_ranges(msgs),
                         ["2022-01-18T12:20:00Z–2022-01-18T13:00:00Z"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
