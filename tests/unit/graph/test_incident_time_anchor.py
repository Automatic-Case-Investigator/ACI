from __future__ import annotations

import json
import os
import sys
import unittest

from langchain_core.messages import ToolMessage

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-thehive"))

from aci_thehive.client import _normalize_case_timestamps
from agent.runtime.graph.nodes_loop import _time_window_guard


class TheHiveCaseDateTest(unittest.TestCase):
    def test_case_date_becomes_incident_time_not_created_at(self):
        case = _normalize_case_timestamps({
            "date": 1642508350000,
            "createdAt": 1782713471057,
            "_createdAt": 1782713471057,
        })

        self.assertEqual(case["incident_time_source"], "case.date")
        self.assertTrue(case["incident_time_iso"].startswith("2022-01-18T12:19:10"))
        self.assertTrue(case["createdAt_iso"].startswith("2026-06-"))
        self.assertNotEqual(case["incident_time_iso"], case["createdAt_iso"])


class SiemTimeGuardTest(unittest.TestCase):
    def test_blocks_query_outside_claimed_task_window(self):
        state = {
            "current_task": {
                "description": (
                    "**Trace tail**\n"
                    "- Time window: `2022-01-18T12:18:30Z` to `2022-01-18T14:18:30Z`"
                )
            },
            "default_vicinity_window_hours": 24,
        }
        err = _time_window_guard(
            "search_keyword",
            {
                "query": "172.17.130.196 wazuh-client",
                "time_range": {
                    "from": "2026-07-03T00:00:00Z",
                    "to": "2026-07-03T06:00:00Z",
                },
            },
            state,
            [],
        )

        self.assertIsNotNone(err)
        self.assertIn("Invalid SIEM time range", err)
        self.assertIn("2022-01-18T12:18:30Z", err)
        self.assertIn("createdAt/_createdAt", err)

    def test_blocks_query_far_from_case_date_anchor(self):
        messages = [
            ToolMessage(
                name="get_case",
                tool_call_id="case-1",
                content=json.dumps({
                    "incident_time_iso": "2022-01-18T12:19:10+00:00",
                    "incident_time_source": "case.date",
                    "createdAt_iso": "2026-06-29T01:11:11+00:00",
                }),
            )
        ]
        state = {"current_task": {"description": "Investigate case"}, "default_vicinity_window_hours": 24}

        err = _time_window_guard(
            "get_event_volume",
            {
                "start_time": "2026-07-03T00:00:00Z",
                "end_time": "2026-07-03T06:00:00Z",
            },
            state,
            messages,
        )

        self.assertIsNotNone(err)
        self.assertIn("2022-01-18T12:19:10Z", err)
        self.assertIn("case.incident_time_iso", err)

    def test_allows_query_inside_claimed_task_window(self):
        state = {
            "current_task": {
                "description": (
                    "**Trace tail**\n"
                    "- Time window: `2022-01-18T12:18:30Z` to `2022-01-18T14:18:30Z`"
                )
            },
            "default_vicinity_window_hours": 24,
        }
        err = _time_window_guard(
            "search_keyword",
            {
                "query": "172.17.130.196 wazuh-client",
                "time_range": {
                    "from": "2022-01-18T12:30:00Z",
                    "to": "2022-01-18T13:00:00Z",
                },
            },
            state,
            [],
        )

        self.assertIsNone(err)

    def test_allows_widening_beyond_task_window_up_to_vicinity(self):
        # A 2-minute task window must NOT trap the agent: it may widen for surrounding
        # context up to the configured vicinity window (regression for the ~60-call
        # `invalid time range` death loop, session 1a06770f).
        state = {
            "current_task": {
                "description": (
                    "**Retrieve raw event**\n"
                    "- Time window: `2022-01-18T12:18:10Z` to `2022-01-18T12:20:10Z`"
                )
            },
            "default_vicinity_window_hours": 24,
        }
        # Widened ~50 min on each side — well outside the 2-min task box, but inside +/-24h.
        err = _time_window_guard(
            "get_event_volume",
            {"start_time": "2022-01-18T11:30:00Z", "end_time": "2022-01-18T12:45:00Z"},
            state,
            [],
        )
        self.assertIsNone(err)

    def test_blocks_widening_past_the_vicinity_window(self):
        # But a query beyond +/-vicinity (here a different day, >24h out) is still blocked.
        state = {
            "current_task": {
                "description": (
                    "**Retrieve raw event**\n"
                    "- Time window: `2022-01-18T12:18:10Z` to `2022-01-18T12:20:10Z`"
                )
            },
            "default_vicinity_window_hours": 24,
        }
        err = _time_window_guard(
            "get_event_volume",
            {"start_time": "2022-01-16T00:00:00Z", "end_time": "2022-01-16T06:00:00Z"},
            state,
            [],
        )
        self.assertIsNotNone(err)
        self.assertIn("Invalid SIEM time range", err)
        self.assertIn("vicinity window", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
