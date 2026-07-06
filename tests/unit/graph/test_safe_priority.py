"""Offline test: _safe_priority coercion of model-supplied lead priorities.

The investigation prompt requires a numeric priority (30-100), but small models
sometimes emit a qualitative label or a decorated string. _safe_priority must map
those onto the priority bands rather than silently collapsing them to the
mid-point (which would destroy the lead's ranking signal).

Run from project root with:
    python -m pytest tests/unit/graph/test_safe_priority.py
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.graph.leads import _safe_priority


class SafePriorityTests(unittest.TestCase):
    def test_plain_int_passthrough_and_clamp(self):
        self.assertEqual(_safe_priority(85), 85)
        self.assertEqual(_safe_priority(0), 0)
        self.assertEqual(_safe_priority(250), 100)
        self.assertEqual(_safe_priority(-5), 0)

    def test_numeric_string(self):
        self.assertEqual(_safe_priority("85"), 85)
        self.assertEqual(_safe_priority("  90 "), 90)

    def test_qualitative_labels_map_to_bands(self):
        self.assertEqual(_safe_priority("Critical"), 95)
        self.assertEqual(_safe_priority("High"), 85)
        self.assertEqual(_safe_priority("medium"), 60)
        self.assertEqual(_safe_priority("Low"), 40)

    def test_decorated_string_extracts_number(self):
        self.assertEqual(_safe_priority("P85"), 85)
        self.assertEqual(_safe_priority("priority: 70"), 70)

    def test_label_wins_over_no_number(self):
        self.assertEqual(_safe_priority("high priority"), 85)

    def test_unusable_falls_back_to_midpoint(self):
        self.assertEqual(_safe_priority(None), 50)
        self.assertEqual(_safe_priority(""), 50)
        self.assertEqual(_safe_priority("urgent"), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
