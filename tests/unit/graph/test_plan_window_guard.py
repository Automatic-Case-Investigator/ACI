"""The seeder enforces the plan's own time-window contract.

The triage contract already says a window narrower than the configured vicinity must
carry a stated reason. Nothing checked it, and an unexplained narrow box becomes the
investigation's evidence horizon — the agent passes the item's `end` straight into
`get_event_volume`, so the profile cannot see past it.

Session 6b96293a: plan item 5 stated `2022-01-18T12:10 – 12:40` with no justification.
Every query in that task fell inside the box; the payload landed at 13:14 and was never
looked at.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ.setdefault("SECRET_KEY", "test")
project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
sys.path.insert(0, project_root)
import django  # noqa: E402

django.setup()

import agent.runtime.graph  # noqa: E402,F401  (import first — seeder_runner cycles through it)
from agent.runtime.engine.seeder_runner import _widen_unjustified_window  # noqa: E402

_NARROW = (
    "**Separate the web scan burst from the SSH access chain**\n"
    "- Pivots: `data.srcip=172.17.130.196`, `agent.name=wazuh-client`\n"
    "- Time window: `2022-01-18T12:10:00Z` to `2022-01-18T12:40:00Z`\n"
    "- Priority: 60"
)


class WidenUnjustifiedWindowTest(unittest.TestCase):
    def test_the_live_failure_is_widened(self):
        out = _widen_unjustified_window(_NARROW, 24)
        self.assertIn("Window correction", out)
        # The corrected range must reach past the original box.
        stamps = re.findall(r"2022-01-\d\dT\d\d:\d\d:\d\dZ", out)
        self.assertTrue(
            any(s > "2022-01-18T13:00:00Z" for s in stamps),
            "widened window must cover the post-burst tail",
        )

    def test_a_justified_narrow_window_is_left_alone(self):
        justified = (
            _NARROW
            + "\n- This narrower range is used because the burst is fully bounded by it."
        )
        self.assertEqual(_widen_unjustified_window(justified, 24), justified)

    def test_a_window_already_at_vicinity_is_left_alone(self):
        wide = _NARROW.replace("2022-01-18T12:40:00Z", "2022-01-19T12:40:00Z")
        self.assertEqual(_widen_unjustified_window(wide, 24), wide)

    def test_an_item_without_a_window_is_left_alone(self):
        item = "**Retrieve syscheck diff**\n- Pivots: `agent.name=wazuh-client`"
        self.assertEqual(_widen_unjustified_window(item, 24), item)

    def test_pivots_and_criterion_are_not_rewritten(self):
        out = _widen_unjustified_window(_NARROW, 24)
        self.assertIn("data.srcip=172.17.130.196", out)
        self.assertIn("Priority: 60", out)

    def test_disabled_when_no_vicinity_configured(self):
        self.assertEqual(_widen_unjustified_window(_NARROW, 0), _NARROW)


class PlanContractTest(unittest.TestCase):
    """The prompt rules the guard backs up — pinned so they cannot silently vanish."""

    def setUp(self):
        path = os.path.join(
            project_root, "agent", "prompts", "triage", "instructions.md"
        )
        with open(path, encoding="utf-8") as fh:
            self.text = fh.read()

    def test_the_anchor_is_the_alerts_own_timestamp(self):
        self.assertIn("The anchor is the alert's own timestamp", self.text)

    def test_the_forward_item_must_move_forward_in_time(self):
        self.assertIn("must move forward in TIME", self.text)

    def test_every_burst_needs_coverage(self):
        self.assertIn("Cover every burst you found", self.text)

    def test_pivots_must_be_the_narrowest_artifact(self):
        self.assertIn("Pivot on the narrowest artifact you actually found", self.text)

    def test_priority_ranks_by_distance_from_the_alerts_chain(self):
        self.assertIn("Rank by distance from the alert's own chain first", self.text)


if __name__ == "__main__":
    unittest.main()
