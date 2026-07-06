from __future__ import annotations

import os
import sys
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.graph.parsing import _missing_triage_sections  # noqa: E402


class TriageReportShapeTest(unittest.TestCase):
    def test_entity_blob_is_not_a_valid_triage_report(self):
        report = (
            '{"entities": [{"subject_type": "user", "subject_id": "kali"}]}\n\n'
            "```json\n"
            '{\n  "verdict": "needs_investigation"\n}\n'
            "```"
        )
        self.assertEqual(
            _missing_triage_sections(report),
            ["Triage Summary", "Key Evidence", "Investigation Plan"],
        )

    def test_structured_triage_report_passes(self):
        report = (
            "## Triage Summary\n"
            "The case indicates web reconnaissance from 172.17.130.196 against wazuh-client.\n\n"
            "## Key Evidence\n"
            "- WPScan user-agent observed against /wp-content/plugins/* at 2022-01-18T12:17:58Z.\n\n"
            "## Investigation Plan\n"
            "1. Review successful HTTP/authentication events from 2022-01-18T12:10:00Z to 2022-01-18T12:40:00Z.\n"
        )
        self.assertEqual(_missing_triage_sections(report), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
