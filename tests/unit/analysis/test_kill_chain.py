from __future__ import annotations

import json
import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from agent.runtime.analysis.kill_chain import (
    MAX_GAP_LEADS, gap_lead_specs, pivots_for_tactic, summarize_kill_chain,
)
from aci_wazuh.client import WazuhClient


class SummarizeKillChainTest(unittest.TestCase):
    def test_orders_tactics_by_kill_chain_and_flags_gaps(self):
        result = {
            "techniques": [
                {"id": "T1053", "technique": "Scheduled Task/Job", "tactics": ["Persistence"],
                 "count": 4, "event_ids": ["E1"]},
                {"id": "T1110", "technique": "Brute Force", "tactics": ["Credential Access"],
                 "count": 30, "event_ids": ["E2"]},
                {"id": "T1078", "technique": "Valid Accounts", "tactics": ["Initial Access"],
                 "count": 2, "event_ids": ["E3"]},
            ]
        }
        content, observed, gaps = summarize_kill_chain(result)
        # ATT&CK kill-chain order: Initial Access < Persistence < Credential Access.
        self.assertLess(content.index("Initial Access"), content.index("Persistence"))
        self.assertLess(content.index("Persistence"), content.index("Credential Access"))
        self.assertEqual(observed, ["Initial Access", "Persistence", "Credential Access"])
        # Execution / C2 / Exfiltration had no evidence → flagged as gaps.
        for gap in ("Execution", "Command and Control", "Exfiltration"):
            self.assertIn(gap, gaps)
        self.assertIn("GAPS", content)
        self.assertIn("T1110 Brute Force×30[E2]", content)

    def test_no_techniques_returns_all_core_gaps(self):
        content, observed, gaps = summarize_kill_chain({"techniques": []})
        self.assertEqual(observed, [])
        self.assertIn("Initial Access", gaps)
        self.assertIn("no MITRE", content)

    def test_accepts_raw_json_string_and_bad_input(self):
        self.assertEqual(summarize_kill_chain("not json")[1], [])
        c, o, g = summarize_kill_chain(json.dumps({"techniques": [
            {"id": "T1059", "technique": "Command Interp.", "tactics": ["Execution"], "count": 1}]}))
        self.assertEqual(o, ["Execution"])


class GapLeadSpecsTest(unittest.TestCase):
    def test_specs_carry_pivots_host_and_priority(self):
        specs = gap_lead_specs(["Execution"], "kali", window_hint="Window: ±48h.")
        self.assertEqual(len(specs), 1)
        s = specs[0]
        self.assertIn("kali", s["title"])
        self.assertIn("Execution", s["title"])
        self.assertIn("80792", s["description"])      # the technique→query pivot
        self.assertIn("Window: ±48h.", s["description"])
        # Gap leads sit in the 50–74 scoping band (speculative coverage), below the
        # 85–94 forward band reserved for grounded pivots extending confirmed evidence.
        self.assertEqual(s["priority"], 60)
        self.assertLessEqual(s["priority"], 74)

    def test_capped_and_sorted_by_priority(self):
        gaps = ["Initial Access", "Persistence", "Execution", "Command and Control",
                "Exfiltration", "Impact"]
        specs = gap_lead_specs(gaps, "kali")
        self.assertEqual(len(specs), MAX_GAP_LEADS)       # capped at 4
        prios = [s["priority"] for s in specs]
        self.assertEqual(prios, sorted(prios, reverse=True))
        # Highest-value forward phases win the cap; low-priority Initial Access drops.
        tactics = [s["tactic"] for s in specs]
        self.assertIn("Impact", tactics)
        self.assertNotIn("Initial Access", tactics)
        # No speculative gap lead may enter the 85–94 grounded forward band; that band
        # is reserved for pivots extending confirmed evidence (Phase 0 #10).
        self.assertTrue(all(p <= 74 for p in prios))

    def test_gap_after_confirmed_phase_is_high_priority_forward_trace(self):
        # Initial Access confirmed → the adjacent Privilege Escalation gap is a forward
        # trace ("what did they do next on this host?"), not a low rule-out backstop.
        specs = gap_lead_specs(["Privilege Escalation"], "wazuh-client",
                               observed=["Initial Access"])
        s = specs[0]
        self.assertEqual(s["priority"], 88)              # forward/active band, not 58
        self.assertIn("Trace forward to Privilege Escalation", s["title"])
        self.assertIn("foothold", s["description"].lower())

    def test_gap_before_any_confirmed_phase_stays_rule_out(self):
        # Nothing established earlier than Initial Access → backward/speculative rule-out.
        specs = gap_lead_specs(["Initial Access"], "wazuh-client", observed=["Execution"])
        s = specs[0]
        self.assertLessEqual(s["priority"], 74)
        self.assertIn("Establish or rule out", s["title"])

    def test_forward_trace_outranks_rule_out_when_mixed(self):
        # Initial Access confirmed: Privilege Escalation (later) is a forward trace;
        # Reconnaissance (earlier) is a backward rule-out.
        specs = gap_lead_specs(
            ["Reconnaissance", "Privilege Escalation"], "wazuh-client",
            observed=["Initial Access"],
        )
        by_tactic = {s["tactic"]: s for s in specs}
        self.assertEqual(by_tactic["Privilege Escalation"]["priority"], 88)  # forward
        self.assertLessEqual(by_tactic["Reconnaissance"]["priority"], 74)    # rule-out
        self.assertEqual(specs[0]["tactic"], "Privilege Escalation")         # sorts first

    def test_no_observed_keeps_legacy_rule_out_behaviour(self):
        # Back-compat: without `observed`, nothing is boosted (existing callers/tests).
        specs = gap_lead_specs(["Execution", "Impact"], "kali")
        self.assertTrue(all(s["priority"] <= 74 for s in specs))

    def test_pivots_for_tactic(self):
        self.assertIn("80792", pivots_for_tactic("Execution"))
        self.assertIn("/dev/tcp", pivots_for_tactic("Command and Control"))
        self.assertEqual(pivots_for_tactic("Nonexistent"), "")


class _FakeTechClient:
    def __init__(self, payload):
        self.posts = []
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, path, json):
        self.posts.append((path, json))
        return httpx.Response(200, json=self._payload,
                              request=httpx.Request("POST", f"https://w{path}"))


class CorrelateTechniquesClientTest(unittest.TestCase):
    def _client(self, fake):
        c = WazuhClient.__new__(WazuhClient)
        c._default_index = "wazuh-alerts-*"
        c._client = lambda: fake
        return c

    def test_parses_techniques_and_tactics(self):
        payload = {
            "hits": {"total": {"value": 36}},
            "aggregations": {
                "by_technique": {"buckets": [
                    {"key": "T1110", "doc_count": 30,
                     "technique": {"buckets": [{"key": "Brute Force"}]},
                     "tactic": {"buckets": [{"key": "Credential Access"}]},
                     "first": {"value_as_string": "2025-04-19T01:50:00Z"},
                     "samples": {"hits": {"hits": [{"_id": "E2"}]}}},
                ]},
                "by_tactic": {"buckets": [{"key": "Credential Access", "doc_count": 30}]},
            },
        }
        fake = _FakeTechClient(payload)
        client = self._client(fake)
        out = client.correlate_techniques("2025-04-19T00:00:00Z", "2025-04-20T00:00:00Z",
                                          query={"term": {"agent.name": "kali"}})
        self.assertEqual(out["total_events"], 36)
        t = out["techniques"][0]
        self.assertEqual(t["id"], "T1110")
        self.assertEqual(t["technique"], "Brute Force")
        self.assertEqual(t["tactics"], ["Credential Access"])
        self.assertEqual(t["event_ids"], ["E2"])
        # Query carries the mitre-exists filter + the host scope + range.
        must = fake.posts[0][1]["query"]["bool"]["must"]
        self.assertTrue(any(c.get("exists", {}).get("field") == "rule.mitre.id" for c in must))
        self.assertTrue(any("term" in c and c["term"].get("agent.name") == "kali" for c in must))


if __name__ == "__main__":
    unittest.main(verbosity=2)
