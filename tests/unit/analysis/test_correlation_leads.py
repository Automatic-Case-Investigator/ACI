from __future__ import annotations

import json
import os
import sys
import unittest
from dataclasses import dataclass

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.analysis.correlation_leads import (
    corr_dedup_key, derive_window, entities_from_neighbors, field_for, match_fields_for,
    normalize_entity_value, select_targets, summarize_correlation,
)


@dataclass(frozen=True)
class _Art:
    kind: str
    value: str
    source: str = ""


class SelectTargetsTest(unittest.TestCase):
    def test_only_pivotable_kinds(self):
        arts = [_Art("ip", "1.2.3.4"), _Art("file", "/tmp/x"), _Art("command", "sh -i"),
                _Art("domain", "evil.com")]
        picked = select_targets(arts, covered=set(), remaining_budget=8)
        self.assertEqual(picked, [("ip", "1.2.3.4", "data.srcip")])

    def test_priority_orders_ip_first_under_batch_cap(self):
        arts = [_Art("host", "web-01"), _Art("ip", "1.1.1.1"), _Art("user", "joe")]
        picked = select_targets(arts, covered=set(), remaining_budget=8, max_per_batch=2)
        kinds = [k for k, _, _ in picked]
        self.assertEqual(kinds, ["ip", "user"])  # host drops under the cap

    def test_dedup_within_batch(self):
        arts = [_Art("ip", "1.1.1.1"), _Art("ip", "1.1.1.1")]
        self.assertEqual(len(select_targets(arts, covered=set(), remaining_budget=8)), 1)

    def test_skips_covered(self):
        arts = [_Art("ip", "1.1.1.1"), _Art("user", "joe")]
        picked = select_targets(arts, covered={corr_dedup_key("ip", "1.1.1.1")}, remaining_budget=8)
        self.assertEqual([k for k, _, _ in picked], ["user"])

    def test_remaining_budget_zero(self):
        self.assertEqual(select_targets([_Art("ip", "x")], covered=set(), remaining_budget=0), [])

    def test_host_is_not_auto_correlated(self):
        # The monitored host returns the whole dataset — excluded from auto-correlation.
        arts = [_Art("host", "kali"), _Art("user", "joe")]
        picked = select_targets(arts, covered=set(), remaining_budget=8)
        self.assertEqual([k for k, _, _ in picked], ["user"])

    def test_field_mapping(self):
        self.assertEqual(field_for("ip"), "data.srcip")
        self.assertEqual(field_for("user"), "data.srcuser")

    def test_match_fields_are_role_agnostic(self):
        self.assertEqual(match_fields_for("ip"), ["data.srcip", "data.dstip"])
        self.assertIn("data.dstuser", match_fields_for("user"))


class DeriveWindowTest(unittest.TestCase):
    def test_bounds_from_event_timestamps_with_padding(self):
        raw = json.dumps({"events": [
            {"@timestamp": "2025-04-20T03:00:00Z"},
            {"@timestamp": "2025-04-20T05:00:00.500Z"},
        ]})
        start, end = derive_window(raw, vicinity_hours=2)
        self.assertEqual(start, "2025-04-20T01:00:00Z")  # 03:00 - 2h
        self.assertEqual(end, "2025-04-20T07:00:00Z")    # 05:00 (+0.5s) + 2h, floored to sec

    def test_no_timestamps_returns_none(self):
        self.assertEqual(derive_window('{"events":[{"foo":"bar"}]}', 24), (None, None))

    def test_mixed_naive_and_aware_timestamps_do_not_raise(self):
        # Wazuh mixes offset-aware (Z) and naive timestamps; min/max must not raise.
        raw = json.dumps({"events": [
            {"@timestamp": "2025-04-20T03:00:00Z"},      # aware
            {"ts": "2025-04-20T05:00:00"},                # naive
        ]})
        start, end = derive_window(raw, vicinity_hours=1)
        self.assertEqual(start, "2025-04-20T02:00:00Z")
        self.assertEqual(end, "2025-04-20T06:00:00Z")


class SummarizeCorrelationTest(unittest.TestCase):
    def _result(self, **kw):
        base = {
            "entity": {"field": "data.srcip", "value": "10.0.2.5"},
            "total_events": 412,
            "first_seen": "2025-04-19T01:50:08.000Z",
            "last_seen": "2025-04-20T03:53:58.000Z",
            "neighbors": {
                "data.dstuser": [
                    {"value": "root", "count": 24, "event_ids": ["E1", "E2"]},
                    {"value": "admin", "count": 3, "event_ids": ["E3"]},
                ],
                "agent.name": [{"value": "kali", "count": 43, "event_ids": ["E9"]}],
            },
        }
        base.update(kw)
        return json.dumps(base)

    def test_renders_neighbors_with_event_anchor(self):
        content, n, cross = summarize_correlation("ip", "10.0.2.5", self._result())
        self.assertIn("correlation[data.srcip 10.0.2.5] 412 ev", content)
        self.assertIn("data.dstuser=root×24[E1]", content)
        self.assertIn("agent.name=kali×43[E9]", content)
        self.assertEqual(n, 2)
        self.assertFalse(cross)

    def test_cross_role_appended(self):
        r = self._result(cross_role={
            "field": "data.dstip", "total_events": 8,
            "neighbors": {"data.srcuser": [{"value": "victim", "count": 8, "event_ids": ["X1"]}]},
        })
        content, n, cross = summarize_correlation("ip", "10.0.2.5", r)
        self.assertTrue(cross)
        self.assertIn("|| cross_role[data.dstip] 8 ev", content)
        self.assertIn("data.srcuser=victim×8[X1]", content)

    def test_too_connected_flag(self):
        content, _, _ = summarize_correlation("ip", "10.0.2.5", self._result(too_connected=True))
        self.assertIn("too_connected", content)

    def test_error_result_is_safe(self):
        content, n, cross = summarize_correlation("ip", "x", '{"error": "boom"}')
        self.assertEqual((n, cross), (0, False))
        self.assertIn("no neighborhood", content)

    def test_unparseable_result_is_safe(self):
        content, n, cross = summarize_correlation("user", "joe", "not json")
        self.assertEqual((n, cross), (0, False))

    def test_via_provenance_in_content(self):
        content, _, _ = summarize_correlation("user", "root", self._result(), via="ip:10.0.2.5")
        self.assertIn("(via ip:10.0.2.5)", content)


class MultiHopExpansionTest(unittest.TestCase):
    def test_entities_from_neighbors_maps_fields_to_kinds(self):
        result = json.dumps({"neighbors": {
            "data.dstuser": [{"value": "root(uid=0)", "count": 5}, {"value": "svc", "count": 2}],
            "data.srcip": [{"value": "10.0.2.5", "count": 9}],
            "agent.name": [{"value": "kali", "count": 9}],   # host → ignored
            "rule.groups": [{"value": "sudo", "count": 3}],  # not an entity field
        }})
        ents = set(entities_from_neighbors(result))
        self.assertIn(("user", "root"), ents)        # uid suffix normalized
        self.assertIn(("user", "svc"), ents)
        self.assertIn(("ip", "10.0.2.5"), ents)
        self.assertNotIn(("host", "kali"), ents)     # host excluded
        self.assertTrue(all(k in ("ip", "user") for k, _ in ents))

    def test_entities_from_neighbors_includes_cross_role(self):
        result = json.dumps({
            "neighbors": {},
            "cross_role": {"field": "data.dstip",
                           "neighbors": {"data.srcuser": [{"value": "victim", "count": 8}]}},
        })
        self.assertIn(("user", "victim"), entities_from_neighbors(result))

    def test_entities_from_neighbors_drops_junk(self):
        result = json.dumps({"neighbors": {"data.srcuser": [
            {"value": "?", "count": 9}, {"value": "", "count": 1}, {"value": "-", "count": 1},
        ]}})
        self.assertEqual(entities_from_neighbors(result), [])

    def test_normalize_entity_value_strips_uid_for_users_only(self):
        self.assertEqual(normalize_entity_value("user", "root(uid=0)"), "root")
        self.assertEqual(normalize_entity_value("ip", "10.0.2.5"), "10.0.2.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
