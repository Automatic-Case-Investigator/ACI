"""Unit tests for query + schema memoization (Phase 1 #13/#18)."""
from __future__ import annotations

import json
import os
import sys
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from agent.runtime.analysis.query_memo import (  # noqa: E402
    BROAD_HIT_THRESHOLD,
    broad_query_memo,
    extract_hit_count,
    extract_schema_fields,
    normalize_query_shape,
)


class NormalizeQueryShapeTest(unittest.TestCase):
    def test_keyword_shape_order_and_space_independent(self):
        a = normalize_query_shape("search_keyword", {"query": "wazuh-client 172.17.130.196"})
        b = normalize_query_shape("search_keyword", {"query": "172.17.130.196   wazuh-client"})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("kw:"))

    def test_keyword_empty_returns_none(self):
        self.assertIsNone(normalize_query_shape("search_keyword", {"query": "   "}))
        self.assertIsNone(normalize_query_shape("search_keyword", {}))

    def test_dsl_shape_time_range_independent(self):
        d1 = {"query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "a", "lte": "b"}}},
            {"term": {"data.srcip": "1.2.3.4"}},
            {"term": {"agent.name": "h1"}},
        ]}}}
        d2 = {"query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "X", "lte": "Y"}}},
            {"term": {"agent.name": "h1"}},
            {"term": {"data.srcip": "1.2.3.4"}},
        ]}}}
        s1 = normalize_query_shape("search", d1)
        s2 = normalize_query_shape("search", d2)
        self.assertEqual(s1, s2)
        self.assertIn("data.srcip=1.2.3.4", s1)
        self.assertIn("agent.name=h1", s1)
        self.assertNotIn("@timestamp", s1)

    def test_non_search_tool_returns_none(self):
        self.assertIsNone(normalize_query_shape("get_event", {"query": "x"}))


class ExtractHitCountTest(unittest.TestCase):
    def test_total_field(self):
        self.assertEqual(extract_hit_count(json.dumps({"total": 1258016, "events": [{"_id": "x"}]})), 1258016)

    def test_events_fallback_when_total_zero(self):
        self.assertEqual(extract_hit_count(json.dumps({"total": 0, "events": [{"_id": "a"}, {"_id": "b"}]})), 2)

    def test_non_search_payload_returns_none(self):
        self.assertIsNone(extract_hit_count(json.dumps({"_id": "doc"})))

    def test_malformed_returns_none(self):
        self.assertIsNone(extract_hit_count("not json"))


class BroadQueryMemoTest(unittest.TestCase):
    def test_broad_keyword_query_memoized(self):
        memo = broad_query_memo(
            "search_keyword", {"query": "wazuh-client 172.17.130.196"},
            json.dumps({"total": 1258016, "events": []}),
        )
        self.assertIsNotNone(memo)
        key, content = memo
        self.assertTrue(key.startswith("qmemo:kw:"))
        self.assertIn("discriminator", content)

    def test_narrow_query_not_memoized(self):
        memo = broad_query_memo(
            "search_keyword", {"query": "rule.id 5402 phopkins"},
            json.dumps({"total": 3, "events": []}),
        )
        self.assertIsNone(memo)

    def test_at_threshold_is_broad(self):
        memo = broad_query_memo(
            "search_keyword", {"query": "a b"},
            json.dumps({"total": BROAD_HIT_THRESHOLD, "events": []}),
        )
        self.assertIsNotNone(memo)

    def test_non_search_tool_not_memoized(self):
        self.assertIsNone(broad_query_memo("get_event", {"query": "x"}, json.dumps({"total": 999999})))


class ExtractSchemaFieldsTest(unittest.TestCase):
    def test_fields_dict(self):
        fields = extract_schema_fields(
            "get_index_schema", json.dumps({"fields": {"data.srcip": "ip", "rule.id": "keyword"}}))
        self.assertEqual(fields, ["data.srcip", "rule.id"])

    def test_fields_list_of_names(self):
        fields = extract_schema_fields("get_index_schema", json.dumps({"fields": ["a", "b", "a"]}))
        self.assertEqual(fields, ["a", "b"])

    def test_mappings_properties(self):
        fields = extract_schema_fields(
            "get_index_schema",
            json.dumps({"mappings": {"properties": {"f1": {"type": "keyword"}, "f2": {"type": "ip"}}}}))
        self.assertEqual(fields, ["f1", "f2"])

    def test_non_schema_tool_returns_none(self):
        self.assertIsNone(extract_schema_fields("search", json.dumps({"fields": {"x": "y"}})))


if __name__ == "__main__":
    unittest.main(verbosity=2)
