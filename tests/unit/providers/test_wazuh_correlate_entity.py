from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient

_START = "2026-06-25T00:00:00Z"
_END = "2026-06-25T04:00:00Z"


def _aggs_response(total: int) -> dict:
    """Canned aggregation response for link_fields=['data.dstuser', 'agent.name'].

    The client names neighbor aggs nf0, nf1... in the order of (link_fields minus the
    pinned entity field), so these keys line up when the entity field is not in the list.
    """
    return {
        "hits": {"total": {"value": total}},
        "aggregations": {
            "first": {"value_as_string": "2026-06-25T00:05:00Z"},
            "last": {"value_as_string": "2026-06-25T03:50:00Z"},
            "nf0": {  # data.dstuser
                "buckets": [
                    {
                        "key": "root",
                        "doc_count": 120,
                        "first": {"value_as_string": "2026-06-25T00:05:00Z"},
                        "last": {"value_as_string": "2026-06-25T01:00:00Z"},
                        "samples": {"hits": {"hits": [{"_id": "e1"}, {"_id": "e2"}]}},
                    },
                    {
                        "key": "svc",
                        "doc_count": 1,
                        "first": {"value_as_string": "2026-06-25T02:00:00Z"},
                        "last": {"value_as_string": "2026-06-25T02:00:00Z"},
                        "samples": {"hits": {"hits": [{"_id": "e9"}]}},
                    },
                ]
            },
            "nf1": {  # agent.name
                "buckets": [
                    {
                        "key": "web-01",
                        "doc_count": 300,
                        "first": {"value_as_string": "2026-06-25T00:05:00Z"},
                        "last": {"value_as_string": "2026-06-25T03:50:00Z"},
                        "samples": {"hits": {"hits": [{"_id": "e3"}]}},
                    }
                ]
            },
        },
    }


class _FakeOpenSearchClient:
    def __init__(self, total: int = 412) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._total = total

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, path: str, json: dict) -> httpx.Response:
        self.posts.append((path, json))
        return httpx.Response(
            200,
            json=_aggs_response(self._total),
            request=httpx.Request("POST", f"https://wazuh.local{path}"),
        )


_LINKS = ["data.dstuser", "agent.name"]


class TestWazuhCorrelateEntity(unittest.TestCase):
    def _client(self, fake: _FakeOpenSearchClient) -> WazuhClient:
        client = WazuhClient.__new__(WazuhClient)
        client._default_index = "wazuh-alerts-*"
        client._client = lambda: fake  # type: ignore[method-assign]
        return client

    def _pinned_term(self, body: dict) -> dict:
        return body["query"]["bool"]["must"][0]["term"]

    def test_neighbors_parsed_with_counts_ids_and_timebounds(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.correlate_entity(
            "data.srcuser", "victim", _START, _END, link_fields=_LINKS
        )

        self.assertEqual(result["entity"], {"field": "data.srcuser", "value": "victim"})
        self.assertEqual(result["total_events"], 412)
        self.assertEqual(result["first_seen"], "2026-06-25T00:05:00Z")
        dstuser = result["neighbors"]["data.dstuser"]
        self.assertEqual(dstuser[0]["value"], "root")
        self.assertEqual(dstuser[0]["count"], 120)
        self.assertEqual(dstuser[0]["event_ids"], ["e1", "e2"])
        self.assertEqual(result["neighbors"]["agent.name"][0]["value"], "web-01")

    def test_entity_field_excluded_from_neighbor_aggs(self):
        # Pinning data.dstuser should drop it from the neighbor set, leaving only agent.name.
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        client.correlate_entity(
            "data.dstuser", "root", _START, _END, link_fields=_LINKS
        )

        aggs = fake.posts[0][1]["aggs"]
        neighbor_terms = {v["terms"]["field"] for k, v in aggs.items() if k.startswith("nf")}
        self.assertEqual(neighbor_terms, {"agent.name"})

    def test_pinned_term_and_range_filter_applied(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        client.correlate_entity("data.srcuser", "victim", _START, _END, link_fields=_LINKS)

        body = fake.posts[0][1]
        self.assertEqual(self._pinned_term(body), {"data.srcuser": "victim"})
        must = body["query"]["bool"]["must"]
        self.assertTrue(any("range" in c for c in must))
        self.assertEqual(body["size"], 0)

    def test_min_cooccurrence_filters_small_buckets(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.correlate_entity(
            "data.srcuser", "victim", _START, _END, link_fields=_LINKS, min_cooccurrence=5
        )

        values = [e["value"] for e in result["neighbors"]["data.dstuser"]]
        self.assertEqual(values, ["root"])  # svc (count=1) dropped

    def test_ip_entity_triggers_cross_role_query(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.correlate_entity(
            "data.srcip", "1.2.3.4", _START, _END, link_fields=_LINKS
        )

        self.assertEqual(len(fake.posts), 2)
        self.assertEqual(self._pinned_term(fake.posts[0][1]), {"data.srcip": "1.2.3.4"})
        self.assertEqual(self._pinned_term(fake.posts[1][1]), {"data.dstip": "1.2.3.4"})
        self.assertEqual(result["cross_role"]["field"], "data.dstip")
        self.assertIn("data.dstuser", result["cross_role"]["neighbors"])

    def test_match_fields_pins_value_across_fields_and_skips_cross_role(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.correlate_entity(
            "data.srcip", "10.0.2.5", _START, _END, link_fields=_LINKS,
            match_fields=["data.srcip", "data.dstip"],
        )

        # Single aggregation query — no separate cross_role pass.
        self.assertEqual(len(fake.posts), 1)
        self.assertNotIn("cross_role", result)
        self.assertEqual(result["entity"]["match_fields"], ["data.srcip", "data.dstip"])
        # Pin is a bool-should over both role fields, not a single term.
        pin = fake.posts[0][1]["query"]["bool"]["must"][0]
        terms = {list(c["term"])[0] for c in pin["bool"]["should"]}
        self.assertEqual(terms, {"data.srcip", "data.dstip"})

    def test_match_fields_excluded_from_neighbor_aggs(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        # data.dstuser is both a match field and a link field → must be dropped as a neighbor.
        client.correlate_entity(
            "data.srcuser", "joe", _START, _END, link_fields=_LINKS,
            match_fields=["data.srcuser", "data.dstuser"],
        )
        aggs = fake.posts[0][1]["aggs"]
        neighbor_terms = {v["terms"]["field"] for k, v in aggs.items() if k.startswith("nf")}
        self.assertEqual(neighbor_terms, {"agent.name"})  # data.dstuser excluded

    def test_non_ip_entity_has_no_cross_role(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.correlate_entity(
            "agent.name", "web-01", _START, _END, link_fields=["data.dstuser", "data.srcip"]
        )

        self.assertEqual(len(fake.posts), 1)
        self.assertNotIn("cross_role", result)

    def test_too_connected_flag_on_noisy_entity(self):
        fake = _FakeOpenSearchClient(total=50000)
        client = self._client(fake)

        result = client.correlate_entity(
            "agent.name", "busy-host", _START, _END, link_fields=_LINKS
        )

        self.assertTrue(result.get("too_connected"))
        self.assertIn("note", result)

    def test_samples_subagg_requested_per_neighbor(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        client.correlate_entity("data.srcuser", "victim", _START, _END, link_fields=_LINKS)

        nf0 = fake.posts[0][1]["aggs"]["nf0"]
        self.assertIn("samples", nf0["aggs"])
        self.assertIn("top_hits", nf0["aggs"]["samples"])
        self.assertEqual(nf0["aggs"]["samples"]["top_hits"]["_source"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
