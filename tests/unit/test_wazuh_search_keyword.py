from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-wazuh"))

from aci_wazuh.client import WazuhClient


class _FakeOpenSearchClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, path: str, json: dict) -> httpx.Response:
        self.posts.append((path, json))
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": 0}, "hits": []}},
            request=httpx.Request("POST", f"https://wazuh.local{path}"),
        )


class TestWazuhSearchKeyword(unittest.TestCase):
    def _client(self, fake: _FakeOpenSearchClient) -> WazuhClient:
        client = WazuhClient.__new__(WazuhClient)
        client._default_index = "wazuh-alerts-*"
        client._client = lambda: fake  # type: ignore[method-assign]
        return client

    def test_space_separated_terms_use_or_semantics(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        client.search_keyword(
            "powershell mimikatz svchost",
            time_range={"from": "2026-06-25T00:00:00Z", "to": "2026-06-25T01:00:00Z"},
            max_results=250,
        )

        self.assertEqual(fake.posts[0][0], "/wazuh-alerts-*/_search")
        self.assertEqual(fake.posts[0][1]["size"], 100)
        self.assertEqual(
            fake.posts[0][1]["query"],
            {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {
                                        "simple_query_string": {
                                            "query": "powershell mimikatz svchost",
                                            "fields": WazuhClient._SEARCH_KEYWORD_FIELDS,
                                            "default_operator": "or",
                                            "lenient": True,
                                        }
                                    },
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    ],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "2026-06-25T00:00:00Z",
                                    "lte": "2026-06-25T01:00:00Z",
                                }
                            }
                        }
                    ],
                }
            },
        )
        self.assertTrue(fake.posts[0][1]["track_total_hits"])

    def test_query_with_paths_uses_discover_style_parser(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        client.search_keyword(
            "kali nano crontab.Tgi9hP /tmp/crontab.Tgi9hP/crontab 10.0.2.15",
            time_range={"from": "2025-04-20T03:44:10Z", "to": "2025-04-20T04:04:10Z"},
        )

        clause = fake.posts[0][1]["query"]["bool"]["must"][0]["bool"]["should"][0]
        self.assertEqual(
            clause["simple_query_string"]["query"],
            "kali nano crontab.Tgi9hP /tmp/crontab.Tgi9hP/crontab 10.0.2.15",
        )
        self.assertIn("full_log", clause["simple_query_string"]["fields"])
        self.assertIn("data.audit.execve.a1", clause["simple_query_string"]["fields"])
        self.assertEqual(clause["simple_query_string"]["default_operator"], "or")

    def test_blank_query_returns_no_results_without_calling_opensearch(self):
        fake = _FakeOpenSearchClient()
        client = self._client(fake)

        result = client.search_keyword(" \t\n ")

        self.assertEqual(result, {"total": 0, "events": []})
        self.assertEqual(fake.posts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
