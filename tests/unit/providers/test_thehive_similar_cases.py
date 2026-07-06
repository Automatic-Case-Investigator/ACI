from __future__ import annotations

import os
import sys
import unittest

import httpx

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "aci-mcp-servers", "aci-thehive"))

from aci_thehive.client import TheHiveClient


def _http_error(status_code: int = 400) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://thehive/api/v1/query")
    response = httpx.Response(status_code, request=request, text="query step unsupported")
    return httpx.HTTPStatusError("query failed", request=request, response=response)


class TestGetSimilarCases(unittest.TestCase):
    def _client(self) -> TheHiveClient:
        return TheHiveClient.__new__(TheHiveClient)

    def test_uses_similar_cases_when_supported(self):
        client = self._client()
        queries: list[list[dict]] = []

        def fake_query(ops: list[dict]):
            queries.append(ops)
            return [{"_id": "~2"}]

        client._query = fake_query  # type: ignore[attr-defined]
        result = client.get_similar_cases("~1", max_items=7)

        self.assertEqual(result["query_operator"], "similarCases")
        self.assertEqual(result["cases"], [{"_id": "~2"}])
        self.assertEqual(queries[0][1]["_name"], "similarCases")
        self.assertEqual(queries[0][2], {"_name": "page", "from": 0, "to": 7})

    def test_falls_back_to_linked_cases_when_similar_cases_fails(self):
        client = self._client()
        queries: list[list[dict]] = []

        def fake_query(ops: list[dict]):
            queries.append(ops)
            if ops[1]["_name"] == "similarCases":
                raise _http_error()
            return [{"_id": "~3"}]

        client._query = fake_query  # type: ignore[attr-defined]
        result = client.get_similar_cases("~1", max_items=5)

        self.assertEqual([q[1]["_name"] for q in queries], ["similarCases", "linkedCases"])
        self.assertEqual(result["query_operator"], "linkedCases")
        self.assertEqual(result["cases"], [{"_id": "~3"}])

    def test_re_raises_when_fallback_also_fails(self):
        client = self._client()

        def fake_query(_: list[dict]):
            raise _http_error(404)

        client._query = fake_query  # type: ignore[attr-defined]
        with self.assertRaises(httpx.HTTPStatusError):
            client.get_similar_cases("~1", max_items=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
