"""Wazuh OpenSearch REST API client."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx


class WazuhClient:
    def __init__(self) -> None:
        # Accept either a full URL (WAZUH_URL) or host+port components.
        url = os.environ.get("WAZUH_URL") or ""
        if not url:
            host = os.environ["WAZUH_HOST"]
            port = os.environ.get("WAZUH_PORT", "9200")
            url = f"https://{host}:{port}"
        self._base = url.rstrip("/")

        user = os.environ.get("WAZUH_USER", "admin")
        password = os.environ.get("WAZUH_PASSWORD", "")
        verify = os.environ.get("WAZUH_VERIFY_TLS", "false").lower() == "true"

        self._auth = (user, password)
        self._verify = verify
        self._default_index = os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
        self._shared: httpx.Client | None = None

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._base,
            auth=self._auth,
            verify=self._verify,
            timeout=30,
        )

    def _get_client(self) -> httpx.Client:
        """Return a reusable HTTP client (kept open across searches for connection
        pooling). Investigations fire many sequential searches; opening a fresh TLS
        connection per call is the dominant cost against a remote OpenSearch."""
        if self._shared is None or self._shared.is_closed:
            self._shared = self._client()
        return self._shared

    def list_indices(self) -> list[str]:
        with self._client() as c:
            resp = c.get("/_cat/indices?format=json&h=index")
            if resp.is_error:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text[:1000]
                raise RuntimeError(f"OpenSearch error {resp.status_code}: {body}")
            return [row["index"] for row in resp.json() if not row["index"].startswith(".")]

    def get_index_schema(self, index_pattern: str) -> dict[str, Any]:
        with self._client() as c:
            resp = c.get(f"/{index_pattern}/_mapping")
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()
            fields: dict = {}
            for idx_data in data.values():
                props = idx_data.get("mappings", {}).get("properties", {})
                self._flatten_props("", props, fields)
            return {"index_pattern": index_pattern, "fields": fields}

    def _flatten_props(self, prefix: str, props: dict, out: dict) -> None:
        for name, meta in props.items():
            full = f"{prefix}{name}"
            out[full] = meta.get("type", "object")
            nested = meta.get("properties", {})
            if nested:
                self._flatten_props(f"{full}.", nested, out)

    @staticmethod
    def _as_dsl(query: dict | str) -> dict:
        """Coerce the caller's query into an explicit OpenSearch Query DSL object.

        Accepts a dict, or a JSON string that decodes to a dict (models frequently
        serialize the DSL). Plain keyword strings are rejected: `search` is DSL-only.
        Use the `search_keyword` tool for free-text matching across all fields.
        """
        if isinstance(query, dict):
            return query
        if isinstance(query, str):
            try:
                parsed = json.loads(query)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "search requires an OpenSearch Query DSL object (e.g. "
                    '{"term": {"data.srcip": "1.2.3.4"}} or {"bool": {"must": [...]}}). '
                    f"The query could not be parsed as JSON ({exc}). For free-text "
                    "matching across all fields, use the search_keyword tool instead."
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError(
                    "search query DSL must be a JSON object (the value under the "
                    f"top-level `query` key), not a {type(parsed).__name__}."
                )
            return parsed
        raise ValueError(
            f"search query must be a DSL object, got {type(query).__name__}."
        )

    # Keys that are part of a *search request* but are NOT valid anywhere inside an
    # OpenSearch query DSL clause. Models frequently leak these into the `query`
    # argument (sometimes nested deep inside a `bool`); strip them everywhere.
    _NON_CLAUSE_KEYS = frozenset({
        "time_range", "max_results", "size", "index_pattern",
        "from", "to", "sort", "aggs", "aggregations", "_source",
        "source_fields",  # model-friendly alias sometimes nested inside the query dict
    })
    # Subset that is NEVER valid at any nesting level in a DSL object; strip recursively.
    _ALWAYS_INVALID = frozenset({"time_range", "max_results", "index_pattern"})

    @classmethod
    def _deep_clean(cls, obj: Any, rescued: list) -> Any:
        """Recursively strip request-level keys from a query DSL tree.

        Keys in _ALWAYS_INVALID (time_range, max_results, index_pattern) are invalid
        at every nesting level — even inside a `bool` clause. Strip them wherever they
        appear. If time_range is found and not yet rescued, save it so the caller can
        use it as the actual time filter.
        """
        if isinstance(obj, dict):
            out: dict = {}
            for k, v in obj.items():
                if k in cls._ALWAYS_INVALID:
                    if k == "time_range" and not rescued and isinstance(v, dict):
                        rescued.append(v)
                    # drop the key — do not pass it through to OpenSearch
                else:
                    out[k] = cls._deep_clean(v, rescued)
            return out
        if isinstance(obj, list):
            return [cls._deep_clean(i, rescued) for i in obj]
        return obj

    @classmethod
    def _unwrap_request(cls, dsl: dict, time_range: dict | None, max_results: int):
        """Tolerate the common mistake of passing a whole search request as `query`.

        The model sometimes nests `{"query": <dsl>, "time_range": ..., "max_results": ...}`
        inside the `query` argument, or embeds time_range/max_results inside a `bool`
        clause. Unwrap any top-level `query` key, rescue time_range/max_results, then
        deep-clean the DSL so no non-clause keys survive at any nesting level.
        """
        for _ in range(5):
            if not (isinstance(dsl, dict) and isinstance(dsl.get("query"), dict)):
                break
            if time_range is None and isinstance(dsl.get("time_range"), dict):
                time_range = dsl["time_range"]
            if isinstance(dsl.get("max_results"), int):
                max_results = dsl["max_results"]
            elif isinstance(dsl.get("size"), int):
                max_results = dsl["size"]
            dsl = dsl["query"]

        # Strip top-level non-clause keys that are valid at request level but not in DSL.
        if isinstance(dsl, dict):
            for key in list(dsl):
                if key in cls._NON_CLAUSE_KEYS:
                    if key == "time_range" and time_range is None and isinstance(dsl[key], dict):
                        time_range = dsl[key]
                    dsl.pop(key, None)

        # Deep-clean: remove time_range/max_results/index_pattern from any nested level.
        rescued: list = []
        dsl = cls._deep_clean(dsl, rescued)
        if time_range is None and rescued:
            time_range = rescued[0]

        return dsl, time_range, max_results

    def search(
        self,
        query: dict | str,
        index_pattern: str | None = None,
        time_range: dict | None = None,
        max_results: int = 20,
        source_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        index = index_pattern or self._default_index
        dsl = self._as_dsl(query)
        dsl, time_range, max_results = self._unwrap_request(dsl, time_range, max_results)
        body: dict = {"query": dsl}

        c = self._get_client()
        resp = c.post(f"/{index}/_search", json=body)
        if resp.is_error:
            try:
                return {"error": resp.json()}
            except Exception:
                return {"error": resp.text[:1000]}
        data = resp.json()

        hits = data.get("hits", {})
        total = hits.get("total", {})
        total_value = total.get("value", 0) if isinstance(total, dict) else total
        return {
            "total": total_value,
            "events": hits.get("hits", []),
        }

    def _range_filter(self, time_range: dict | None) -> dict | None:
        if not time_range:
            return None
        return {"range": {"@timestamp": {
            "gte": time_range.get("from", "now-24h"),
            "lte": time_range.get("to", "now"),
        }}}

    def profile_field(
        self,
        field: str,
        index_pattern: str | None = None,
        time_range: dict | None = None,
        top_n: int = 10,
        query: dict | str | None = None,
    ) -> dict[str, Any]:
        """Return the most common values of a field (terms aggregation).

        Useful for understanding the shape of the data: top source IPs, users,
        rule IDs, processes, etc. Wazuh string fields are mapped as `keyword`, so
        they aggregate directly — there is no `.keyword` subfield to fall back to.
        """
        index = index_pattern or self._default_index

        must: list[dict] = []
        if query:
            if isinstance(query, dict):
                clause, time_range, _ = self._unwrap_request(query, time_range, top_n)
                must.append(clause)
            else:
                must.append({"query_string": {"query": query}})
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)

        def _run(agg_field: str) -> dict:
            body: dict = {
                "size": 0,
                "track_total_hits": True,
                "aggs": {"top": {"terms": {"field": agg_field, "size": min(top_n, 100)}}},
            }
            if must:
                body["query"] = {"bool": {"must": must}}
            with self._client() as c:
                resp = c.post(f"/{index}/_search", json=body)
                if resp.is_error:
                    try:
                        return {"_error": resp.json()}
                    except Exception:
                        return {"_error": resp.text[:1000]}
                return resp.json()

        used_field = field
        data = _run(field)
        if "_error" in data:
            err = data["_error"]
            raise ValueError(
                f"Cannot aggregate field '{field}': {err}. "
                "It may be a non-aggregatable text field or may not exist. "
                "Verify the exact field name with get_index_schema; "
                "do not append '.keyword' (Wazuh has no such subfield)."
            )

        agg = data.get("aggregations", {}).get("top", {})
        return {
            "field": used_field,
            "matched_docs": data.get("hits", {}).get("total", {}).get("value", 0),
            "top_values": [
                {"value": b["key"], "count": b["doc_count"]} for b in agg.get("buckets", [])
            ],
            "other_count": agg.get("sum_other_doc_count", 0),
        }

    def search_keyword(
        self,
        keyword: str,
        index_pattern: str | None = None,
        time_range: dict | None = None,
        max_results: int = 20,
    ) -> dict[str, Any]:
        """Find events containing a keyword in ANY field (full-text across all fields)."""
        index = index_pattern or self._default_index
        must: list[dict] = [
            {"multi_match": {"query": keyword, "fields": ["*"], "lenient": True}}
        ]
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)

        body = {"query": {"bool": {"must": must}}, "size": min(max_results, 100)}
        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()

        hits = data.get("hits", {})
        return {
            "total": hits.get("total", {}).get("value", 0),
            "events": hits.get("hits", []),
        }

    def aggregate(
        self,
        aggs: dict,
        query: dict | None = None,
        time_range: dict | None = None,
        index_pattern: str | None = None,
    ) -> dict[str, Any]:
        """Run an arbitrary OpenSearch aggregation and return the raw `aggregations` dict."""
        index = index_pattern or self._default_index
        body: dict = {"size": 0, "aggs": aggs}

        must: list[dict] = []
        if query:
            clause, time_range, _ = self._unwrap_request(query, time_range, 0)
            must.append(clause)
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)
        if must:
            body["query"] = {"bool": {"must": must}}

        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            return resp.json().get("aggregations", {})

    def get_event(self, event_id: str, index_pattern: str | None = None) -> dict[str, Any]:
        # NB: a plain `GET /<index>/_doc/<id>` does NOT work against a wildcard index
        # pattern (e.g. 'wazuh-alerts-4.x-*'), which is the normal case here. Use an
        # ids search so the document is found regardless of which concrete index holds it.
        index = index_pattern or self._default_index
        body = {"query": {"ids": {"values": [event_id]}}, "size": 1}
        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return {"error": f"No event found with _id '{event_id}' in index '{index}'."}
        h = hits[0]
        return {"_id": h["_id"], "_index": h["_index"], **h.get("_source", {})}
