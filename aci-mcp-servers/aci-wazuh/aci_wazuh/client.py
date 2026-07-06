"""Wazuh OpenSearch REST API client."""
from __future__ import annotations

import json
import math
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx


class WazuhClient:
    _SEARCH_KEYWORD_FIELDS = [
        "full_log",
        "rule.description",
        "rule.groups",
        "rule.id",
        "agent.name",
        "agent.ip",
        "data.srcip",
        "data.dstip",
        "data.srcuser",
        "data.dstuser",
        "data.user",
        "data.command",
        "data.audit.command",
        "data.audit.exe",
        "data.audit.execve.a0",
        "data.audit.execve.a1",
        "data.audit.execve.a2",
        "data.audit.execve.a3",
        "data.audit.execve.a4",
        "data.audit.cwd",
        "data.audit.file.name",
        "data.win.eventdata.image",
        "data.win.eventdata.commandLine",
        "data.win.eventdata.parentImage",
        "syscheck.path",
        "syscheck.diff",
        "location",
    ]

    # Above this many matches, an all-terms keyword search is still considered too
    # broad to be useful as evidence; the result is flagged so the caller narrows.
    _BROAD_RESULT_THRESHOLD = 500

    # Candidate categorical fields for the flood SELECTIVITY MAP. When a search is
    # flooded, a terms aggregation over each of these reveals which axis the events
    # actually vary along (a dominant value with a small minority = the discriminator;
    # minority values are candidate deviations to inspect). Over-inclusive is safe: a
    # field absent from the matched set returns no buckets and is skipped. Low/medium cardinality only — a high-cardinality field
    # (e.g. data.url, which a scan spreads across hundreds of paths) has no dominant
    # value and is deprioritized by the ranker, never chosen as the discriminator.
    # NOTE: the exact Wazuh fields for HTTP method/status vary by ruleset (status is
    # often decoded into `data.id`); tune this list against `get_index_schema`.
    _SELECTIVITY_FIELDS = (
        "rule.id",
        "rule.level",
        "data.id",          # HTTP status code on web accesslog rules (200 vs 404)
        "data.protocol",    # HTTP method / protocol on many web rules (GET vs POST)
        "data.srcip",
        "data.dstip",
        "data.dstuser",
        "data.audit.exe",
    )
    # A field is a DISCRIMINATOR only when one value dominates this much of the flood
    # (so the rest is a genuine minority, not just an even spread) AND a non-empty
    # minority exists. A field whose dominant share is below this is high-cardinality
    # noise; one at ~1.0 with no minority is pure flood signature (a `must_not` target).
    _SELECTIVITY_DOMINANT_MIN = 0.6

    # An ISO-8601 date or datetime appearing as a *keyword term* is a model mistake:
    # timestamps belong in `time_range`, not in the text query (they match nothing and
    # trigger the OR-fallback explosion). Detected and stripped deterministically.
    _TS_TOKEN_RE = re.compile(
        r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
    )

    @classmethod
    def _strip_temporal_tokens(cls, query: str) -> tuple[str, list[str]]:
        """Drop ISO-8601 date/datetime tokens from a keyword query string.

        Returns (cleaned_query, dropped_tokens). Deterministic: timestamps are a
        time_range concern, never a text term.
        """
        kept, dropped = [], []
        for tok in query.split():
            (dropped if cls._TS_TOKEN_RE.match(tok) else kept).append(tok)
        return " ".join(kept), dropped

    @classmethod
    def _has_noop_should(cls, dsl: Any) -> bool:
        """True when a `bool` clause anywhere in the tree has `should` but no `must`
        and no `minimum_should_match` — a query shape that LOOKS like it filters on
        the `should` terms but, under Elasticsearch/OpenSearch defaults, does not:
        with no `must` clause, `minimum_should_match` defaults to 0, so the `should`
        list becomes scoring-only and the bool matches everything else in scope
        (commonly: the whole `filter` time range). This degrades a query that reads
        as narrow into one that returns the whole window — confirmed live (a query
        intending to match an IP/content discriminator silently returned 10,000+
        truncated hits because its only constraint was the time filter).
        """
        if isinstance(dsl, dict):
            b = dsl.get("bool")
            if isinstance(b, dict):
                has_should = bool(b.get("should"))
                has_must = bool(b.get("must"))
                has_msm = "minimum_should_match" in b
                if has_should and not has_must and not has_msm:
                    return True
            for v in dsl.values():
                if cls._has_noop_should(v):
                    return True
        elif isinstance(dsl, list):
            for v in dsl:
                if cls._has_noop_should(v):
                    return True
        return False

    @staticmethod
    def _query_error_hint(err: Any) -> str | None:
        """Map a known Elasticsearch parse failure to one actionable line.

        The raw ES stack trace is hard for an agent to act on; this returns concrete
        guidance for malformed structured queries (e.g. a bad `bool`/`should` clause).
        """
        low = str(err).lower()
        if any(k in low for k in ("parsing_exception", "query malformed",
                                  "x_content_parse_exception", "parse_exception")):
            return (
                "Your structured query is malformed and was not run. Every `bool` clause "
                "(`must`/`should`/`filter`) must be a LIST of clause objects, each a single "
                "query type such as {\"term\": {\"field\": \"value\"}}; do not nest `should` "
                "directly inside `should`. Rebuild it, or use `search_keyword` / `profile_field`."
            )
        return None

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

    # Leaf clause operators whose body is `{field: value}` — the places a query names a
    # field. Used to detect when a zero-hit result was caused by a wrong field NAME (which
    # returns 0 exactly like a genuine absence) rather than a true negative.
    _LEAF_FIELD_OPS = ("term", "terms", "match", "match_phrase", "match_phrase_prefix",
                       "wildcard", "prefix", "regexp", "fuzzy", "range")

    @classmethod
    def _query_leaf_fields(cls, dsl: Any) -> set[str]:
        """Collect every field NAME referenced by a leaf clause in a DSL tree."""
        fields: set[str] = set()

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for op in cls._LEAF_FIELD_OPS:
                    body = node.get(op)
                    if isinstance(body, dict):
                        for field_name in body:
                            if field_name != "boost":
                                fields.add(field_name)
                exists = node.get("exists")
                if isinstance(exists, dict) and isinstance(exists.get("field"), str):
                    fields.add(exists["field"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(dsl)
        fields.discard("@timestamp")
        return fields

    def _known_fields(self, index: str) -> set[str]:
        """Cached set of field names in the index mapping (empty on any failure → the
        field-existence check then simply stays silent, never a false negative)."""
        cache = getattr(self, "_schema_cache", None)
        if cache is None:
            cache = {}
            self._schema_cache = cache
        if index in cache:
            return cache[index]
        try:
            schema = self.get_index_schema(index)
            fields = set((schema.get("fields") or {}).keys()) if isinstance(schema, dict) else set()
        except Exception:
            fields = set()
        cache[index] = fields
        return fields

    @staticmethod
    def _field_candidates(queried: str, known: set[str]) -> list[str]:
        """Known mapping fields whose leaf segment matches the queried field's leaf
        segment (e.g. `url` → `data.url`), ranked shortest-first."""
        seg = str(queried).split(".")[-1].lower()
        cands = [
            k for k in known
            if k.lower() != str(queried).lower() and k.split(".")[-1].lower() == seg
        ]
        return sorted(cands, key=len)[:5]

    def _absent_field_warnings(self, index: str, queried_fields: set[str]) -> list[dict]:
        """For each queried field not present in the index mapping, a warning with
        candidate real field names. Empty if the mapping is unavailable (fail-open)."""
        known = self._known_fields(index)
        if not known:
            return []
        out: list[dict] = []
        for field_name in sorted(queried_fields):
            if field_name in known:
                continue
            out.append({
                "queried": field_name,
                "present": False,
                "candidates": self._field_candidates(field_name, known),
            })
        return out

    @staticmethod
    def _field_warning_note(warnings: list[dict]) -> str:
        parts = []
        for w in warnings:
            cands = ", ".join(w.get("candidates") or [])
            parts.append(f"`{w['queried']}`" + (f" (did you mean {cands}?)" if cands else ""))
        return (
            "0 hits — but the query references field name(s) not in the index mapping: "
            + "; ".join(parts)
            + ". A wrong field name returns 0 exactly like a genuine absence — correct the "
            "field name and re-run before concluding this is a negative."
        )

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

    @staticmethod
    def _clause_label(clause: Any) -> str:
        """Compact human label for one bool clause, e.g. 'data.srcip=1.2.3.4'."""
        if not isinstance(clause, dict):
            return str(clause)[:60]
        for op in ("term", "match", "match_phrase", "wildcard", "prefix"):
            body = clause.get(op)
            if isinstance(body, dict) and body:
                field, val = next(iter(body.items()))
                if isinstance(val, dict):
                    val = val.get("value", val.get("query", val))
                return f"{field}={val}"
        terms = clause.get("terms")
        if isinstance(terms, dict) and terms:
            field, vals = next(iter(terms.items()))
            vals = vals if isinstance(vals, list) else [vals]
            shown = ",".join(str(v) for v in vals[:4]) + ("…" if len(vals) > 4 else "")
            return f"{field} in [{shown}]"
        rng = clause.get("range")
        if isinstance(rng, dict) and rng:
            return f"{next(iter(rng))} range"
        exists = clause.get("exists")
        if isinstance(exists, dict):
            return f"exists {exists.get('field')}"
        if "bool" in clause:
            return "(nested bool)"
        return json.dumps(clause)[:60]

    @classmethod
    def _extract_bool_clauses(cls, dsl: Any) -> tuple[list, list]:
        """Return (must_clauses, should_clauses) from a DSL, dropping the @timestamp
        range (that is the window baseline, not a discriminator)."""
        def _not_ts(c: Any) -> bool:
            return not (isinstance(c, dict) and isinstance(c.get("range"), dict)
                        and "@timestamp" in c["range"])
        b = dsl.get("bool") if isinstance(dsl, dict) else None
        if not isinstance(b, dict):
            # A bare leaf query (e.g. a lone term) counts as a single must clause.
            if isinstance(dsl, dict) and dsl and "match_all" not in dsl and _not_ts(dsl):
                return [dsl], []
            return [], []
        def _norm(v: Any) -> list:
            return v if isinstance(v, list) else ([] if v is None else [v])
        musts = [c for c in _norm(b.get("must")) if _not_ts(c)]
        shoulds = [c for c in _norm(b.get("should")) if _not_ts(c)]
        return musts, shoulds

    def _clause_diagnostics(
        self, index: str, musts: list, shoulds: list, rng: dict | None
    ) -> dict | None:
        """Per-clause selectivity: for each must/should clause, how many documents in
        the query's time window match THAT clause alone (independent of its siblings).

        Exposes which discriminator is doing the work and which is a flood — e.g.
        `data.srcip=X` matching 1.2M while `rule.groups in [authentication_success]`
        matches 12 tells the caller the IP is broad and the auth-success clause is the
        more selective candidate, and reveals a `should` clause that barely narrows the
        result. Best-effort: one size=0 filters aggregation; returns None on any failure
        so search never breaks.
        """
        if not (musts or shoulds):
            return None
        filters: dict[str, Any] = {}
        labels: list[tuple[str, str, str]] = []
        for i, c in enumerate(musts):
            filters[f"m{i}"] = c
            labels.append((f"m{i}", "must", self._clause_label(c)))
        for i, c in enumerate(shoulds):
            filters[f"s{i}"] = c
            labels.append((f"s{i}", "should", self._clause_label(c)))
        base_query = {"bool": {"filter": [rng]}} if rng else {"match_all": {}}
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": base_query,
            "aggs": {"clauses": {"filters": {"filters": filters}}},
        }
        try:
            with self._client() as c:
                resp = c.post(f"/{index}/_search", json=body)
                if resp.is_error:
                    return None
                data = resp.json()
        except Exception:
            return None
        buckets = data.get("aggregations", {}).get("clauses", {}).get("buckets", {})
        window = data.get("hits", {}).get("total", {})
        window_docs = window.get("value", 0) if isinstance(window, dict) else window
        clauses = [
            {"clause": label, "type": kind, "matches": buckets.get(key, {}).get("doc_count", 0)}
            for key, kind, label in labels
        ]
        return {"window_docs": window_docs, "clauses": clauses}

    @staticmethod
    def _agg_key(field: str) -> str:
        return "sel__" + field.replace(".", "_")

    @classmethod
    def _selectivity_map(cls, aggregations: dict) -> list[dict]:
        """Turn the per-field terms aggregations into a ranked selectivity map.

        For each candidate field: the dominant value + its share of the flood, and the
        minority values. A field is a DISCRIMINATOR when a value dominates (share >=
        _SELECTIVITY_DOMINANT_MIN) AND a minority exists — the minority is the candidate
        deviation (200 among 404s). A field at share ~1.0 with no minority is FLOOD
        SIGNATURE (a `must_not` target). A field with no dominant value is HIGH-CARDINALITY
        noise. Discriminators rank first, by dominant share desc (a rarer minority stands
        out more); the loud, spread, and empty fields fall below and are never chosen.
        """
        entries: list[dict] = []
        for field in cls._SELECTIVITY_FIELDS:
            agg = aggregations.get(cls._agg_key(field), {})
            buckets = [b for b in agg.get("buckets", []) if b.get("doc_count")]
            if not buckets:
                continue
            # Denominator is the TRUE matched count for this field, NOT the hits `total`:
            # on a TRUNCATED result `total` is the capped lower bound (10000) while the
            # aggregation counts every matching doc, so `doc_count / total` can exceed 100%.
            # Sum this field's buckets + the docs beyond the top-N (`sum_other_doc_count`).
            denom = sum(b["doc_count"] for b in buckets) + agg.get("sum_other_doc_count", 0)
            if not denom:
                continue
            top = buckets[0]
            dominant_share = top["doc_count"] / denom
            minorities = [
                {"value": b["key"], "count": b["doc_count"]} for b in buckets[1:]
            ]
            if dominant_share >= cls._SELECTIVITY_DOMINANT_MIN and minorities:
                role = "discriminator"
            elif dominant_share >= cls._SELECTIVITY_DOMINANT_MIN:
                role = "flood_signature"
            else:
                role = "high_cardinality"
            entries.append({
                "field": field,
                "dominant": top["key"],
                "dominant_share": round(dominant_share, 3),
                "minorities": minorities[:5],
                "role": role,
            })
        rank = {"discriminator": 0, "flood_signature": 1, "high_cardinality": 2}
        entries.sort(key=lambda e: (rank[e["role"]], -e["dominant_share"]))
        return entries

    def _residue_sample(
        self, client, index: str, dsl: dict, field: str, dominant_value,
        per_value: int = 2, cap: int = 10,
    ) -> list[dict]:
        """Sample the residue after removing the flood's DOMINANT value — a couple of
        events per distinct minority value, ordered RAREST-first. The order is a useful
        retrieval heuristic for surfacing small deviations, but the caller must inspect
        the returned samples and rank them by semantic fit to the objective. Best-effort:
        [] on error.
        """
        try:
            body = {
                "size": 0,
                "query": {"bool": {"must": [dsl], "must_not": [{"term": {field: dominant_value}}]}},
                "aggs": {"by_value": {
                    "terms": {"field": field, "size": 12, "order": {"_count": "asc"}},
                    "aggs": {"ex": {"top_hits": {"size": per_value}}},
                }},
            }
            resp = client.post(f"/{index}/_search", json=body)
            if resp.is_error:
                return []
            buckets = resp.json().get("aggregations", {}).get("by_value", {}).get("buckets", [])
            out: list[dict] = []
            for b in buckets:
                for h in b.get("ex", {}).get("hits", {}).get("hits", []):
                    out.append(h)
                    if len(out) >= cap:
                        return out
            return out
        except Exception:
            return []

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
        noop_should = self._has_noop_should(dsl)
        # Capture the caller's clauses BEFORE the outer time-range wrap below rewrites dsl.
        diag_musts, diag_shoulds = self._extract_bool_clauses(dsl)

        # Wrap the caller's DSL in a bool+filter so the time range is always
        # enforced, even when the model embeds it only as the time_range param
        # rather than inside the DSL itself.
        rng = self._range_filter(time_range)
        if rng:
            dsl = {"bool": {"must": dsl, "filter": [rng]}}
        body: dict = {"query": dsl, "size": min(max_results, 100)}
        # rule.groups composition of the matched set. A terms aggregation runs over ALL
        # matching docs (not just the returned slice), so it reveals the true class mix
        # even when hits are truncated — surfaced only for an over-broad result, to point
        # the caller at the behaviour class that is flooding it.
        body["aggs"] = {"rule_groups": {"terms": {"field": "rule.groups", "size": 8}}}
        # Selectivity map: a terms agg per candidate field over ALL matching docs, so a
        # flooded result can reveal which axis the events vary along (the discriminator)
        # vs the homogeneous flood signature. Read only when flooded (below); cheap on the
        # common small result. The rule.groups axis is already covered above.
        for _f in self._SELECTIVITY_FIELDS:
            body["aggs"][self._agg_key(_f)] = {"terms": {"field": _f, "size": 8}}

        c = self._get_client()
        resp = c.post(f"/{index}/_search", json=body)
        if resp.is_error:
            try:
                err = resp.json()
            except Exception:
                err = resp.text[:1000]
            out: dict[str, Any] = {"error": err}
            hint = self._query_error_hint(err)
            if hint:
                out["hint"] = hint
            return out
        data = resp.json()

        hits = data.get("hits", {})
        total = hits.get("total", {})
        if isinstance(total, dict):
            total_value = total.get("value", 0)
            # "gte" means OpenSearch stopped counting at the cap (track_total_hits off):
            # the true total is >= total_value and the returned `events` are an arbitrary
            # slice. Surface this so the caller knows the result is TRUNCATED, not a
            # complete set — otherwise a 1.3M-hit query reads as a normal "10000 hits".
            total_relation = total.get("relation", "eq")
        else:
            total_value, total_relation = total, "eq"
        out: dict[str, Any] = {
            "total": total_value,
            "total_relation": total_relation,
            "truncated": total_relation == "gte",
            "events": hits.get("hits", []),
        }
        if noop_should:
            out["note"] = (
                "Your query has a `should` clause with no `must` and no "
                "`minimum_should_match` — under Elasticsearch defaults this makes "
                "`should` SCORING-ONLY, not a filter: the result above is NOT narrowed "
                "by those terms, only by whatever `must`/`filter` you also supplied "
                "(often just the time range). Either move the discriminator into "
                "`must` (a hard AND), or add `\"minimum_should_match\": 1` to require "
                "at least one `should` clause to match."
            )
        # Per-clause selectivity: how many docs in the window each must/should clause
        # matches on its own. Lets the caller see which discriminator is selective vs a
        # flood, and whether the conjunction (`total` above) is carried by one clause.
        diagnostics = self._clause_diagnostics(index, diag_musts, diag_shoulds, rng)
        if diagnostics:
            out["clause_diagnostics"] = diagnostics

        # Over-broad result: surface WHICH behaviour classes make up the flood, and tell
        # the caller to scope by class. An entity-only query (host/IP with no rule.groups)
        # returns the union of all the entity's classes, so the loudest (usually IDS/network
        # noise against a scanned host) buries the quiet class holding the evidence.
        rg_buckets = data.get("aggregations", {}).get("rule_groups", {}).get("buckets", [])
        rule_groups = [{"group": b["key"], "count": b["doc_count"]} for b in rg_buckets]
        flooded = out["truncated"] or total_value >= self._BROAD_RESULT_THRESHOLD
        if flooded and rule_groups:
            out["rule_groups_breakdown"] = rule_groups
            clause_json = json.dumps([*diag_musts, *diag_shoulds])
            entity_scoped = any(
                f in clause_json
                for f in ("agent.name", "agent.ip", "data.srcip", "data.dstip")
            )
            has_class = "rule.groups" in clause_json
            top = rule_groups[0]["group"]
            if entity_scoped and not has_class:
                flood_note = (
                    "This query is scoped to an entity with no behaviour-class filter, so it "
                    "returns the UNION of all of that entity's classes and the dominant one "
                    f"(`{top}`) is burying your evidence and overflowing the cap. Add a "
                    "`rule.groups` constraint matching your objective (e.g. web, "
                    "authentication, audit, syscheck), or `must_not` the dominant class — see "
                    "`rule_groups_breakdown` for the class mix."
                )
            else:
                flood_note = (
                    "Over-broad result: its `rule.groups` composition is in "
                    f"`rule_groups_breakdown`, and the dominant class (`{top}`) is burying the "
                    "rest. Scope to the class your objective needs, or `must_not` the dominant one."
                )
            out["note"] = (out["note"] + " " + flood_note) if out.get("note") else flood_note

        # Selectivity map + minority sample: even a class-scoped query can stay flooded by
        # the scan's own events (rule.groups:web + /wp-content/* is still thousands of
        # probes). Name the axis the events actually vary along and hand back a sample of
        # the deviating (minority) events, so payload-bearing residue is visible even if
        # the note is ignored. rule.id is just one candidate axis here, not the assumed
        # answer.
        if flooded:
            sel_map = self._selectivity_map(data.get("aggregations", {}))
            if sel_map:
                out["selectivity_map"] = sel_map
                discriminator = next((e for e in sel_map if e["role"] == "discriminator"), None)
                if discriminator and discriminator["minorities"]:
                    field = discriminator["field"]
                    dominant = discriminator["dominant"]
                    # Retain the historical narrowed-query suggestion for compatibility, but
                    # make the primary method semantic: read the returned residue sample first.
                    rarest = discriminator["minorities"][-1]["value"]
                    minority_values = [m["value"] for m in discriminator["minorities"]]
                    sample = self._residue_sample(c, index, dsl, field, dominant)
                    if sample:
                        out["minority_sample"] = sample
                    pct = round(discriminator["dominant_share"] * 100)
                    shown = ", ".join(str(v) for v in minority_values[:6])
                    sel_note = (
                        f"Still flood-dominated. The events differ along `{field}` (dominant "
                        f"`{dominant}` {pct}%; minority values: {shown}). `minority_sample` is the "
                        f"residue after removing `{dominant}` and contains raw events to inspect. "
                        f"Read and decode the sample first, then rank minority candidates by semantic "
                        f"fit to the task objective rather than rarity alone. Query `{field}={rarest}` "
                        f"or `must_not {field}={dominant}` only if the sample is insufficient or you "
                        f"need to enumerate scope."
                    )
                    out["note"] = (out["note"] + " " + sel_note) if out.get("note") else sel_note

        # Zero-hit result: a wrong field NAME returns 0 exactly like a genuine absence.
        # Flag any queried field that is not in the index mapping so the caller corrects
        # the name instead of recording a false negative. Only on a true zero result.
        if total_value == 0:
            warnings = self._absent_field_warnings(
                index, self._query_leaf_fields({"bool": {"must": diag_musts, "should": diag_shoulds}})
            )
            if warnings:
                out["field_warnings"] = warnings
                note = self._field_warning_note(warnings)
                out["note"] = (out["note"] + " " + note) if out.get("note") else note
        return out

    def _range_filter(self, time_range: dict | None) -> dict | None:
        if not time_range:
            return None
        return {"range": {"@timestamp": {
            "gte": time_range.get("from", "now-24h"),
            "lte": time_range.get("to", "now"),
        }}}

    # rare_terms upper bound on "how many docs a term may appear in" to still count as
    # rare. OpenSearch defaults to 1 (true singletons); meaningful SOC deviations often
    # fire a handful of times (a webshell invoked per command, a 2-record service-stop), so 1 is too
    # strict. Kept modest because rare_terms cost/precision degrade as this grows.
    _RARE_MAX_DOC_COUNT_DEFAULT = 10

    def profile_field(
        self,
        field: str,
        index_pattern: str | None = None,
        time_range: dict | None = None,
        top_n: int = 10,
        query: dict | str | None = None,
        rare: bool = False,
        max_doc_count: int | None = None,
    ) -> dict[str, Any]:
        """Profile a field's values (a terms aggregation).

        By default returns the MOST common values (top-N, descending). With
        `rare=True` it instead returns the LEAST common values via a `rare_terms`
        aggregation — the long tail a top-N view structurally hides. In noisy
        telemetry the high-volume head is the environment's background; a
        low-frequency value (a rule that fired a handful of times, a single
        anomalous user/path/destination) is where an intrusion shows up. `rare`
        surfaces those directly without first having to guess a narrow window.

        Wazuh string fields are mapped as `keyword`, so they aggregate directly —
        there is no `.keyword` subfield to fall back to.
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

        # max_doc_count is clamped to OpenSearch's supported rare_terms range [1, 100];
        # an unset (None) value uses the default, an out-of-range value is clamped.
        raw_cap = self._RARE_MAX_DOC_COUNT_DEFAULT if max_doc_count is None else int(max_doc_count)
        rare_cap = max(1, min(raw_cap, 100))

        def _run(agg_field: str) -> dict:
            if rare:
                aggs = {"rare": {"rare_terms": {"field": agg_field, "max_doc_count": rare_cap}}}
            else:
                aggs = {"top": {"terms": {"field": agg_field, "size": min(top_n, 100)}}}
            body: dict = {
                "size": 0,
                "track_total_hits": True,
                "aggs": aggs,
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

        aggs = data.get("aggregations", {})
        matched = data.get("hits", {}).get("total", {}).get("value", 0)

        # An unmapped keyword field aggregates to zero buckets (no error) — the same
        # silent-zero as search. When nothing matched, flag the profiled field or any
        # query field that is absent from the index mapping.
        def _field_warnings() -> list[dict]:
            if matched:
                return []
            fields = {used_field} | (
                self._query_leaf_fields(query) if isinstance(query, dict) else set()
            )
            return self._absent_field_warnings(index, fields)

        if rare:
            # rare_terms returns ascending by count (rarest first); slice to top_n so a
            # high-cardinality tail does not flood the result.
            buckets = aggs.get("rare", {}).get("buckets", [])[: min(top_n, 100)]
            out = {
                "field": used_field,
                "matched_docs": matched,
                "rare_values": [
                    {"value": b["key"], "count": b["doc_count"]} for b in buckets
                ],
                "max_doc_count": rare_cap,
            }
        else:
            agg_out = aggs.get("top", {})
            out = {
                "field": used_field,
                "matched_docs": matched,
                "top_values": [
                    {"value": b["key"], "count": b["doc_count"]} for b in agg_out.get("buckets", [])
                ],
                "other_count": agg_out.get("sum_other_doc_count", 0),
            }
        warnings = _field_warnings()
        if warnings:
            out["field_warnings"] = warnings
            out["note"] = self._field_warning_note(warnings)
        return out

    def search_keyword(
        self,
        query: str,
        index_pattern: str | None = None,
        time_range: dict | None = None,
        max_results: int = 20,
    ) -> dict[str, Any]:
        """Find events matching the supplied keywords across common Wazuh fields.

        Terms are AND-ed by default: every term must appear in a document, so adding
        more distinctive terms *narrows* the result set (the intuitive behavior). If an
        all-terms match returns no events, the search automatically retries with OR
        semantics (any term) and flags the result as a broadened fallback — so a query
        listing alternative terms still casts a wide net rather than returning nothing.
        An all-terms match that is still very large is flagged as too broad.
        """

        index = index_pattern or self._default_index

        query = " ".join(t for t in query.split() if t)
        # Strip ISO timestamps the model wrongly placed in the keyword terms — they
        # match nothing and force the OR-fallback to return the whole index.
        query, dropped_ts = self._strip_temporal_tokens(query)
        if not query:
            note = {"total": 0, "events": []}
            if dropped_ts:
                note["note"] = (
                    "Query contained only timestamp token(s); timestamps belong in "
                    "`time_range`, not the keyword query. Re-run with real keyword terms "
                    "and put the window in `time_range`."
                )
            return note

        def _run(operator: str) -> dict[str, Any]:
            query_body: dict[str, Any] = {
                "bool": {
                    "should": [
                        {
                            "simple_query_string": {
                                "query": query,
                                "fields": self._SEARCH_KEYWORD_FIELDS,
                                "default_operator": operator,
                                "lenient": True,
                            }
                        }
                    ],
                    "minimum_should_match": 1,
                }
            }
            rng = self._range_filter(time_range)
            if rng:
                query_body = {"bool": {"must": [query_body], "filter": [rng]}}

            body = {
                "query": query_body,
                "size": min(max_results, 100),
                "track_total_hits": True,
            }
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

        def _annotate(out: dict) -> dict:
            if "error" in out:
                hint = self._query_error_hint(out["error"])
                if hint:
                    out["hint"] = hint
            if dropped_ts:
                out["dropped_temporal_terms"] = dropped_ts
            return out

        result = _run("and")
        if "error" in result:
            return _annotate(result)

        if not result["events"]:
            # No document contained all terms — broaden to any-term (the wide net),
            # but label it so the caller knows the match is looser.
            fallback = _run("or")
            if "error" not in fallback and fallback["events"]:
                fallback["broadened"] = True
                fallback["note"] = (
                    "No events matched all terms; broadened to ANY-term match. "
                    "Results are relevance-ranked — add a distinctive term or narrow "
                    "the time range to focus."
                )
                return _annotate(fallback)
            return _annotate(result)

        if result["total"] > self._BROAD_RESULT_THRESHOLD:
            result["too_broad"] = True
            result["note"] = (
                f"Matched {result['total']} events even with all terms required — "
                "still too broad to be decisive. Add a more distinctive term or narrow "
                "the time range before relying on these results."
            )
        return _annotate(result)

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

    @staticmethod
    def _parse_ts(value: Any) -> "datetime | None":
        """Best-effort parse of an ISO 8601 string or epoch number into a datetime.

        Returns None when the value cannot be interpreted; callers fall back to a
        default interval rather than failing the whole request.
        """
        if value is None:
            return None
        if isinstance(value, (int, float)):
            # Heuristic: epoch milliseconds vs seconds.
            secs = value / 1000 if value > 1e12 else value
            try:
                return datetime.fromtimestamp(secs, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None

    def _resolve_interval(
        self, start_time: Any, end_time: Any, interval: str | None, bins: int
    ) -> str:
        """Choose an OpenSearch fixed_interval string.

        If the caller supplied an explicit `interval` (e.g. '5m', '1h'), honor it.
        Otherwise divide the start..end span into `bins` equal buckets and express
        the bucket width in whole seconds. Falls back to '1h' when the span cannot
        be computed (unparseable timestamps).
        """
        if interval:
            return interval
        bins = max(1, min(bins, 1000))
        start = self._parse_ts(start_time)
        end = self._parse_ts(end_time)
        if start and end and end > start:
            span_secs = (end - start).total_seconds()
            width = max(1, int(span_secs // bins))
            return f"{width}s"
        return "1h"

    # --- Activity-regime detection (Otsu on a log scale) ----------------------
    # A SOC volume histogram is bimodal: a quiet "baseline" floor and a raised
    # "active" mass. A point-outlier test (median/MAD z-score) breaks when the
    # active period is a sustained plateau rather than a narrow spike, because the
    # median then sits INSIDE the elevated mass and reads the plateau as normal.
    # Otsu's threshold instead splits the bins into the two clusters by maximizing
    # between-class variance, making no assumption about how wide the active region
    # is — a 1-bin spike and a 10-bin plateau are both bounded correctly.
    #
    # The split is computed on log1p(count), not raw counts. Event volume is
    # heavy-tailed and spans orders of magnitude, and "active" is a MULTIPLICATIVE
    # idea (N times the baseline), not an additive one. Raw-count Otsu is dominated
    # by the variance of the largest bins, so on a steep ramp it draws the line too
    # high and lumps a genuinely-active ramp bin into 'quiet' (observed live: a
    # 118k-event bin over a ~70-event floor classified as baseline because isolating
    # the tight 266k–318k top cluster scored higher). The log transform puts the
    # break between the baseline and the surge, where it belongs.
    _OTSU_MIN_BINS = 3
    # Separability floor (eta^2 = between-class / total variance, in [0,1]). Below
    # this the split is not clean — high within-class spread — and we report no
    # regime rather than slicing noise.
    _OTSU_MIN_ETA = 0.5
    # Contrast floor: the active class must stand at least this many times above the
    # quiet one (a ratio, measured as a difference of log-means = ratio of geometric
    # means). eta only measures whether two clusters are tight and separable, not
    # whether one is meaningfully ELEVATED — a flat histogram (52 vs 47) is cleanly
    # bimodal but not an activity regime. This rejects it.
    _OTSU_MIN_CONTRAST = 3.0
    # When the active region spans more than this many hours, the profile did not
    # localize anything: the activity overflows the window edges and a raw search
    # over it would hit the result ceiling. The result is flagged `saturated` and the
    # navigation note tells the agent to narrow / raise resolution rather than "query
    # the onset/cessation edges" (which, 48h apart, is not a drillable window). This
    # is the temporal analogue of search's TOO_BROAD flag.
    _VOLUME_SATURATION_HOURS = 6.0

    @classmethod
    def _otsu_active_threshold(cls, counts: list[int]) -> float | None:
        """Otsu cutoff (on log1p(count)) separating 'quiet' bins from an 'active'
        regime.

        Returns the raw count at/above which a bin is "active", or None when the
        distribution is not meaningfully bimodal (flat, or a single level — no
        distinct active period). active = count >= returned threshold.
        """
        n = len(counts)
        if n < cls._OTSU_MIN_BINS:
            return None
        logs = [math.log1p(c) for c in counts]
        distinct = sorted(set(logs))
        if len(distinct) < 2:
            return None  # perfectly flat — no regime to find
        mean_all = sum(logs) / n
        variance_all = sum((x - mean_all) ** 2 for x in logs) / n
        if variance_all <= 0:
            return None
        best_cut: float | None = None
        best_variance = -1.0
        best_mean_quiet = best_mean_active = 0.0
        # Candidate cutoffs are the distinct log values (excluding the minimum, which
        # would leave the quiet class empty). For each, score the between-class
        # variance of quiet=<t / active=>=t.
        for t in distinct[1:]:
            quiet = [x for x in logs if x < t]
            active = [x for x in logs if x >= t]
            if not quiet or not active:
                continue
            w_q, w_a = len(quiet) / n, len(active) / n
            m_q, m_a = sum(quiet) / len(quiet), sum(active) / len(active)
            variance = w_q * w_a * (m_a - m_q) ** 2
            if variance > best_variance:
                best_variance, best_cut, best_mean_quiet, best_mean_active = variance, t, m_q, m_a
        if best_cut is None:
            return None
        # Unimodal guard: require a clean two-cluster separation...
        if best_variance / variance_all < cls._OTSU_MIN_ETA:
            return None
        # ...and a meaningful elevation of the active class over the quiet one. In log
        # space the mean difference is the log of the geometric-mean ratio.
        if best_mean_active - best_mean_quiet < math.log(cls._OTSU_MIN_CONTRAST):
            return None
        # Map the log cutoff back to a raw count: the smallest count that is active.
        return float(min(c for c, x in zip(counts, logs) if x >= best_cut))

    # A run of active bins is one burst; a run of MORE than this many consecutive
    # sub-threshold bins ends it. Small (1) so a one-bin dip does not split a plateau,
    # but any real quiet stretch separates distinct bursts (e.g. a scan on one day and a
    # login flood the next). A single-regime profile has one burst; a wide/vicinity
    # window usually holds several, which the single onset/cessation/peak view hides.
    _BURST_MAX_GAP_BINS = 1

    @classmethod
    def _detect_bursts(cls, bins_out: list[dict], threshold: float | None) -> list[dict]:
        """Segment the histogram into distinct activity bursts.

        Groups contiguous runs of bins at/above the active `threshold`, tolerating gaps
        of up to `_BURST_MAX_GAP_BINS` sub-threshold bins inside a run. Each burst is
        {start, end, peak_count, total}. Returns the top bursts by total volume so a
        wide window's real structure (several separated bursts) is visible instead of one
        collapsed span. Empty when no regime was found. Fail-open: never raises.
        """
        if threshold is None or not bins_out:
            return []
        try:
            runs: list[list[dict]] = []
            current: list[dict] = []
            gap = 0
            for b in bins_out:
                if b.get("count", 0) >= threshold:
                    current.append(b)
                    gap = 0
                elif current:
                    gap += 1
                    if gap > cls._BURST_MAX_GAP_BINS:
                        runs.append(current)
                        current, gap = [], 0
            if current:
                runs.append(current)
            bursts = [
                {
                    "start": r[0]["time"],
                    "end": r[-1]["time"],
                    "peak_count": max(b["count"] for b in r),
                    "total": sum(b["count"] for b in r),
                }
                for r in runs
            ]
            bursts.sort(key=lambda x: -x["total"])
            return bursts[:8]
        except Exception:
            return []

    def get_event_volume(
        self,
        start_time: Any,
        end_time: Any,
        query: dict | str | None = None,
        interval: str | None = None,
        bins: int = 24,
        index_pattern: str | None = None,
    ) -> dict[str, Any]:
        """Return a time histogram of matching event counts (a date_histogram).

        Buckets the events matching `query` across the @timestamp range
        [start_time, end_time] into fixed-width bins. Empty bins are returned with
        count 0 (via extended_bounds) so the caller can spot temporal gaps and the
        onset/cessation of activity directly. Use to confirm brute-force bursts,
        beaconing cadence, and quiet gaps without paging raw events.
        """
        index = index_pattern or self._default_index
        time_range = {"from": start_time, "to": end_time}

        must: list[dict] = []
        if query:
            if isinstance(query, dict):
                clause, time_range, _ = self._unwrap_request(query, time_range, 0)
                must.append(clause)
            else:
                must.append({"simple_query_string": {
                    "query": query,
                    "fields": self._SEARCH_KEYWORD_FIELDS,
                    "lenient": True,
                }})
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)

        fixed_interval = self._resolve_interval(
            time_range.get("from"), time_range.get("to"), interval, bins
        )
        hist: dict[str, Any] = {
            "field": "@timestamp",
            "fixed_interval": fixed_interval,
            "min_doc_count": 0,
        }
        # extended_bounds forces zero-count buckets across the whole window so gaps
        # are visible. Only meaningful when both edges are known.
        if rng:
            hist["extended_bounds"] = {
                "min": rng["range"]["@timestamp"]["gte"],
                "max": rng["range"]["@timestamp"]["lte"],
            }
        body: dict = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {"volume": {"date_histogram": hist}},
        }
        if must:
            body["query"] = {"bool": {"must": must}}

        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()

        buckets = data.get("aggregations", {}).get("volume", {}).get("buckets", [])
        bins_out = [
            {"time": b.get("key_as_string", b.get("key")), "count": b["doc_count"]}
            for b in buckets
        ]
        counts = [b["count"] for b in bins_out]
        total = data.get("hits", {}).get("total", {})
        total_value = total.get("value", 0) if isinstance(total, dict) else total

        # Pre-digest the temporal shape so the caller doesn't have to parse every
        # bucket. Otsu's threshold splits the bins into a quiet baseline and an
        # ACTIVE regime; the first/last active bin are the activity onset and
        # cessation. This bounds the active block whether it is a narrow spike or a
        # sustained multi-hour plateau (a plateau defeats a peak/outlier test, whose
        # baseline gets contaminated by the elevated mass). The agent's to-do list
        # is then: the onset window (initial access), the active windows, and the
        # cessation edge (where follow-on / "did it actually stop" hides) — not the
        # densest bucket of a known scan.
        peak_idx = max(range(len(bins_out)), key=lambda i: bins_out[i]["count"]) if bins_out else -1
        peak_bucket = bins_out[peak_idx] if peak_idx >= 0 else None
        threshold = self._otsu_active_threshold(counts)
        active = [b for b in bins_out if b["count"] >= threshold] if threshold is not None else []
        onset = active[0] if active else None
        cessation = active[-1] if active else None
        # The above-baseline windows flanking the densest bin, split for downstream
        # model inference: the ramp-up side (pre) and the wind-down side (post). The
        # spike's own bin is excluded from both. A sustained plateau populates both
        # lists; a clean single-bin spike leaves both empty (the regime is one bin).
        # The post side is where follow-on (exploitation/lateral movement/privesc)
        # hides once the burst quiets; the pre side is the lead-in toward the peak.
        if threshold is not None and peak_idx >= 0:
            pre_spike = [b for b in bins_out[:peak_idx] if b["count"] >= threshold]
            post_spike = [b for b in bins_out[peak_idx + 1:] if b["count"] >= threshold]
        else:
            pre_spike, post_spike = [], []
        # Saturation: the active region spans most of the window, so the profile did
        # not localize anything (observed live: a 48h window where every hour cleared
        # the baseline — onset is the first bin, cessation the last). Measured by the
        # absolute onset→cessation duration, which separates a deliberate tight zoom
        # (minutes) from an un-narrowed broad sweep (many hours) regardless of bin
        # count or width.
        saturated = False
        span_hours = 0.0
        if onset is not None and cessation is not None:
            o_ts, c_ts = self._parse_ts(onset["time"]), self._parse_ts(cessation["time"])
            if o_ts and c_ts:
                span_hours = (c_ts - o_ts).total_seconds() / 3600
                saturated = span_hours > self._VOLUME_SATURATION_HOURS
        # Distinct bursts in the window — a wide/vicinity window usually holds several,
        # which the single onset/cessation/peak view collapses into one span.
        bursts = self._detect_bursts(bins_out, threshold)
        result: dict[str, Any] = {
            "interval": fixed_interval,
            "total": total_value,
            "bins": bins_out,
            "peak_count": max(counts) if counts else 0,
            "peak_bucket": peak_bucket,
            "active_threshold": threshold,
            "onset": onset,
            "cessation": cessation,
            "active_bins": active[:30],
            "pre_spike_active_bins": pre_spike[:20],
            "post_spike_active_bins": post_spike[:20],
            "empty_bins": sum(1 for c in counts if c == 0),
            "saturated": saturated,
            "bursts": bursts,
        }
        # Assemble the navigation note from the parts that apply: an overall shape
        # line (saturated / plateau / post-peak tail) plus a pre-spike segment whenever
        # activity ramped up before the densest bin. Each segment points the agent at a
        # set of unqueried windows; an empty side simply contributes nothing.
        notes: list[str] = []
        if len(bursts) > 1:
            # The window holds SEVERAL distinct bursts separated by quiet gaps — the
            # single onset/cessation/peak collapses them, so list them and make the agent
            # pick the one that fits its objective (not the largest or the earliest).
            shown = ", ".join(
                f"{b['start']}→{b['end']} ({b['total']} ev)" for b in bursts[:6]
            )
            more = f" (+{len(bursts) - 6} more)" if len(bursts) > 6 else ""
            notes.append(
                f"This window contains {len(bursts)} DISTINCT activity bursts separated by "
                f"quiet gaps: {shown}{more}. This is not one event — do NOT treat the whole "
                f"span as a single burst or shrink toward the densest bin blindly. Choose the "
                f"burst that matches your objective's phase, class, and time (the loudest is "
                f"often background noise — a scan/flood — not your target), then re-profile "
                f"and drill THAT sub-window."
            )
        elif saturated:
            # The plateau guidance ("query the onset/cessation edges") is meaningless
            # when the edges are many hours apart — tell the agent to re-scope instead.
            peak_time = (peak_bucket or {}).get("time", onset["time"])
            notes.append(
                f"Active region spans {span_hours:.0f}h ({onset['time']} → {cessation['time']}) — "
                f"the window is far too WIDE; the activity is not localized and a raw search over it "
                f"will hit the result ceiling. FIX BY SHRINKING THE TIME WINDOW: re-run with a shorter "
                f"start_time→end_time span (e.g. a 1–2h slice around the densest activity near "
                f"{peak_time}), then keep halving the span until the active region no longer fills it. "
                f"Do NOT change the bin `interval` instead — a coarser interval only hides more, and a "
                f"finer one over the same wide span stays saturated; it is the WINDOW that is too wide, "
                f"not the resolution. Do NOT conclude from this shape."
            )
        elif onset is not None and len(active) > 2:
            # Sustained / plateau: the histogram alone won't tell you what happened
            # across a multi-bin active block — point the agent at its edges.
            notes.append(
                f"Sustained elevated activity ({len(active)} bins above baseline "
                f"~{threshold:g}/bin) from ONSET {onset['time']} to CESSATION "
                f"{cessation['time']}. This is a plateau, not a point spike — query the "
                f"onset window for initial access and the cessation edge (and the bin "
                f"after) for follow-on / whether it actually stopped. NOTE these edges are "
                f"only located to the {fixed_interval} bin width: the true onset/cessation "
                f"can sit anywhere INSIDE the edge bin, so re-profile a tight window around "
                f"the edge at a finer interval to pin the exact transition before you drill "
                f"it. Do NOT conclude from the histogram alone."
            )
        elif post_spike:
            times = ", ".join(str(b["time"]) for b in post_spike[:8])
            more = f" (+{len(post_spike) - 8} more)" if len(post_spike) > 8 else ""
            notes.append(
                f"Activity continues AFTER the main peak ({peak_bucket['time']}) at: {times}{more}. "
                "A scan/flood is noise to step past — query these post-spike windows for what "
                "the source did next (exploitation/lateral movement/privesc hide in the tail). "
                "Do NOT zoom into the densest bucket of a known scan."
            )
        if pre_spike and not saturated and len(bursts) <= 1:
            times = ", ".join(str(b["time"]) for b in pre_spike[:8])
            more = f" (+{len(pre_spike) - 8} more)" if len(pre_spike) > 8 else ""
            notes.append(
                f"Activity ramps up BEFORE the main peak ({peak_bucket['time']}) at: {times}{more}. "
                "Query these pre-spike windows for the initial access / staging that led to the "
                "burst — the onset, not the peak, is where the intrusion starts."
            )
        if notes:
            result["note"] = " ".join(notes)
        return result

    # Curated neighbor dimensions for correlate_entity. One terms aggregation is run
    # per field (minus the pinned entity field) within the events matching the entity,
    # so a single call returns the entity's whole grounded neighborhood.
    _CORRELATE_DEFAULT_FIELDS = [
        "agent.name",
        "data.srcip",
        "data.dstip",
        "data.srcuser",
        "data.dstuser",
        "data.user",
        "data.audit.command",
        "data.win.eventdata.image",
        "syscheck.path",
        "rule.groups",
        "rule.id",
    ]

    # When the pinned entity is an IP, also correlate it in the opposite network role
    # so "is this C2/callback destination also the initial-access source?" is answered
    # in one call.
    _IP_ROLE_OPPOSITE = {"data.srcip": "data.dstip", "data.dstip": "data.srcip"}

    # An entity tied to more events than this is too connected to discriminate; the
    # result is flagged so the caller narrows the window rather than over-pivoting.
    _CORRELATE_NOISY_THRESHOLD = 10000

    def _correlate_one(
        self,
        field: str,
        value: str,
        time_range: dict | None,
        link_fields: list[str],
        top_n: int,
        samples: int,
        index: str,
        min_cooccurrence: int,
        match_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Profile every neighbor field within the events matching the pinned entity.

        By default the entity is pinned as `field == value`. When `match_fields` is
        given, the value is matched in ANY of those fields (so an entity is found
        regardless of which role-field actually holds it — e.g. a user that appears
        as `data.dstuser` rather than `data.srcuser`); all pinned fields are then
        excluded from neighbor profiling.

        Returns the entity's event total, first/last seen, and per-neighbor buckets
        each carrying a count, time bounds, and a few sample event _ids (grounding).
        """
        pin_fields = match_fields or [field]
        if len(pin_fields) == 1:
            pin: dict = {"term": {pin_fields[0]: value}}
        else:
            pin = {"bool": {
                "should": [{"term": {f: value}} for f in pin_fields],
                "minimum_should_match": 1,
            }}
        must: list[dict] = [pin]
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)

        excluded = set(pin_fields)
        neighbor_fields = [f for f in link_fields if f not in excluded]
        aggs: dict[str, Any] = {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
        }
        field_map: dict[str, str] = {}
        for i, nf in enumerate(neighbor_fields):
            key = f"nf{i}"  # avoid dotted agg names
            field_map[key] = nf
            aggs[key] = {
                "terms": {"field": nf, "size": min(top_n, 50)},
                "aggs": {
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}},
                    "samples": {
                        "top_hits": {
                            "size": min(samples, 5),
                            "_source": False,
                            "sort": [{"@timestamp": {"order": "asc"}}],
                        }
                    },
                },
            }

        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"must": must}},
            "aggs": aggs,
        }
        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()

        aggregations = data.get("aggregations", {})
        total = data.get("hits", {}).get("total", {})
        total_value = total.get("value", 0) if isinstance(total, dict) else total

        neighbors: dict[str, list] = {}
        for key, nf in field_map.items():
            entries = []
            for b in aggregations.get(key, {}).get("buckets", []):
                if b["doc_count"] < min_cooccurrence:
                    continue
                ids = [
                    h["_id"]
                    for h in b.get("samples", {}).get("hits", {}).get("hits", [])
                ]
                entries.append({
                    "value": b["key"],
                    "count": b["doc_count"],
                    "first": b.get("first", {}).get("value_as_string"),
                    "last": b.get("last", {}).get("value_as_string"),
                    "event_ids": ids,
                })
            if entries:
                neighbors[nf] = entries

        return {
            "total_events": total_value,
            "first_seen": aggregations.get("first", {}).get("value_as_string"),
            "last_seen": aggregations.get("last", {}).get("value_as_string"),
            "neighbors": neighbors,
        }

    def correlate_entity(
        self,
        field: str,
        value: str,
        start_time: Any = None,
        end_time: Any = None,
        link_fields: list[str] | None = None,
        top_n: int = 10,
        min_cooccurrence: int = 1,
        index_pattern: str | None = None,
        match_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return the grounded correlation neighborhood of a confirmed entity.

        Pins `field == value` and, in a single aggregation, profiles every other
        curated dimension (users, hosts, IPs in both roles, processes, files, rule
        families) that co-occurs with it — each neighbor carrying a count, time
        bounds, and sample event _ids so the link is independently citable. For IP
        entities the same value is also correlated in the opposite network role
        (`cross_role`), surfacing whether a callback destination is also a login
        source. Use this as the FIRST pivot after confirming any entity, before
        issuing manual per-field queries.
        """
        index = index_pattern or self._default_index
        time_range = (
            {"from": start_time, "to": end_time}
            if (start_time or end_time)
            else None
        )
        fields = link_fields or self._CORRELATE_DEFAULT_FIELDS
        samples = 3

        primary = self._correlate_one(
            field, value, time_range, fields, top_n, samples, index, min_cooccurrence,
            match_fields=match_fields,
        )
        if "error" in primary:
            return primary

        result: dict[str, Any] = {
            "entity": {"field": field, "value": value},
            "window": time_range,
            **primary,
        }
        if match_fields:
            result["entity"]["match_fields"] = match_fields
        if primary.get("total_events", 0) > self._CORRELATE_NOISY_THRESHOLD:
            result["too_connected"] = True
            result["note"] = (
                f"Entity matched {primary['total_events']} events — too connected to "
                "discriminate. Narrow the time window before relying on these links."
            )

        # Single-field mode: for an IP, also correlate the opposite network role.
        # When match_fields spans both roles already, the cross-role view is redundant.
        opposite = None if match_fields else self._IP_ROLE_OPPOSITE.get(field)
        if opposite:
            cr = self._correlate_one(
                opposite, value, time_range, fields, top_n, samples, index, min_cooccurrence
            )
            if "error" not in cr:
                result["cross_role"] = {"field": opposite, **cr}

        return result

    def correlate_techniques(
        self,
        start_time: Any = None,
        end_time: Any = None,
        query: dict | str | None = None,
        index_pattern: str | None = None,
        top_n: int = 30,
    ) -> dict[str, Any]:
        """Aggregate MITRE ATT&CK techniques observed in the window (kill-chain view).

        Groups events by `rule.mitre.id`, attaching the technique name and tactic(s)
        and sample event _ids, plus a tactic histogram. This raises correlation from
        the entity level to the adversary-behavior level: the caller can order the
        techniques along the kill chain and spot phases with no evidence. Optionally
        scope with a query (e.g. a host) — recommended, so the techniques describe one
        incident rather than the whole environment.
        """
        index = index_pattern or self._default_index
        time_range = (
            {"from": start_time, "to": end_time} if (start_time or end_time) else None
        )
        must: list[dict] = []
        if query:
            if isinstance(query, dict):
                clause, time_range, _ = self._unwrap_request(query, time_range, 0)
                must.append(clause)
            else:
                must.append({"simple_query_string": {
                    "query": query, "fields": self._SEARCH_KEYWORD_FIELDS, "lenient": True,
                }})
        rng = self._range_filter(time_range)
        if rng:
            must.append(rng)
        # Only events Wazuh has tagged with an ATT&CK technique.
        must.append({"exists": {"field": "rule.mitre.id"}})

        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"must": must}},
            "aggs": {
                "by_technique": {
                    "terms": {"field": "rule.mitre.id", "size": min(top_n, 100)},
                    "aggs": {
                        "technique": {"terms": {"field": "rule.mitre.technique", "size": 1}},
                        "tactic": {"terms": {"field": "rule.mitre.tactic", "size": 3}},
                        "first": {"min": {"field": "@timestamp"}},
                        "samples": {"top_hits": {
                            "size": 2, "_source": False,
                            "sort": [{"@timestamp": {"order": "asc"}}],
                        }},
                    },
                },
                "by_tactic": {"terms": {"field": "rule.mitre.tactic", "size": 20}},
            },
        }
        with self._client() as c:
            resp = c.post(f"/{index}/_search", json=body)
            if resp.is_error:
                try:
                    return {"error": resp.json()}
                except Exception:
                    return {"error": resp.text[:1000]}
            data = resp.json()

        aggs = data.get("aggregations", {})
        total = data.get("hits", {}).get("total", {})
        total_value = total.get("value", 0) if isinstance(total, dict) else total

        techniques = []
        for b in aggs.get("by_technique", {}).get("buckets", []):
            tech = [x["key"] for x in b.get("technique", {}).get("buckets", [])]
            tacs = [x["key"] for x in b.get("tactic", {}).get("buckets", [])]
            ids = [h["_id"] for h in b.get("samples", {}).get("hits", {}).get("hits", [])]
            techniques.append({
                "id": b["key"],
                "technique": tech[0] if tech else None,
                "tactics": tacs,
                "count": b["doc_count"],
                "first": b.get("first", {}).get("value_as_string"),
                "event_ids": ids,
            })
        tactics = [
            {"tactic": b["key"], "count": b["doc_count"]}
            for b in aggs.get("by_tactic", {}).get("buckets", [])
        ]
        return {
            "window": time_range,
            "total_events": total_value,
            "techniques": techniques,
            "tactics": tactics,
        }

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
