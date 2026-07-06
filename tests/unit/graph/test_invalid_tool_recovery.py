from __future__ import annotations

import os
import sys
import types
import unittest
from importlib.util import module_from_spec, spec_from_file_location

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)

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
    return None


query_memo.extract_hit_count = _extract_hit_count
sys.modules.setdefault("agent", agent_pkg)
sys.modules.setdefault("agent.runtime", runtime_pkg)
sys.modules.setdefault("agent.runtime.graph", graph_pkg)
sys.modules.setdefault("agent.runtime.analysis", analysis_pkg)
sys.modules.setdefault("agent.runtime.analysis.query_memo", query_memo)

observation_path = os.path.join(project_root, "agent", "runtime", "graph", "observation.py")
spec = spec_from_file_location("agent.runtime.graph.observation", observation_path)
observation = module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(observation)
build_observation = observation.build_observation


class InvalidToolRecoveryTest(unittest.TestCase):
    def test_invalid_siem_time_window_preserves_recovery_window(self):
        raw = (
            "Error: Invalid SIEM time range: 2026-06-28T00:00:00Z to "
            "2026-06-29T00:00:00Z. The claimed task specifies "
            "2022-01-18T12:17:29Z to 2022-01-19T12:21:57Z. Use the task's "
            "absolute incident window unless the task explicitly provides a different one."
        )

        obs = build_observation([{"name": "search", "raw": raw}], objective="check scan tail")

        self.assertIn("INVALID_TIME_WINDOW", obs["signals"])
        self.assertNotIn("ORIENTATION_ONLY", obs["signals"])
        self.assertEqual(obs["evidence_queries"], 0)
        self.assertEqual(obs["error_recoveries"][0]["requested_window"], {
            "from": "2026-06-28T00:00:00Z",
            "to": "2026-06-29T00:00:00Z",
        })
        self.assertEqual(obs["error_recoveries"][0]["required_window"], {
            "from": "2022-01-18T12:17:29Z",
            "to": "2022-01-19T12:21:57Z",
        })
        self.assertIn("claimed task's absolute time window", " ".join(obs["recommended_moves"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
