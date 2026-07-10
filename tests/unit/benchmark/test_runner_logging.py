from __future__ import annotations

import json
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from benchmark.pipeline import runner
from benchmark.scoring import ScenarioSpec


class _Entry:
    id = "recon"
    anchor_event_id = None


class _Spec:
    entry_points = [_Entry()]


class _Run:
    def __init__(self, id="run-1", agent_name="investigation", status="completed", result="report"):
        self.id = id
        self.agent_name = agent_name
        self.status = status
        self.result = result
        self.verdict = {"classification": "tp"}
        self.metadata = {}

    def refresh_from_db(self):
        return None

    def save(self, **_kwargs):
        return None


class _QuerySet(list):
    def first(self):
        return self[0] if self else None

    def order_by(self, *_args):
        return self


class _AgentRunObjects:
    session = _Run(id="session-1", agent_name="orchestrator", result="session answer")
    child = _Run(id="run-1", agent_name="investigation", result="report")

    def filter(self, **kwargs):
        if kwargs.get("id") == "session-1":
            return _QuerySet([self.session])
        if kwargs.get("metadata__session_id") == "session-1":
            return _QuerySet([self.child])
        return _QuerySet([])

    def exclude(self, **_kwargs):
        return _QuerySet([self.child])


class _AgentRun:
    STATUS_COMPLETED = "completed"
    STATUS_INCOMPLETE_BUDGET = "incomplete_budget"
    STATUS_CANCELLED = "cancelled"
    STATUS_BLOCKED = "blocked"
    STATUS_FAILED = "failed"
    objects = _AgentRunObjects()


class _Capture:
    input = 10
    output = 5
    calls = 2
    by_session = {
        "session-1": {"input": 10, "output": 5, "model_calls": 2},
        "session-2": {"input": 20, "output": 7, "model_calls": 3},
    }

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class RunnerLoggingTest(unittest.TestCase):
    def test_scenario_anchor_timestamp_is_json_safe(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox",
            "phases": [],
            "entry_points": [{
                "id": "recon",
                "anchor_timestamp": datetime(2022, 1, 18, 12, 19, 10, tzinfo=timezone.utc),
                "anchor_rule_id": 31151,
                "anchor_agent_id": 27,
            }],
        })

        entry = spec.entry_points[0]
        self.assertEqual(entry.anchor_timestamp, "2022-01-18T12:19:10Z")
        self.assertEqual(entry.anchor_rule_id, "31151")
        self.assertEqual(entry.anchor_agent_id, "27")
        self.assertEqual(runner._question_for(entry, "alert-1"), "Triage and investigate alert alert-1.")
        json.dumps({"anchor_timestamp": entry.anchor_timestamp})

    def test_resolves_closest_imported_hive_alert(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox",
            "phases": [],
            "entry_points": [{
                "id": "recon",
                "anchor_timestamp": "2022-01-18T12:19:10Z",
                "anchor_rule_id": "31151",
                "anchor_agent_id": "27",
            }],
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "manifests"
            manifests.mkdir()
            (manifests / "thehive_manifest.run-1.json").write_text(json.dumps({
                "scenario": "fox",
                "tag": "ait-import-run:run-1",
                "alerts": [
                    {"id": "alert-far", "sourceRef": "far", "date": 1642500000000,
                     "tags": ["rule=31151", "agent_id=27"]},
                    {"id": "alert-near", "sourceRef": "near", "date": 1642508350000,
                     "tags": ["rule=31151", "agent_id=27"]},
                    {"id": "alert-wrong-agent", "sourceRef": "wrong", "date": 1642508350000,
                     "tags": ["rule=31151", "agent_id=1"]},
                ],
            }), encoding="utf-8")

            record = runner._resolve_entry_alert(spec.entry_points[0], "fox", root)

        self.assertEqual(record["id"], "alert-near")
        self.assertEqual(runner._question_for(spec.entry_points[0], record["id"]),
                         "Triage and investigate alert alert-near.")

    def test_resolves_hive_alert_without_manifest(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox",
            "phases": [],
            "entry_points": [{
                "id": "recon",
                "anchor_timestamp": "2022-01-18T12:19:10Z",
                "anchor_rule_id": "31151",
                "anchor_agent_id": "27",
            }],
        })
        records = [
            {"id": "alert-from-hive", "sourceRef": "collapsed", "date": 1642508350000,
             "tags": ["rule=31151", "agent_id=27"]},
        ]
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runner, "_query_alert_records_for_entry", return_value=records):
            record = runner._resolve_entry_alert(spec.entry_points[0], "fox", Path(tmp))

        self.assertEqual(record["id"], "alert-from-hive")

    def test_resolve_anchor_iso_prefers_configured_timestamp(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox", "phases": [],
            "entry_points": [{"id": "recon", "anchor_timestamp": "2022-01-18T12:19:10Z"}],
        })
        # Configured timestamp wins even when the alert carries a (different) date.
        iso = runner._resolve_anchor_iso(spec.entry_points[0], {"date": 1642508350000})
        self.assertEqual(iso, "2022-01-18T12:19:10Z")

    def test_resolve_anchor_iso_falls_back_to_alert_event_date(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox", "phases": [],
            "entry_points": [{"id": "privilege_escalation", "anchor_event_id": "1700000000.110417"}],
        })
        # No configured timestamp → derive from the alert's original event `date` (epoch ms).
        iso = runner._resolve_anchor_iso(spec.entry_points[0], {"date": 1642511671000})
        self.assertEqual(iso, "2022-01-18T13:14:31Z")

    def test_resolve_anchor_iso_is_none_when_unknown(self):
        spec = ScenarioSpec.from_dict({
            "name": "fox", "phases": [],
            "entry_points": [{"id": "privilege_escalation", "anchor_event_id": "x"}],
        })
        self.assertIsNone(runner._resolve_anchor_iso(spec.entry_points[0], {}))

    def test_question_includes_anchor_hint_when_known(self):
        spec = ScenarioSpec.from_dict({"name": "fox", "phases": [], "entry_points": [{"id": "recon"}]})
        q = runner._question_for(spec.entry_points[0], "alert-1", "2022-01-18T13:14:31Z")
        self.assertEqual(
            q,
            "Triage and investigate alert alert-1. "
            "The alert corresponds to activity observed around 2022-01-18T13:14:31Z.",
        )
        # Omitted when unknown — no invented time.
        self.assertEqual(
            runner._question_for(spec.entry_points[0], "alert-1"),
            "Triage and investigate alert alert-1.",
        )

    def test_trial_integrity_helpers(self):
        from types import SimpleNamespace as NS
        children = [
            NS(agent_name="triage", status="completed", result="triage report", error=""),
            NS(agent_name="investigation", status="failed", result="", error="Connection error."),
        ]
        target = runner._target_run(children, "investigation")
        self.assertIs(target, children[1])
        # a transiently-failed investigation is neither valid nor a real trial, and IS retryable
        self.assertFalse(runner._trial_produced_result(target))
        self.assertTrue(runner._is_transient_failure(target))
        # a completed investigation with a result is a valid trial, not retryable
        ok = NS(agent_name="investigation", status="completed", result="full report", error="")
        self.assertTrue(runner._trial_produced_result(ok))
        self.assertFalse(runner._is_transient_failure(ok))
        # a non-transient failure (real bug) is invalid but NOT retried
        bug = NS(agent_name="investigation", status="failed", result="", error="list index out of range")
        self.assertFalse(runner._trial_produced_result(bug))
        self.assertFalse(runner._is_transient_failure(bug))
        # a missing requested-agent run is invalid
        self.assertIsNone(runner._target_run([children[0]], "investigation"))
        self.assertFalse(runner._trial_produced_result(None))

    def test_run_logs_trial_start_and_done(self):
        messages = []
        agent_models = types.ModuleType("agent.models")
        agent_models.AgentRun = _AgentRun
        dashboard_runner = types.ModuleType("agent.dashboard.runner")
        dashboard_runner.start_session = lambda *_args, **_kwargs: "session-1"
        dashboard_runner.is_processing = lambda *_args, **_kwargs: False
        dashboard_events = types.ModuleType("agent.dashboard.events")
        dashboard_events.install = lambda: None
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runner, "_django_setup"), \
                patch.dict(sys.modules, {
                    "agent.models": agent_models,
                    "agent.dashboard.runner": dashboard_runner,
                    "agent.dashboard.events": dashboard_events,
                }), \
                patch("benchmark.scoring.ScenarioSpec.from_yaml", return_value=_Spec()), \
                patch.object(runner, "_resolve_entry_alert", return_value={"id": "alert-1"}), \
                patch.object(runner, "_capture_tokens", return_value=_Capture()):
            ids = runner.run("fox", "recon", 1, tmp, log=messages.append)
            meta = json.loads((Path(tmp) / "fox" / "recon" / "1" / "meta.json").read_text())

        self.assertEqual(ids, ["session-1"])
        self.assertEqual(meta["run_id"], "run-1")
        self.assertEqual(meta["session_id"], "session-1")
        self.assertEqual(meta["live_session_url"], "/dashboard/session-1/")
        self.assertEqual(meta["tokens"], {"input": 10, "output": 5, "model_calls": 2})
        self.assertTrue(any("entry_point=recon" in m for m in messages))
        self.assertTrue(any("start scenario=fox" in m for m in messages))
        self.assertTrue(any("done scenario=fox" in m and "tokens=in:10 out:5 calls:2" in m for m in messages))

    def test_run_uses_concurrent_trial_pool(self):
        messages = []
        starts: list[str] = []
        wait_count = 0
        lock = threading.Lock()
        both_waiting = threading.Event()
        release_waits = threading.Event()

        def fake_start_session(*_args, **_kwargs):
            with lock:
                session_id = f"session-{len(starts) + 1}"
                starts.append(session_id)
                return session_id

        def fake_wait(session_id, *_args, **_kwargs):
            nonlocal wait_count
            with lock:
                wait_count += 1
                if wait_count == 2:
                    both_waiting.set()
            self.assertTrue(both_waiting.wait(1), "second trial never entered wait")
            release_waits.set()
            return _Run(id=session_id, agent_name="orchestrator", result="session answer")

        def fake_children(session_id, _AgentRunClass):
            return [_Run(id=f"run-{session_id}", agent_name="investigation", result="report")]

        agent_models = types.ModuleType("agent.models")
        agent_models.AgentRun = _AgentRun
        dashboard_runner = types.ModuleType("agent.dashboard.runner")
        dashboard_runner.start_session = fake_start_session
        dashboard_runner.is_processing = lambda *_args, **_kwargs: False
        dashboard_events = types.ModuleType("agent.dashboard.events")
        dashboard_events.install = lambda: None
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runner, "_django_setup"), \
                patch.dict(sys.modules, {
                    "agent.models": agent_models,
                    "agent.dashboard.runner": dashboard_runner,
                    "agent.dashboard.events": dashboard_events,
                }), \
                patch("benchmark.scoring.ScenarioSpec.from_yaml", return_value=_Spec()), \
                patch.object(runner, "_resolve_entry_alert", return_value={"id": "alert-1"}), \
                patch.object(runner, "_capture_tokens", return_value=_Capture()), \
                patch.object(runner, "_wait_for_session", side_effect=fake_wait), \
                patch.object(runner, "_session_children", side_effect=fake_children):
            ids = runner.run("fox", "recon", 2, tmp, log=messages.append, concurrency=2)

        self.assertEqual(ids, ["session-1", "session-2"])
        self.assertTrue(release_waits.is_set())
        self.assertEqual(starts, ["session-1", "session-2"])
        self.assertTrue(any("trial=1/2" in m for m in messages))
        self.assertTrue(any("trial=2/2" in m for m in messages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
