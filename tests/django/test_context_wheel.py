"""`runner.get_ctx` — the payload behind the dashboard's context wheel.

Covers the three things that made the wheel show a wrong number or cost too much
to show: which run's reading is picked, that the warning band travels with the
payload, and that deleting a session drops its readings.
"""
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.db import connection

from agent.dashboard import runner
from agent.dashboard.run_actions import delete_run
from agent.models import AgentRun
from agent.runtime.graph.toolio import _COMPACT_THRESHOLD
from agent.runtime.infra import logbus


class GetCtxTests(TestCase):
    def setUp(self):
        self.orch = AgentRun.objects.create(
            agent_name="orchestrator", case_id="~1", question="q",
            status=AgentRun.STATUS_RUNNING,
        )
        self.sid = str(self.orch.id)
        self.addCleanup(logbus.clear_session_context_usage, self.sid)

    def _record(self, run_id, tokens, source):
        session_token = logbus.bind_session(self.sid)
        run_token = logbus.bind_run(run_id)
        try:
            logbus.update_context_usage(tokens, source)
        finally:
            logbus.reset_run(run_token)
            logbus.reset_session(session_token)

    def test_reports_the_orchestrator_reading_when_no_specialist_runs(self):
        self._record(self.sid, 12345, "orch")
        ctx = runner.get_ctx(self.sid)
        self.assertEqual(ctx["tokens"], 12345)
        self.assertEqual(ctx["source"], "orch")
        self.assertGreater(ctx["limit"], 0)

    def test_carries_the_compaction_warning_fraction(self):
        # The browser colors the ring at this fraction; it must match the point
        # where history compaction actually fires.
        self.assertEqual(runner.get_ctx(self.sid)["warn_frac"], _COMPACT_THRESHOLD)

    def test_running_specialist_reading_wins(self):
        inv = AgentRun.objects.create(
            agent_name="investigation", case_id="~1", question="q",
            status=AgentRun.STATUS_RUNNING, metadata={"session_id": self.sid},
        )
        self._record(self.sid, 10000, "orch")
        self._record(str(inv.id), 90000, "inv")

        ctx = runner.get_ctx(self.sid)
        self.assertEqual(ctx["tokens"], 90000)
        self.assertEqual(ctx["source"], "inv")

    def test_falls_back_to_the_freshest_reading_before_a_new_run_reports(self):
        # A just-spawned specialist has no reading yet. The wheel should hold the
        # freshest number in the session rather than resetting to empty.
        inv_done = AgentRun.objects.create(
            agent_name="investigation", case_id="~1", question="q",
            status=AgentRun.STATUS_COMPLETED, metadata={"session_id": self.sid},
        )
        self._record(self.sid, 10000, "orch")
        self._record(str(inv_done.id), 77000, "inv")

        AgentRun.objects.create(
            agent_name="triage", case_id="~1", question="q",
            status=AgentRun.STATUS_RUNNING, metadata={"session_id": self.sid},
        )
        ctx = runner.get_ctx(self.sid)
        self.assertEqual(ctx["tokens"], 77000)

    def test_does_not_scan_the_run_table_when_no_specialist_exists(self):
        self._record(self.sid, 5000, "orch")
        runner.get_ctx(self.sid)  # warm the context-length cache

        with CaptureQueriesContext(connection) as captured:
            runner.get_ctx(self.sid)

        # The orchestrator-only phase used to fall into a 200-row ordered scan on
        # every status push (~2.5x/sec per open session).
        scans = [q["sql"] for q in captured.captured_queries if "LIMIT 200" in q["sql"]]
        self.assertEqual(scans, [])


class DeletePurgesContextTests(TestCase):
    def test_deleting_a_session_clears_its_readings(self):
        orch = AgentRun.objects.create(
            agent_name="orchestrator", case_id="~1", question="q",
        )
        sid = str(orch.id)
        inv = AgentRun.objects.create(
            agent_name="investigation", case_id="~1", question="q",
            metadata={"session_id": sid},
        )
        for run_id, tokens in ((sid, 100), (str(inv.id), 200)):
            session_token = logbus.bind_session(sid)
            run_token = logbus.bind_run(run_id)
            logbus.update_context_usage(tokens, "orch")
            logbus.reset_run(run_token)
            logbus.reset_session(session_token)

        delete_run(orch)

        self.assertIsNone(logbus.get_context_usage(sid))
        self.assertIsNone(logbus.get_latest_context_usage(sid))
