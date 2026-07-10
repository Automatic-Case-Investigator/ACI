"""Session-delete cascade: removing an orchestrator session must take its child
specialist runs (and events) with it, on ANY delete path — because the child→session
link is a soft `metadata["session_id"]` reference, not a DB foreign key.
"""
from django.test import TestCase

from agent.models import AgentEvent, AgentRun


class SessionCascadeDeleteTests(TestCase):
    def _session_with_children(self):
        orch = AgentRun.objects.create(agent_name="orchestrator", case_id="~1", question="q")
        sid = str(orch.id)
        triage = AgentRun.objects.create(
            agent_name="triage", case_id="~1", question="q", metadata={"session_id": sid},
        )
        inv = AgentRun.objects.create(
            agent_name="investigation", case_id="~1", question="q", metadata={"session_id": sid},
        )
        AgentEvent.objects.create(session_id=sid, source="orch", kind="note", summary="hi")
        return orch, triage, inv, sid

    def test_deleting_session_via_instance_delete_cascades_children(self):
        orch, triage, inv, sid = self._session_with_children()
        orch.delete()  # the bare model delete — not the app-level delete_run helper
        self.assertFalse(AgentRun.objects.filter(id__in=[triage.id, inv.id]).exists())
        self.assertFalse(AgentEvent.objects.filter(session_id=sid).exists())

    def test_deleting_session_via_bulk_queryset_cascades_children(self):
        orch, triage, inv, sid = self._session_with_children()
        # A bulk queryset delete (e.g. admin / shell / cleanup) must cascade too.
        AgentRun.objects.filter(id=orch.id).delete()
        self.assertFalse(AgentRun.objects.filter(id__in=[triage.id, inv.id]).exists())

    def test_deleting_a_child_does_not_cascade_siblings_or_parent(self):
        orch, triage, inv, sid = self._session_with_children()
        triage.delete()
        self.assertTrue(AgentRun.objects.filter(id=orch.id).exists())
        self.assertTrue(AgentRun.objects.filter(id=inv.id).exists())

    def test_unrelated_session_children_are_untouched(self):
        _, keep_triage, _, _ = self._session_with_children()
        orch2, _, _, _ = self._session_with_children()
        orch2.delete()
        self.assertTrue(AgentRun.objects.filter(id=keep_triage.id).exists())
