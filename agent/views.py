from __future__ import annotations

import threading

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .agents.registry import get_agent
from .models import AgentEvent, AgentRun
from .runtime.avfs import reports_dir
from .runtime.run import run_agent_sync


class AgentRunView(APIView):
    def post(self, request):
        agent_name = request.data.get("agent_name", "investigation")
        case_id = request.data.get("case_id")
        question = request.data.get("question")

        if not case_id:
            return Response({"error": "case_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not question:
            return Response({"error": "question is required"}, status=status.HTTP_400_BAD_REQUEST)
        if get_agent(agent_name) is None:
            return Response({"error": f"Unknown agent: {agent_name}"}, status=status.HTTP_400_BAD_REQUEST)

        run = AgentRun.objects.create(
            case_id=case_id,
            agent_name=agent_name,
            question=question,
            status=AgentRun.STATUS_QUEUED,
            metadata=request.data.get("metadata") or {},
        )
        thread = threading.Thread(
            target=run_agent_sync,
            args=(str(run.id), agent_name, case_id, question),
            daemon=True,
        )
        thread.start()
        return Response(
            {"run_id": str(run.id), "status": run.status},
            status=status.HTTP_201_CREATED,
        )


class AgentRunDetailView(APIView):
    def get(self, request, run_id):
        try:
            run = AgentRun.objects.get(id=run_id)
        except AgentRun.DoesNotExist:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "run_id": str(run.id),
            "case_id": run.case_id,
            "agent_name": run.agent_name,
            "question": run.question,
            "status": run.status,
            "result": run.result,
            "error": run.error,
            "metadata": run.metadata,
            "created_at": run.created_at.isoformat(),
            "updated_at": run.updated_at.isoformat(),
        })


class AgentRunStatusView(APIView):
    def get(self, request, run_id):
        try:
            run = AgentRun.objects.get(id=run_id)
        except AgentRun.DoesNotExist:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({
            "run_id": str(run.id),
            "status": run.status,
            "error": run.error,
            "updated_at": run.updated_at.isoformat(),
        })


class AgentRunEventsView(APIView):
    def get(self, request, run_id):
        events = AgentEvent.objects.filter(session_id=str(run_id)).order_by("id")
        return Response({
            "run_id": str(run_id),
            "events": [
                {
                    "id": event.id,
                    "seq": event.seq,
                    "source": event.source,
                    "kind": event.kind,
                    "summary": event.summary,
                    "detail": event.detail,
                    "expand": event.expand,
                    "metadata": event.metadata,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ],
        })


class AgentRunCancelView(APIView):
    def post(self, request, run_id):
        try:
            run = AgentRun.objects.get(id=run_id)
        except AgentRun.DoesNotExist:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        run.status = AgentRun.STATUS_CANCELLED
        run.metadata = {**(run.metadata or {}), "cancel_requested": True}
        run.save(update_fields=["status", "metadata", "updated_at"])
        return Response({"run_id": str(run.id), "status": run.status})


class AgentRunResumeView(APIView):
    def post(self, request, run_id):
        try:
            run = AgentRun.objects.get(id=run_id)
        except AgentRun.DoesNotExist:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        if run.status not in {
            AgentRun.STATUS_CANCELLED,
            AgentRun.STATUS_BLOCKED,
            AgentRun.STATUS_INCOMPLETE_BUDGET,
            AgentRun.STATUS_FAILED,
        }:
            return Response(
                {"error": f"Run cannot be resumed from status {run.status}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        metadata = dict(run.metadata or {})
        metadata.pop("cancel_requested", None)
        run.status = AgentRun.STATUS_QUEUED
        run.metadata = metadata
        run.save(update_fields=["status", "metadata", "updated_at"])
        thread = threading.Thread(
            target=run_agent_sync,
            args=(str(run.id), run.agent_name, run.case_id, run.question),
            daemon=True,
        )
        thread.start()
        return Response({"run_id": str(run.id), "status": run.status})


class CaseQueueTasksView(APIView):
    def get(self, request, case_id, agent_name):
        run_id = request.query_params.get("run_id")
        if not run_id:
            return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        from aci_taskqueue.store import list_tasks

        return Response({"tasks": list_tasks(case_id, run_id, agent_name)})

    def post(self, request, case_id, agent_name):
        run_id = request.data.get("run_id")
        title = request.data.get("title")
        if not run_id:
            return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not title:
            return Response({"error": "title is required"}, status=status.HTTP_400_BAD_REQUEST)
        from aci_taskqueue.store import create_task

        task = create_task(
            case_id=case_id,
            run_id=run_id,
            agent_name=agent_name,
            title=title,
            description=request.data.get("description", ""),
            priority=int(request.data.get("priority", 50)),
            origin="human",
        )
        return Response({"task": task}, status=status.HTTP_201_CREATED)

    def patch(self, request, case_id, agent_name):
        task_id = request.data.get("task_id")
        if not task_id:
            return Response({"error": "task_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        from aci_taskqueue.store import update_task

        fields = {
            key: request.data[key]
            for key in ("title", "description", "priority", "status", "summary", "avfs_paths")
            if key in request.data
        }
        task = update_task(task_id, **fields)
        if task is None:
            return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response({"task": task})


class CaseWorkspaceView(APIView):
    def get(self, request, case_id):
        from .runtime.avfs import case_dir, evidence_dir, findings_dir, reports_dir

        root = case_dir(case_id)
        return Response({
            "case_id": case_id,
            "root": root,
            "memory_index": f"{root}/memory.md",
            "directories": {
                "evidence": evidence_dir(case_id),
                "findings": findings_dir(case_id),
                "reports": reports_dir(case_id),
            },
        })


class CaseLatestReportView(APIView):
    def get(self, request, case_id):
        run = (
            AgentRun.objects
            .filter(case_id=case_id, agent_name="investigation")
            .order_by("-updated_at")
            .first()
        )
        return Response({
            "case_id": case_id,
            "path": f"{reports_dir(case_id)}/final.md",
            "citations_path": f"{reports_dir(case_id)}/citations.json",
            "run_id": str(run.id) if run else "",
            "status": run.status if run else "",
            "result": run.result if run else "",
        })
