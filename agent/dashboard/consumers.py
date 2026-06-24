"""WebSocket consumer for the live run dashboard.

Channels provides the WS transport; event delivery tails the `AgentEvent` table by
id cursor (reliable across the writer thread / event loop boundary) and pushes
server-rendered HTML frames. Three frame types: `log` (one event), `queue`, `status`.
The browser only swaps innerHTML — all rendering lives in the cotton components.
"""
from __future__ import annotations

import inspect
import json
import re

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.template.loader import render_to_string

from .events import group_name

ACTIVE_STATUSES = {"pending", "claimed", "blocked"}

# Internal seed task titles created by the graph runtime — these are orchestration
# artifacts and should not be displayed in the investigation queue panel.
_INTERNAL_TASK_PREFIXES = (
    "Populate investigation queue",
    "Investigate case ",  # fallback seed when no triage handoff is present
)

# The board content for a TI result is formatted as
# "TI[provider] kind value: <verdict> (<score>) — <indicators>" (see
# agent.ti.enricher.write_ti_results), so the verdict is the first known keyword
# after the colon.
_TI_VERDICT_RE = re.compile(r":\s*(malicious|suspicious|clean|unknown)\b")

async def _resolve_coroutines(obj):
    if inspect.iscoroutine(obj):
        return await obj

    if isinstance(obj, dict):
        return {
            k: await _resolve_coroutines(v)
            for k, v in obj.items()
        }

    if isinstance(obj, list):
        return [
            await _resolve_coroutines(v)
            for v in obj
        ]

    return obj

def _ti_display_rows(board_entries: list) -> list[dict]:
    """Project ti_result board entries into display rows with a parsed verdict."""
    rows = []
    for e in board_entries:
        if e.get("kind") != "ti_result":
            continue
        m = _TI_VERDICT_RE.search(e.get("content", "") or "")
        rows.append({**e, "verdict": m.group(1) if m else "unknown"})
    return rows


# ── sync helpers (DB + task store), called via database_sync_to_async ────────────
def _resolve_investigation(session_id: str):
    from agent.models import AgentRun

    qs = AgentRun.objects.filter(agent_name="investigation")
    try:
        inv = qs.filter(metadata__session_id=session_id).order_by("-created_at").first()
        if inv:
            return inv
    except Exception:
        pass
    for run in qs.order_by("-created_at"):
        if (run.metadata or {}).get("session_id") == session_id:
            return run
    return None


def _resolve_restartable_specialist(session_id: str):
    from agent.models import AgentRun
    from agent.dashboard import runner

    try:
        runs = AgentRun.objects.filter(metadata__session_id=session_id).order_by("-created_at")
    except Exception:
        runs = AgentRun.objects.order_by("-created_at")[:200]
    for run in runs:
        if (run.metadata or {}).get("session_id") != session_id:
            continue
        if runner.can_restart_from_prior_run(run):
            return run
    return None


def _snapshot(session_id: str) -> dict:
    from agent.models import AgentRun
    from agent.dashboard import runner
    from django.urls import reverse

    orch = AgentRun.objects.filter(id=session_id).first()
    inv = _resolve_investigation(session_id)
    active_specialist = runner.active_specialist_for_session(session_id)
    tasks: list = []
    board_entries: list = []
    case_id = run_id = inv_status = ""
    if inv:
        case_id, run_id, inv_status = inv.case_id, str(inv.id), inv.status
        from aci_taskqueue import store as task_store

        try:
            raw = task_store.list_tasks(case_id, run_id, "investigation")
            raw = [
                t for t in raw
                if not any(t["title"].startswith(p) for p in _INTERNAL_TASK_PREFIXES)
            ]
            active = [t for t in raw if t["status"] in ACTIVE_STATUSES]
            done = [t for t in raw if t["status"] not in ACTIVE_STATUSES]
            tasks = active + done
        except Exception:
            tasks = []

        try:
            from aci_board import store as board_store

            board_entries = board_store.list_entries(case_id, run_id, "investigation")
        except Exception:
            board_entries = []

    running = bool(inv and inv_status == "running")
    processing = runner.is_processing(session_id) or bool(active_specialist)
    processing_source = ""
    if active_specialist:
        processing_source = "inv" if active_specialist.agent_name == "investigation" else "tri"
    elif runner.is_processing(session_id):
        processing_source = "orch"
    restart_source = inv if (inv and runner.can_restart_from_prior_run(inv)) else _resolve_restartable_specialist(session_id)
    can_restart = bool(restart_source)
    # Surface the latest structured verdict for the diagnosis card. Prefer the
    # investigation run; fall back to the most recent run with a verdict for this
    # session (e.g. a triage-only session).
    verdict_run = inv if (inv and inv.verdict) else _latest_verdict_run(session_id)
    analyst_verdict = ""
    if verdict_run:
        from agent.models import FeedbackEntry
        fb = FeedbackEntry.objects.filter(run_id=str(verdict_run.id)).first()
        if fb and fb.analyst_verdict:
            av = fb.analyst_verdict
            analyst_verdict = av.get("verdict", "") if isinstance(av, dict) else str(av)
    return {
        "status": orch.status if orch else "unknown",
        "question": orch.question if orch else "",
        "case_id": (orch.case_id if orch and orch.case_id else case_id),
        "run_id": run_id,
        "inv_status": inv_status,
        "running": running,
        "processing": processing,
        "processing_source": processing_source,
        "ctx": runner.get_ctx(session_id),
        "tasks": tasks,
        "board_entries": board_entries,
        # Findings (fact/hypothesis/artifact) and advisory TI results render in
        # separate board sections so reputation hits don't blend into the findings.
        "finding_entries": [e for e in board_entries if e.get("kind") != "ti_result"],
        "ti_entries": _ti_display_rows(board_entries),
        "verdict": verdict_run.verdict if verdict_run else None,
        "verdict_run_id": str(verdict_run.id) if verdict_run else "",
        "analyst_verdict": analyst_verdict,
        "can_restart": can_restart,
        "restart_agent": restart_source.agent_name if restart_source else "",
        "restart_run_id": str(restart_source.id) if restart_source else "",
        "restart_url": reverse("dashboard:run_restart", args=[restart_source.id]) if restart_source else "",
        # B4: the queue/Findings Board column is only meaningful once investigation has work or is
        # active. A fresh/triage-only session shows a full-width chat.
        "show_queue": bool(tasks or board_entries),
    }


def _latest_verdict_run(session_id: str):
    """Most recent run in this session that carries a structured verdict, or None."""
    from agent.models import AgentRun

    try:
        runs = AgentRun.objects.filter(
            metadata__session_id=session_id, verdict__isnull=False
        ).order_by("-updated_at")
        return runs.first()
    except Exception:
        return None


def _apply_queue_action(session_id: str, msg: dict) -> None:
    inv = _resolve_investigation(session_id)
    if not inv:
        return
    from aci_taskqueue import store

    action = msg.get("action")
    if action == "add":
        store.create_task(
            inv.case_id, str(inv.id), "investigation",
            title=(msg.get("title") or "(untitled)").strip(),
            description=msg.get("description", ""),
            priority=int(msg.get("priority") or 50),
            origin="human",
        )
    elif action == "del":
        store.delete_task(msg.get("task_id", ""))
    elif action == "edit":
        fields = {}
        for key in ("title", "description", "priority"):
            val = msg.get(key)
            if val not in (None, ""):
                fields[key] = int(val) if key == "priority" else val
        if fields:
            store.update_task(msg.get("task_id", ""), **fields)
    elif action == "move":
        active = [
            t for t in store.list_tasks(inv.case_id, str(inv.id), "investigation")
            if t["status"] in ACTIVE_STATUSES
        ]
        tid = msg.get("task_id", "")
        ids = [t["id"] for t in active if t["id"] != tid]
        pos = max(1, min(int(msg.get("position") or 1), len(ids) + 1))
        ids.insert(pos - 1, tid)
        store.reorder(inv.case_id, str(inv.id), "investigation", ids)


class RunConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.session_id = self.scope["url_route"]["kwargs"]["session_id"]
        self.group = group_name(self.session_id)
        # Resume from the last event the page already rendered server-side (passed
        # as ?after=<id>). Without this the stream re-pushes the initial events and
        # they render twice. On reconnect the client passes its advanced cursor.
        self.cursor = self._cursor_from_query()
        self._queue_sig = None
        self._status_sig = None
        await self.accept()
        await self.channel_layer.group_add(self.group, self.channel_name)
        await self._push_new_events()
        await self._push_queue_and_status()
        import asyncio

        self._task = asyncio.create_task(self._loop())

    def _cursor_from_query(self) -> int:
        from urllib.parse import parse_qs

        raw = self.scope.get("query_string", b"") or b""
        try:
            return int(parse_qs(raw.decode()).get("after", ["0"])[0])
        except (ValueError, TypeError):
            return 0

    async def disconnect(self, code):
        task = getattr(self, "_task", None)
        if task:
            task.cancel()
        if hasattr(self, "group"):
            await self.channel_layer.group_discard(self.group, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        try:
            msg = json.loads(text_data or "{}")
        except Exception:
            return
        if msg.get("action") == "ask":
            question = (msg.get("question") or "").strip()
            if question:
                from agent.dashboard import runner
                await database_sync_to_async(runner.send_message)(self.session_id, question)
        elif msg.get("action") == "stop":
            from agent.dashboard import runner
            await database_sync_to_async(runner.stop_processing)(self.session_id)
        elif msg.get("action") in {"add", "del", "edit", "move"}:
            await database_sync_to_async(_apply_queue_action)(self.session_id, msg)
            self._queue_sig = None  # force a refresh on next push
            await self._push_queue_and_status()

    async def _loop(self):
        import asyncio

        tick = 0
        try:
            while True:
                await asyncio.sleep(0.05)   # 50 ms — smooth token delivery
                await self._push_stream_chunks()
                tick += 1
                if tick % 8 == 0:           # every ~400 ms — DB events + queue
                    await self._push_new_events()
                    await self._push_queue_and_status()
        except asyncio.CancelledError:
            pass

    async def _push_stream_chunks(self):
        from agent.dashboard.events import drain_stream_chunks
        chunks = drain_stream_chunks(self.session_id)
        for chunk in chunks:
            await self.send(text_data=json.dumps({
                "type": "log",
                "kind": chunk.get("kind", "stream"),
                "html": "",
                "seq": chunk.get("seq"),
                "source": chunk.get("source"),
                "run_id": chunk.get("run_id", ""),
                "detail": chunk.get("detail", ""),
                "metadata": chunk.get("metadata", {}),
            }))

    @database_sync_to_async
    def _fetch_events(self, after_id):
        from agent.models import AgentEvent

        return list(
            AgentEvent.objects.filter(session_id=self.session_id, id__gt=after_id).order_by("id")
        )

    async def _push_new_events(self):
        for ev in await self._fetch_events(self.cursor):
            html = render_to_string("dashboard/_event.html", {"ev": ev})
            await self.send(text_data=json.dumps({
                "type": "log",
                "id": ev.id,
                "html": html,
                "seq": ev.seq,
                "source": ev.source,
                "kind": ev.kind,
                "run_id": ev.run_id,
                "summary": ev.summary,
                "detail": ev.detail,
                "metadata": ev.metadata or {},
            }))
            self.cursor = ev.id

    async def _push_queue_and_status(self):
        snap = await database_sync_to_async(_snapshot)(self.session_id)
        snap = await _resolve_coroutines(snap)

        ctx = snap["ctx"]
        verdict_sig = (snap.get("verdict") or {}).get("verdict") if snap.get("verdict") else None
        status_sig = (
            snap["status"], snap["case_id"], snap["run_id"], snap["inv_status"],
            snap["processing"], snap.get("processing_source"), ctx["tokens"], ctx.get("run_id"), ctx.get("source"),
            ctx.get("limit"), ctx.get("ts"), verdict_sig, snap.get("verdict_run_id"),
            snap.get("can_restart"), snap.get("restart_agent"), snap.get("restart_run_id"),
            snap.get("analyst_verdict"),
        )
        if status_sig != self._status_sig:
            self._status_sig = status_sig
            html = render_to_string("dashboard/_status.html", {"snap": snap})
            await self.send(text_data=json.dumps({
                "type": "status",
                "html": html,
                "processing": snap["processing"],
                "processing_source": snap.get("processing_source", ""),
                "ctx_tokens": ctx["tokens"],
                "ctx_limit": ctx["limit"],
                "ctx_run_id": ctx.get("run_id", ""),
                "ctx_source": ctx.get("source", ""),
                "ctx_ts": ctx.get("ts"),
            }))
        queue_sig = (snap["show_queue"],) + tuple(
            (t["id"], t["status"], t["priority"], t["title"], t.get("summary"), t.get("updated_at"))
            for t in snap["tasks"]
        ) + tuple(
            (e["id"], e["kind"], e["status"], e["content"], e.get("updated_at"))
            for e in snap["board_entries"]
        )
        if queue_sig != self._queue_sig:
            self._queue_sig = queue_sig
            html = render_to_string("dashboard/_queue.html", {"snap": snap})
            await self.send(text_data=json.dumps({
                "type": "queue", "html": html, "show_queue": snap["show_queue"],
            }))
