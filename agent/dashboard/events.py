"""Capture logbus events and persist them for the live dashboard.

`emit()` fires inside async graph nodes, where sync ORM raises
SynchronousOnlyOperation. So the logging handler only *enqueues* events; a
dedicated daemon thread (a plain thread → sync ORM is allowed) drains the queue
and writes `AgentEvent` rows. WebSocket consumers tail those rows from the DB.

Only events bound to a dashboard session (logbus session contextvar set by the
runner) are persisted/streamed; ad-hoc agent logging is ignored here.

Streaming note: the runner executes each orchestrator turn on its own
`asyncio.new_event_loop()`, which is separate from the ASGI/Channels event loop.
Sending via `channel_layer.group_send` on the runner loop would put the message
into a queue tied to the wrong loop and never reach the consumer. Instead, stream
events are placed in a per-session in-memory buffer (thread-safe); the consumer
drains that buffer every 50 ms from within the ASGI loop.
"""
from __future__ import annotations

import logging
import queue
import threading

from agent.runtime.logbus import LogEvent, next_seq

_queue: "queue.Queue[LogEvent]" = queue.Queue()
_installed = False
_lock = threading.Lock()
_log = logging.getLogger("agent.dashboard")

# Per-session streaming buffer.  The runner appends here; consumers drain it.
_stream_buffers: dict[str, list] = {}
_stream_lock = threading.Lock()


def group_name(session_id: str) -> str:
    return f"run_{session_id}"


def drain_stream_chunks(session_id: str) -> list[dict]:
    """Return and clear all pending stream chunks for a session (thread-safe)."""
    with _stream_lock:
        return _stream_buffers.pop(session_id, [])


def _synthesize(record: logging.LogRecord) -> LogEvent:
    """Wrap a plain agent.* logging record (not from logbus.emit)."""
    kind = "error" if record.levelno >= logging.WARNING else "note"
    return LogEvent(next_seq(), record.created, "log", kind, record.getMessage())


class _EnqueueHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            ev = getattr(record, "logevent", None) or _synthesize(record)
            if not ev.session_id:
                return
            if ev.kind in {"stream", "intent_delta"}:
                # Final-answer text is orchestrator-only. Public intent belongs to
                # every agent and is rendered inside the matching agent trace.
                if ev.kind == "intent_delta" or ev.source == "orch":
                    with _stream_lock:
                        buf = _stream_buffers.setdefault(ev.session_id, [])
                        buf.append({
                            "seq": ev.seq,
                            "source": ev.source,
                            "run_id": ev.run_id or "",
                            "kind": ev.kind,
                            "detail": ev.detail or "",
                            "metadata": ev.metadata or {},
                        })
                return  # never persist stream events to DB
            _queue.put(ev)
        except Exception:
            pass


def _writer_loop() -> None:
    from django.db import close_old_connections

    from agent.models import AgentEvent

    while True:
        ev = _queue.get()
        try:
            AgentEvent.objects.create(
                session_id=ev.session_id or "",
                run_id=ev.run_id or "",
                seq=ev.seq,
                source=ev.source,
                kind=ev.kind,
                summary=ev.summary,
                detail=ev.detail or "",
                expand=ev.expand,
                metadata=ev.metadata or {},
            )
        except Exception:
            _log.exception("event writer failed to persist %s/%s", ev.source, ev.kind)
        finally:
            close_old_connections()


def install() -> None:
    """Attach the capture handler and start the writer thread (idempotent)."""
    global _installed
    with _lock:
        if _installed:
            return
        lg = logging.getLogger("agent")
        if not any(isinstance(h, _EnqueueHandler) for h in lg.handlers):
            lg.addHandler(_EnqueueHandler())
        lg.setLevel(logging.INFO)
        threading.Thread(target=_writer_loop, name="aci-event-writer", daemon=True).start()
        _installed = True
