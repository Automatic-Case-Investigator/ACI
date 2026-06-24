"""Inspect AgentEvent / AgentRun rows.

Consolidates the former ``check_*.py`` and ``get_event.py`` one-off scripts into
a single parametrized tool.

Examples
--------
    # Last 20 events for a session
    python scripts/dev/inspect_events.py --session <id>

    # Only investigation-agent error events, full detail
    python scripts/dev/inspect_events.py --session <id> --source inv --kind error --full

    # Counts by source/kind for a run
    python scripts/dev/inspect_events.py --run <id> --count

    # A single event by id (replaces get_event.py)
    python scripts/dev/inspect_events.py --event 12345

    # Most recent runs (no scope given)
    python scripts/dev/inspect_events.py --runs --agent triage
"""
from __future__ import annotations

import argparse
from collections import Counter

from _setup import django_setup

django_setup()

from agent.models import AgentEvent, AgentRun  # noqa: E402  (after django_setup)


def _clip(text: object, limit: int) -> str:
    s = str(text or "").replace("\n", " ")
    return s[:limit]


def _print_event_row(e: AgentEvent, *, field: str, limit: int) -> None:
    ts = e.created_at.strftime("%H:%M:%S") if e.created_at else ""
    value = e.detail if field == "detail" else e.summary
    print(f"[{ts}] {e.source:6s} {e.kind:12s} | {_clip(value, limit)}")


def _print_single_event(event_id: int) -> None:
    e = AgentEvent.objects.get(id=event_id)
    print(f"Event {e.id}  source={e.source}  kind={e.kind}")
    print(f"Summary: {e.summary}")
    print("\nDetail:")
    print(e.detail or "(empty)")


def _print_runs(agent: str | None, limit: int) -> None:
    qs = AgentRun.objects.all()
    if agent:
        qs = qs.filter(agent_name=agent)
    for r in qs.order_by("-created_at")[:limit]:
        meta = r.metadata or {}
        verdict = r.verdict
        vstr = verdict.get("verdict") if isinstance(verdict, dict) else verdict
        print(
            f"{r.agent_name:13s} {str(r.id)} status={r.status:10s} "
            f"verdict={vstr} session={meta.get('session_id')} case={meta.get('case_id')}"
        )


def _events_queryset(args: argparse.Namespace):
    qs = AgentEvent.objects.all()
    if args.session:
        qs = qs.filter(session_id=args.session)
    if args.run:
        qs = qs.filter(run_id=args.run)
    if args.source:
        qs = qs.filter(source=args.source)
    if args.kind:
        qs = qs.filter(kind=args.kind)
    return qs.order_by("id")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--session", help="filter events by session id")
    scope.add_argument("--run", help="filter events by run id")
    scope.add_argument("--event", type=int, help="show a single event by id (full detail)")
    scope.add_argument("--runs", action="store_true", help="list recent AgentRun rows instead of events")
    p.add_argument("--source", help="filter by source label (tri/inv/orch/...)")
    p.add_argument("--kind", help="filter by kind (answer/error/think/call/done/...)")
    p.add_argument("--agent", help="with --runs: filter by agent_name")
    p.add_argument("--latest", type=int, default=20, help="show the last N events (default 20)")
    p.add_argument("--count", action="store_true", help="print counts by source/kind instead of rows")
    p.add_argument("--full", action="store_true", help="show full detail text rather than clipped summary")
    p.add_argument("--limit", type=int, default=100, help="per-row clip length (default 100)")
    args = p.parse_args()

    if args.event is not None:
        _print_single_event(args.event)
        return 0
    if args.runs:
        _print_runs(args.agent, args.latest)
        return 0

    if not (args.session or args.run):
        p.error("one of --session, --run, --event, or --runs is required")

    events = list(_events_queryset(args))
    print(f"Total matching events: {len(events)}")

    if args.count:
        print("\nBy source:", dict(Counter(e.source for e in events)))
        print("By kind:  ", dict(Counter(e.kind for e in events)))
        return 0

    field = "detail" if args.full else "summary"
    limit = 4000 if args.full else args.limit
    for e in events[-args.latest:]:
        _print_event_row(e, field=field, limit=limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
