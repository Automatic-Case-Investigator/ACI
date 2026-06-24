"""Poll a run or session, streaming new events until it finishes.

Consolidates the former ``poll_run.py`` and ``poll_session.py`` scripts.

Examples
--------
    python scripts/dev/poll.py --run <run_id> --max-wait 600
    python scripts/dev/poll.py --session <session_id>
"""
from __future__ import annotations

import argparse
import json
import time

from _setup import django_setup

django_setup()

from agent.models import AgentEvent, AgentRun  # noqa: E402


def _events(args: argparse.Namespace):
    qs = AgentEvent.objects.all()
    if args.run:
        qs = qs.filter(run_id=args.run)
    else:
        qs = qs.filter(session_id=args.session)
    return list(qs.order_by("id"))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("--run", help="run id to poll")
    scope.add_argument("--session", help="session id to poll")
    p.add_argument("--max-wait", type=int, default=600, help="seconds to wait (default 600)")
    p.add_argument("--poll", type=int, default=10, help="poll interval seconds (default 10)")
    args = p.parse_args()

    label = f"run {args.run}" if args.run else f"session {args.session}"
    print(f"Polling {label} for up to {args.max_wait}s...")
    seen: set[int] = set()
    start = time.time()
    while time.time() - start < args.max_wait:
        events = _events(args)
        for e in events:
            if e.id not in seen:
                seen.add(e.id)
                snippet = (e.detail or "")[:200].replace("\n", " ")
                print(f"  [{e.kind:12s}] {snippet}")

        if args.run:
            run = AgentRun.objects.filter(id=args.run).first()
            if run and run.status in ("completed", "failed"):
                print(f"\n=== Run {run.status.upper()} ===")
                if run.verdict:
                    print(f"Verdict: {json.dumps(run.verdict, indent=2)}")
                if run.result:
                    print("Result:", (run.result or "")[:4000])
                return 0
        else:
            answers = [e for e in events if e.kind in ("answer", "error")]
            if answers:
                last = answers[-1]
                print(f"\n=== FINAL ({last.kind}) ===")
                print((last.detail or "")[:4000])
                return 0
        time.sleep(args.poll)

    print("TIMEOUT — no final result yet")
    for e in _events(args)[-10:]:
        print(f"  [{e.kind:12s}] {(e.detail or '')[:150]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
