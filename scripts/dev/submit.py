"""Submit a question to the dashboard (new session or follow-up).

Consolidates the former ``submit_new.py`` and ``submit_followup.py`` scripts.

Examples
--------
    # New session
    python scripts/dev/submit.py --question "Triage and investigate case ~245862456"

    # Follow-up on an existing session, then poll for the answer
    python scripts/dev/submit.py --session <id> --question "investigate this case" --poll
"""
from __future__ import annotations

import argparse
import time

import requests

from _setup import django_setup

django_setup()

from agent.models import AgentEvent  # noqa: E402


def _poll(session_id: str, base: str, max_wait: int, pre_seen: set[int]) -> None:
    print(f"Polling up to {max_wait}s (skipping {len(pre_seen)} pre-existing events)...")
    seen = set(pre_seen)
    start = time.time()
    while time.time() - start < max_wait:
        events = list(AgentEvent.objects.filter(session_id=session_id).order_by("id"))
        new = [e for e in events if e.id not in seen]
        for e in new:
            seen.add(e.id)
            print(f"  [{e.kind:12s}] {(e.detail or '')[:200].replace(chr(10), ' ')}")
        finals = [e for e in new if e.kind in ("answer", "error")]
        if finals:
            last = finals[-1]
            print(f"\n=== FINAL ({last.kind}) ===")
            print((last.detail or "")[:4000])
            return
        time.sleep(10)
    print("TIMEOUT")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--question", required=True, help="analyst question to submit")
    p.add_argument("--session", help="existing session id (omit to start a new session)")
    p.add_argument("--base", default="http://localhost:8000", help="server base URL")
    p.add_argument("--poll", action="store_true", help="poll for the answer after submitting")
    p.add_argument("--max-wait", type=int, default=420, help="poll timeout seconds (default 420)")
    args = p.parse_args()

    if args.session:
        url = f"{args.base}/dashboard/{args.session}/ask"
        pre_seen = {e.id for e in AgentEvent.objects.filter(session_id=args.session)}
    else:
        url = f"{args.base}/dashboard/ask"
        pre_seen = set()

    r = requests.post(url, data={"question": args.question}, allow_redirects=False)
    print(f"POST {url} -> {r.status_code}")
    loc = r.headers.get("Location", "")
    session_id = args.session or loc.rstrip("/").split("/")[-1]
    print(f"Session ID: {session_id}")

    if args.poll:
        _poll(session_id, args.base, args.max_wait, pre_seen)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
