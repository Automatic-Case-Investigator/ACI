"""
End-to-end test runner.
Usage: python tests/test_run.py [--case-id CASE_ID] [--question "..."] [--poll-secs N]
"""
import sys, os, time, json, argparse, requests

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
# Navigate from .claude/skills/run-aci-backend/tests/ up to project root
# (5 levels: tests -> run-aci-backend -> skills -> .claude -> ACI_Backend)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, project_root)
import django
django.setup()

from agent.models import AgentEvent, AgentRun

BASE = "http://localhost:8000"


def submit(question):
    r = requests.post(f"{BASE}/dashboard/ask", data={"question": question}, allow_redirects=False)
    assert r.status_code == 302, f"Expected 302, got {r.status_code}: {r.text[:200]}"
    loc = r.headers["Location"]
    session_id = loc.rstrip("/").split("/")[-1]
    print(f"  session: {session_id}")
    return session_id


def followup(session_id, text):
    """Send a follow-up message via the ask_followup HTTP endpoint."""
    r = requests.post(
        f"{BASE}/dashboard/{session_id}/ask",
        data={"question": text},
        allow_redirects=False,
    )
    print(f"  followup -> {r.status_code} {r.text[:100]}")


def poll(session_id, poll_secs, stop_kinds=("answer", "error"), after_id=0, stop_source=None):
    """Poll events until a stop_kind is seen or timeout. Returns (event, last_id).

    If stop_source is set, only events from that source count as stop conditions.
    """
    deadline = time.time() + poll_secs
    last_id = after_id
    while time.time() < deadline:
        events = list(
            AgentEvent.objects.filter(session_id=session_id, id__gt=last_id).order_by("id")
        )
        for e in events:
            last_id = e.id
            ts = e.created_at.strftime("%H:%M:%S") if hasattr(e, "created_at") else ""
            print(f"  [{ts}] {e.source:6s} {e.kind:12s} | {str(e.detail or '')[:120]}")
            if e.kind in stop_kinds:
                if stop_source is None or e.source == stop_source:
                    return e, last_id
        time.sleep(5)
    return None, last_id


def _resolve_investigation(session_id):
    """Match consumers.py _resolve_investigation: find by metadata.session_id."""
    qs = AgentRun.objects.filter(agent_name="investigation")
    try:
        inv = qs.filter(metadata__session_id=session_id).order_by("created_at").first()
        if inv:
            return inv
    except Exception:
        pass
    for run in qs.order_by("created_at"):
        if (run.metadata or {}).get("session_id") == session_id:
            return run
    return None


def board_entries(session_id):
    inv = _resolve_investigation(session_id)
    if not inv:
        print("  [board] no investigation run found")
        return []
    try:
        from aci_board import store as board_store
        return board_store.list_entries(inv.case_id, str(inv.id), "investigation")
    except Exception as ex:
        print(f"  [board] error: {ex}")
        return []


def task_summary(session_id):
    inv = _resolve_investigation(session_id)
    if not inv:
        print("  [tasks] no investigation run found")
        return
    try:
        from aci_taskqueue import store as tq_store
        tasks = tq_store.list_tasks(inv.case_id, str(inv.id), "investigation")
        total = len(tasks)
        done = sum(1 for t in tasks if t.get("status") == "completed")
        print(f"  tasks: {done}/{total} completed")
        for t in tasks:
            print(f"  [{t.get('status'):10s}|pri={t.get('priority', 0):3d}] {t.get('title', '')[:80]}")
    except Exception as ex:
        print(f"  [tasks] error: {ex}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case-id", default="~254202040")
    p.add_argument(
        "--question",
        default="Triage case ~254202040 — investigate suspicious crontab and process activity",
    )
    p.add_argument("--poll-secs", type=int, default=300)
    args = p.parse_args()

    print(f"\n{'='*60}")
    print(f"SUBMIT: {args.question[:80]}")
    print("=" * 60)
    session_id = submit(args.question)

    print(f"\n--- phase 1: triage (waiting for answer) ---")
    # Triage alone can take 2-3 min; the post-triage orchestrator call adds ~1 min more.
    # Reserve only a small slice for phase 3 so phase 1 has enough room.
    phase1_secs = max(60, args.poll_secs - 300)
    ev1, cursor = poll(session_id, phase1_secs, stop_kinds=("answer", "error"))

    if ev1 is None:
        print("TIMEOUT waiting for triage answer")
        return 1
    if ev1.kind == "error":
        print(f"\nERROR in triage: {ev1.detail}")
        return 1

    print(f"\n--- TRIAGE ANSWER (truncated) ---")
    print(str(ev1.detail or "")[:1500])

    print(f"\n--- phase 2: sending 'yes' to proceed with investigation ---")
    followup(session_id, "yes")

    print(f"\n--- phase 3: investigation (waiting for answer, cursor={cursor}) ---")
    ev2, cursor2 = poll(
        session_id, args.poll_secs, stop_kinds=("answer", "error"),
        after_id=cursor, stop_source="orch",
    )

    if ev2 is None:
        print("TIMEOUT waiting for investigation answer")
        # Still print partial info
    else:
        print(f"\n{'='*60}")
        print("INVESTIGATION ANSWER (truncated):")
        print("=" * 60)
        print(str(ev2.detail or "")[:3000])

    print(f"\n--- board entries ---")
    entries = board_entries(session_id)
    if entries:
        for e in entries:
            print(
                f"  [{e['kind']:10s}|{e.get('confidence', ''):6s}|{e.get('status', ''):9s}]"
                f" {e['content'][:100]}"
            )
        print(f"  total board entries: {len(entries)}")
    else:
        print("  (no board entries — investigation may not have found confirmed facts)")

    print(f"\n--- task summary ---")
    task_summary(session_id)

    ok = ev2 is not None and ev2.kind == "answer"
    print(f"\nSMOKE {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
