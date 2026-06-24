"""Diagnose why test polling might fail."""
import os, sys, time, requests, django
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ['DJANGO_SETTINGS_MODULE'] = 'aci.settings'
# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
django.setup()
from agent.models import AgentEvent
from agent.dashboard.runner import send_message, is_processing

BASE = "http://localhost:8000"

def main():
    # Step 1: Create a test session
    print("Creating test session...", flush=True)
    r = requests.post(f"{BASE}/dashboard/ask", data={"question": "Quick test: what is ACI?"}, allow_redirects=False)
    print(f"POST status: {r.status_code}", flush=True)
    session_id = r.headers["Location"].rstrip("/").split("/")[-1]
    print(f"Session ID: {session_id}", flush=True)

    # Step 2: Poll for answer
    print("Polling for answer (30s max)...", flush=True)
    deadline = time.time() + 30
    last_id = 0
    found = False
    while time.time() < deadline:
        events = list(AgentEvent.objects.filter(session_id=session_id, id__gt=last_id).order_by("id"))
        for ev in events:
            last_id = ev.id
            print(f"  Found event: [{ev.id}] kind={ev.kind} source={ev.source}", flush=True)
            if ev.kind == "answer":
                print(f"  ANSWER: {(ev.detail or '')[:200]}", flush=True)
                found = True
                break
        if found:
            break
        time.sleep(2)

    if not found:
        print("No answer found in 30 seconds", flush=True)
    else:
        print("\nTest PASS: test process can see server events and answers", flush=True)

    # Step 3: Try sending Round 2 via send_message
    print(f"\nSending Round 2 via send_message...", flush=True)
    last_id_before = last_id
    result = send_message(session_id, "Describe your capabilities in one sentence.")
    print(f"send_message returned: {result}", flush=True)
    print(f"is_processing: {is_processing(session_id)}", flush=True)

    # Poll for Round 2 answer
    print("Polling for Round 2 answer (60s max)...", flush=True)
    deadline = time.time() + 60
    last_id = last_id_before
    found2 = False
    while time.time() < deadline:
        events = list(AgentEvent.objects.filter(session_id=session_id, id__gt=last_id).order_by("id"))
        for ev in events:
            last_id = ev.id
            print(f"  New event: [{ev.id}] kind={ev.kind} source={ev.source} | {(ev.summary or '')[:60]}", flush=True)
            if ev.kind == "answer":
                print(f"  ROUND 2 ANSWER: {(ev.detail or '')[:200]}", flush=True)
                found2 = True
                break
        if found2:
            break
        time.sleep(2)

    if not found2:
        print("No Round 2 answer in 60 seconds", flush=True)
        print("This means send_message from test process is NOT working as expected", flush=True)
        return 1

    print("Round 2 PASS: send_message works from test process", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
