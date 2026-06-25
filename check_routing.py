"""Check session state and send 'yes' to test investigation routing."""
import sys, os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, ".")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django
django.setup()
from agent.models import AgentRun, AgentEvent
import requests

BASE = "http://localhost:8000"
session = sys.argv[1] if len(sys.argv) > 1 else ""
if not session:
    print("Usage: python check_routing.py <session_id>")
    sys.exit(1)

events = list(AgentEvent.objects.filter(session_id=session).order_by("id"))
print(f"Events so far: {len(events)}")
for e in events[-8:]:
    summary = (e.summary or "")[:120]
    print(f"  [{e.source}] {e.kind}: {summary}")

answers = [e for e in events if e.kind == "answer"]
print(f"\nAnswers: {len(answers)}")
if answers:
    print(f"Last answer preview: {answers[-1].detail[:300]}")

# Check if there's an existing triage report by looking for orchestrator answer
has_triage = any(e.source == "orch" and e.kind == "answer" for e in events)
print(f"\nHas triage answer: {has_triage}")

if "--send-yes" in sys.argv:
    print("\nSending 'yes' to trigger investigation routing...")
    r = requests.post(f"{BASE}/dashboard/{session}/ask", data={"question": "yes"})
    print(f"Response: {r.status_code}")
