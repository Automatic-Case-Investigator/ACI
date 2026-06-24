import sys, os, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
sys.path.insert(0, '.')
import django
django.setup()
from agent.models import AgentEvent

SESSION_ID = "4d44d048-9f0a-41d4-b556-0da03aa86805"
POLL_SECS = 7200
start = time.time()
last_count = 0
answer_count = 0  # track how many answers we've seen (triage + investigation)

print(f"Monitoring session {SESSION_ID}")
while time.time() - start < POLL_SECS:
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by("id"))
    if len(events) != last_count:
        for e in events[last_count:]:
            elapsed = int(time.time() - start)
            print(f"[{elapsed:5d}s] {e.source or 'sys':8s} {e.kind:12s} | {str(e.summary or '')[:120]}")
        last_count = len(events)
        answers = [e for e in events if e.kind == "answer"]
        # Wait for 2 answers: triage + investigation
        if len(answers) >= 2:
            print("\n=== INVESTIGATION FINAL ===")
            print(answers[-1].detail)
            break
    time.sleep(5)
else:
    print("TIMEOUT - printing last events")
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by("id"))
    print(f"Total events: {len(events)}")
    # Print last 20 events
    for e in events[-20:]:
        print(f"{e.source or 'sys':8s} {e.kind:12s} | {str(e.summary or '')[:120]}")
