import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentRun, AgentEvent

# Find newest orchestrator run
newest = AgentRun.objects.filter(agent_name='orchestrator').order_by('-created_at').first()
if not newest:
    print("No orchestrator run found")
    sys.exit(0)

SESSION = str(newest.id)
print(f"Session: {SESSION}")
print(f"Created: {newest.created_at}")
print(f"Status: {newest.status}")

events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))
total = len(events)
print(f"Total events: {total}")

# Show last 15
for e in events[-15:]:
    ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
    detail = str(e.detail or '')[:160]
    print(f'[{ts}] {e.source:6s} {e.kind:12s} | {detail}')

# Check answer
answers = [e for e in events if e.kind in ('answer', 'error')]
if answers:
    print(f"\nANSWER/ERROR:")
    for a in answers:
        print(f"  {a.source} {a.kind}: {str(a.detail or '')[:200]}")
