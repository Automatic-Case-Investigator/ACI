import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

SESSION = "483e7384-8ce5-43f0-b681-e951702366d6"
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))
total = len(events)
print(f"total: {total}")
# Show last 15
for e in events[-15:]:
    ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
    detail = str(e.detail or '')[:160]
    print(f'[{ts}] {e.source:6s} {e.kind:12s} | {detail}')
# Check for answer/error events
answers = [e for e in events if e.kind in ('answer', 'error')]
if answers:
    print(f"\nANSWER/ERROR FOUND ({len(answers)}):")
    for a in answers:
        print(f"  {a.source} {a.kind}: {str(a.detail or '')[:300]}")
