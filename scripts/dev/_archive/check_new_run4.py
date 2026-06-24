import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentRun, AgentEvent
import django.utils.timezone as tz

SESSION = "56666ab1-7e63-4abc-baec-c8722966386f"
print("Server time:", tz.now().strftime('%H:%M:%S'))
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))
print(f"Total events: {len(events)}")
for e in events[-15:]:
    ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
    detail = str(e.detail or '')[:200]
    print(f'[{ts}] {e.source:6s} {e.kind:12s} | {detail}')
answers = [e for e in events if e.kind in ('answer', 'error')]
if answers:
    print("\nANSWER/ERROR:")
    for a in answers[-3:]:
        print(f"  {a.source} {a.kind}: {str(a.detail or '')[:300]}")
