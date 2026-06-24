import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent
SESSION = "ae562e04-c79d-48a4-ae16-ee31042571d1"
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('-id')[:20])
for e in reversed(events):
    ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
    detail = str(e.detail or '')[:120]
    print(f'[{ts}] {e.source:6s} {e.kind:12s} | {detail}')
total = AgentEvent.objects.filter(session_id=SESSION).count()
print(f"\ntotal events: {total}")
