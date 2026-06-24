import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentEvent

SESSION_ID = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 15

events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
print(f'Total events in session: {len(events)}')
print(f'Last {N} events:')
for e in events[-N:]:
    detail = (e.detail or '')[:300].replace('\n', ' ')
    print(f'  [{e.id:6d}] [{e.kind:12s}] {detail}')
