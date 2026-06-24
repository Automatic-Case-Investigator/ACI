import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
sys.path.insert(0, '.')
import django
django.setup()
from agent.models import AgentEvent

SESSION_ID = '7349277a-26c8-4538-82fe-54ead37d46dc'
events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
print(f'Total events: {len(events)}')
for e in events[-25:]:
    print(f"{e.source:8s} {e.kind:12s} | {str(e.summary or '')[:100]}")
