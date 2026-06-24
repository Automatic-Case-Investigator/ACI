import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent, AgentRun

# Find the newest run
recent_runs = list(AgentRun.objects.order_by('-created_at')[:10])
for r in recent_runs:
    count = AgentEvent.objects.filter(session_id=r.id).count()
    print(f'id={r.id} case={r.case_id} agent={r.agent_name} status={r.status} events={count} created={r.created_at}')
