import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentRun
runs = list(AgentRun.objects.order_by('-updated_at')[:5])
for r in runs:
    print(f'id={r.id} case_id={r.case_id} agent={r.agent_name} status={r.status} updated={r.updated_at}')
