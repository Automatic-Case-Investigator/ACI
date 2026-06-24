import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentRun, AgentEvent
import django.utils.timezone as tz

print("Server time:", tz.now().strftime('%H:%M:%S'))
runs = AgentRun.objects.filter(agent_name='orchestrator').order_by('-created_at')[:3]
for r in runs:
    cnt = AgentEvent.objects.filter(session_id=str(r.id)).count()
    created = r.created_at.strftime('%H:%M:%S')
    print(f"  {r.id} | {r.status:8s} | events={cnt:3d} | created={created}")
