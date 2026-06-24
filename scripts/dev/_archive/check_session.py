import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentRun

# Find recent triage runs
runs = list(AgentRun.objects.filter(agent_name='triage').order_by('-created_at')[:5])
for r in runs:
    print(f'Triage run {r.id}: status={r.status}')
    v = r.verdict
    if v:
        verdict_str = v.get('verdict') if isinstance(v, dict) else str(v)
        conf = v.get('confidence') if isinstance(v, dict) else ''
        print(f'  verdict={verdict_str} confidence={conf}')
    else:
        print(f'  verdict=None')
    meta = r.metadata or {}
    print(f'  session_id={meta.get("session_id")}')
    print(f'  case_id={meta.get("case_id")}')
    print()

# Also check orchestrator runs for the session
SESSION_ID = sys.argv[1] if len(sys.argv) > 1 else '08330bd0-c50a-405b-977f-bf943f7c069b'
orch = list(AgentRun.objects.filter(agent_name='orchestrator').order_by('-created_at')[:3])
for r in orch:
    print(f'Orch run {r.id}: status={r.status}')
    meta = r.metadata or {}
    print(f'  session_id={meta.get("session_id")}')
    v = r.verdict
    print(f'  verdict={json.dumps(v) if v else None}')
    print()
