import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
sys.path.insert(0, '.')
import django
django.setup()
from agent.models import AgentEvent, AgentRun
from django.utils import timezone

print("Recent AgentRuns (last 5):")
for run in AgentRun.objects.order_by('-created_at')[:5]:
    print(f"  {run.id} | {run.status} | {run.created_at}")

print("\nRecent sessions with events:")
from django.db.models import Count, Max
sessions = AgentEvent.objects.values('session_id').annotate(
    count=Count('id'), last=Max('created_at')
).order_by('-last')[:5]
for s in sessions:
    print(f"  {s['session_id']} | events={s['count']} | last={s['last']}")
