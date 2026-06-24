import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
sys.path.insert(0, '.')
import django
django.setup()
from agent.models import AgentEvent, AgentRun

SESSION_ID = '4d44d048-9f0a-41d4-b556-0da03aa86805'
events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
print(f'Total events: {len(events)}')

answers = [e for e in events if e.kind == 'answer']
print(f'Answer events: {len(answers)}')
done_events = [e for e in events if e.kind == 'done']
print(f'Done events: {len(done_events)}')
for e in done_events[-5:]:
    print(f"  {e.source}: {e.summary}")

print('\nLast 20 events:')
for e in events[-20:]:
    print(f"{e.source:8s} {e.kind:12s} | {str(e.summary or '')[:100]}")
