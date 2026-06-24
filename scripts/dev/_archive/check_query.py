import sys, os, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

SESSION = '02e9d828-bee8-4844-bdaa-3e2a36abd4a8'
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))

# Find call events that preceded parsing_exception errors
error_times = set()
for e in events:
    if e.source == 'inv' and e.kind == 'error' and 'parsing_exception' in str(e.detail or ''):
        error_times.add(e.created_at)

# Find call events just before those errors
printed = 0
prev_call = None
for i, e in enumerate(events):
    if e.source == 'inv' and e.kind == 'call':
        prev_call = e
    if e.source == 'inv' and e.kind == 'error' and 'parsing_exception' in str(e.detail or '') and printed < 2:
        if prev_call:
            print(f"\n=== CALL that caused parsing_exception ===")
            print(f"[{prev_call.created_at}]")
            try:
                d = json.loads(str(prev_call.detail or '{}'))
                print(json.dumps(d, indent=2))
            except:
                print(str(prev_call.detail or '')[:2000])
            printed += 1
