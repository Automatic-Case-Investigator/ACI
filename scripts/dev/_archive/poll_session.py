import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentEvent

SESSION_ID = sys.argv[1] if len(sys.argv) > 1 else '08330bd0-c50a-405b-977f-bf943f7c069b'
MAX_WAIT = int(sys.argv[2]) if len(sys.argv) > 2 else 420
POLL = 10

print(f'Polling session {SESSION_ID} for up to {MAX_WAIT}s...')
seen_ids = set()
start = time.time()
while time.time() - start < MAX_WAIT:
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
    new = [e for e in events if e.id not in seen_ids]
    for e in new:
        seen_ids.add(e.id)
        snippet = (e.detail or '')[:200].replace('\n', ' ')
        print(f'  [{e.kind:12s}] {snippet}')
    answers = [e for e in events if e.kind in ('answer', 'error')]
    if answers:
        last = answers[-1]
        print()
        print(f'=== FINAL ({last.kind}) ===')
        print((last.detail or '')[:4000])
        break
    time.sleep(POLL)
else:
    print('TIMEOUT — no final answer yet')
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
    print(f'Total events so far: {len(events)}')
    for e in events[-10:]:
        detail = (e.detail or '')[:150]
        print(f'  [{e.kind:12s}] {detail}')
