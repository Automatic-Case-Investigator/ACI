import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django, time, requests
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentEvent

BASE = 'http://localhost:8000'
SESSION_ID = sys.argv[1] if len(sys.argv) > 1 else '08330bd0-c50a-405b-977f-bf943f7c069b'
QUESTION = sys.argv[2] if len(sys.argv) > 2 else 'investigate this case'
MAX_WAIT = int(sys.argv[3]) if len(sys.argv) > 3 else 420

print(f'Submitting follow-up to session {SESSION_ID}: {QUESTION!r}')
r = requests.post(f'{BASE}/dashboard/{SESSION_ID}/ask', data={'question': QUESTION}, allow_redirects=False)
print(f'POST status: {r.status_code} location: {r.headers.get("Location","none")}')

print(f'Polling up to {MAX_WAIT}s...')
seen_ids = set()
# Pre-populate seen_ids with events before the submission
for e in AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'):
    seen_ids.add(e.id)
print(f'  (skipping {len(seen_ids)} pre-existing events)')

start = time.time()
while time.time() - start < MAX_WAIT:
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
    new = [e for e in events if e.id not in seen_ids]
    for e in new:
        seen_ids.add(e.id)
        snippet = (e.detail or '')[:200].replace('\n', ' ')
        print(f'  [{e.kind:12s}] {snippet}')
    answers = [e for e in events if e.id in [x.id for x in new] and e.kind in ('answer', 'error')]
    if answers:
        last = answers[-1]
        print()
        print(f'=== FINAL ({last.kind}) ===')
        print((last.detail or '')[:4000])
        break
    time.sleep(10)
else:
    print('TIMEOUT')
    events = list(AgentEvent.objects.filter(session_id=SESSION_ID).order_by('id'))
    for e in events[-10:]:
        detail = (e.detail or '')[:150]
        print(f'  [{e.kind:12s}] {detail}')
