import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django, time, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentRun, AgentEvent

RUN_ID = sys.argv[1] if len(sys.argv) > 1 else '11bb8430-5b18-4cd4-bc6a-d68ec9ef7eb2'
MAX_WAIT = int(sys.argv[2]) if len(sys.argv) > 2 else 600
POLL = 10

print(f'Polling investigation run {RUN_ID} for up to {MAX_WAIT}s...')
seen_ids = set()
start = time.time()
while time.time() - start < MAX_WAIT:
    run = AgentRun.objects.filter(id=RUN_ID).first()
    if not run:
        print('Run not found'); break
    events = list(AgentEvent.objects.filter(run_id=RUN_ID).order_by('id'))
    new = [e for e in events if e.id not in seen_ids]
    for e in new:
        seen_ids.add(e.id)
        snippet = (e.detail or '')[:200].replace('\n', ' ')
        print(f'  [{e.kind:12s}] {snippet}')
    if run.status in ('completed', 'failed'):
        print()
        print(f'=== Run {run.status.upper()} ===')
        v = run.verdict
        if v:
            print(f'Verdict: {json.dumps(v, indent=2)}')
        print(f'Result snippet:')
        print((run.result or '')[:3000])
        break
    time.sleep(POLL)
else:
    run = AgentRun.objects.filter(id=RUN_ID).first()
    print(f'TIMEOUT — run status={run.status if run else "?"}')
    events = list(AgentEvent.objects.filter(run_id=RUN_ID).order_by('id'))
    print(f'Total events: {len(events)}')
    for e in events[-8:]:
        detail = (e.detail or '')[:150]
        print(f'  [{e.kind:12s}] {detail}')
