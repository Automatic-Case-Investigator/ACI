import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

SESSION = '02e9d828-bee8-4844-bdaa-3e2a36abd4a8'
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))
print(f"Total events: {len(events)}")

# Find all 80792 query results
for e in events:
    if e.source == 'inv' and e.kind == 'result' and '80792' in str(e.detail or ''):
        detail = str(e.detail or '')
        ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
        print(f"\n[{ts}] 80792 result snippet:")
        print(detail[:1500])

# Check board
try:
    from aci_board import store as board_store
    run_id = '60908c30-6cd3-4cc6-8743-057eab0d7260'
    entries = board_store.list_entries('~41893984', run_id, 'investigation')
    print(f"\nBoard ({len(entries)} entries):")
    for e in entries:
        print(f"  [{e['kind']:10s}|{e.get('confidence',''):6s}] {e['content'][:150]}")
except Exception as ex:
    print(f"\nBoard error: {ex}")
