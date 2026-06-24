import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

SESSION = "483e7384-8ce5-43f0-b681-e951702366d6"
events = list(AgentEvent.objects.filter(session_id=SESSION).order_by('id'))
total = len(events)
print(f"total: {total}")
# Only show inv events
inv_events = [e for e in events if e.source == 'inv']
print(f"inv events: {len(inv_events)}")
for e in inv_events[-20:]:
    ts = e.created_at.strftime('%H:%M:%S') if e.created_at else ''
    detail = str(e.detail or '')[:200]
    print(f'[{ts}] {e.source:6s} {e.kind:12s} | {detail}')
# Check board
try:
    from aci_board import store as board_store
    entries = board_store.list_entries('~41893984', '81f24965-4b1a-4095-b1c9-7fde0fa8f96a', 'investigation')
    if entries:
        print(f"\nBoard ({len(entries)} entries):")
        for e in entries:
            print(f"  [{e['kind']:10s}|{e.get('confidence',''):6s}] {e['content'][:100]}")
    else:
        print("\nBoard: empty")
except Exception as ex:
    print(f"\nBoard error: {ex}")
