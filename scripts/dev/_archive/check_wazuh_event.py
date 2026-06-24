"""Check the full content of Wazuh audit alerts to find the hex payload."""
import sys, os, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

# Look at all result events in old session and find one containing actual alert body
SESSION = "ae562e04-c79d-48a4-ae16-ee31042571d1"
events = list(AgentEvent.objects.filter(session_id=SESSION, kind='result').order_by('id'))
hex_payload = "7368202d69"
for e in events:
    detail = str(e.detail or '')
    # Looking for any event that contains the hex payload
    if hex_payload.lower() in detail.lower():
        print(f"=== FOUND HEX IN EVENT (id={e.id}) ===")
        print(detail[:3000])
        print()
        break

print("Checking all result events for 'crontab' and 'audit.execve' ...")
for e in events:
    detail = str(e.detail or '')
    if ('"execve"' in detail or 'syscheck.diff' in detail or 'diff' in detail.lower()) and 'crontab' in detail.lower():
        print(f"\n=== Event id={e.id} ===")
        print(detail[:2000])
        break
