import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent

# Look for the tool result that returned alert ~43516000 in the new session
SESSION = "483e7384-8ce5-43f0-b681-e951702366d6"
events = list(AgentEvent.objects.filter(session_id=SESSION, kind='result').order_by('id'))
for e in events:
    detail = str(e.detail or '')
    if '43516000' in detail and len(detail) > 50:
        print(f"=== Alert ~43516000 result ===")
        print(detail[:3000])
        print()
