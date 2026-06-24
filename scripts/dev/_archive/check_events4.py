import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
import django; django.setup()
from agent.models import AgentEvent
SESSION = "ae562e04-c79d-48a4-ae16-ee31042571d1"
total = AgentEvent.objects.filter(session_id=SESSION).count()
print(f"total events: {total}")
latest = AgentEvent.objects.filter(session_id=SESSION).order_by('-id').first()
if latest:
    print(f"latest at: {latest.created_at}")
