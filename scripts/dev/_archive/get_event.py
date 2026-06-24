import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()
from agent.models import AgentEvent

EVENT_ID = int(sys.argv[1])
e = AgentEvent.objects.get(id=EVENT_ID)
print(f'Kind: {e.kind}')
print(f'Summary: {e.summary}')
print()
print('Detail:')
print(e.detail or '(empty)')
