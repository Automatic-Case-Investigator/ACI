import sys; sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import os, django, requests
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aci.settings')
django.setup()

BASE = 'http://localhost:8000'
QUESTION = sys.argv[1] if len(sys.argv) > 1 else 'Triage and investigate case ~245862456'

r = requests.post(f'{BASE}/dashboard/ask', data={'question': QUESTION}, allow_redirects=False)
print(f'POST status: {r.status_code}')
loc = r.headers.get('Location', '')
session_id = loc.rstrip('/').split('/')[-1]
print(f'Session ID: {session_id}')
