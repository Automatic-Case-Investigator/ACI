"""ASGI entry point.

HTTP is served by Django as usual; WebSocket connections (the live dashboard log)
are routed to Channels consumers. Keep `get_asgi_application()` first so Django is
fully set up before importing anything that touches models/consumers.
"""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci_backend.settings")

# Initialise Django (populates the app registry) before importing consumers.
django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from channels.security.websocket import AllowedHostsOriginValidator  # noqa: E402

from agent.dashboard.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(URLRouter(websocket_urlpatterns)),
    }
)
