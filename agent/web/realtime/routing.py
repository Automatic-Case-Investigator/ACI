from django.urls import re_path

from .consumers import RunConsumer

websocket_urlpatterns = [
    re_path(r"^ws/runs/(?P<session_id>[^/]+)/$", RunConsumer.as_asgi()),
]
