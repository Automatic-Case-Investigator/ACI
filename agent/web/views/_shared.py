from __future__ import annotations

"""Base classes shared by the view packages."""

from rest_framework.permissions import AllowAny
from rest_framework.views import APIView


class PublicAPIView(APIView):
    """APIView reachable without authentication.

    The deployment is a local no-login console (see `views/dashboard/pages.py`): the
    server-rendered dashboard and the SIEM/SOAR webhooks call these endpoints with
    no JWT, so they opt out of the global `IsAuthenticated` default. Endpoints that
    are only for authenticated API clients keep the default and subclass `APIView`.
    """

    authentication_classes: list = []
    permission_classes = [AllowAny]
