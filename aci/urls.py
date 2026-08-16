from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from agent.web.urls import api_urlpatterns, dashboard_urlpatterns

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="dashboard:index", permanent=False)),
    path("admin/", admin.site.urls),
    # Both lists come from the single `agent/web/urls.py`; only the dashboard is
    # namespaced, so the API keeps flat route names (`reverse("agent_run_create")`).
    path("dashboard/", include((dashboard_urlpatterns, "dashboard"))),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/agent/", include(api_urlpatterns)),
]
