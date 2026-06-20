from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="dashboard:index", permanent=False)),
    path("admin/", admin.site.urls),
    path("dashboard/", include("agent.dashboard.urls")),
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/agent/", include("agent.urls")),
]
