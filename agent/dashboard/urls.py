from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("ask", views.ask, name="ask"),
    path("<uuid:session_id>/", views.session_view, name="session"),
    path("<uuid:session_id>/ask", views.ask_followup, name="ask_followup"),
    path("<uuid:session_id>/delete", views.delete_session, name="delete_session"),
]
