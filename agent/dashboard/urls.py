from django.urls import path

from . import views
from . import runs_views
from . import settings_views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("ask", views.ask, name="ask"),
    path("settings/", settings_views.settings_view, name="settings"),
    path("settings/model", settings_views.settings_model_save, name="settings_model_save"),
    path("settings/connection/save", settings_views.settings_connection_save, name="settings_connection_save"),
    path("settings/connection/test", settings_views.settings_connection_test, name="settings_connection_test"),
    path("settings/runtime", settings_views.settings_runtime_save, name="settings_runtime_save"),
    path("settings/provider", settings_views.settings_provider_toggle, name="settings_provider_toggle"),
    path("settings/agent", settings_views.settings_agent_save, name="settings_agent_save"),
    path("settings/workflow", settings_views.settings_workflow_save, name="settings_workflow_save"),
    path("settings/trigger/save", settings_views.settings_trigger_save, name="settings_trigger_save"),
    path("settings/trigger/toggle", settings_views.settings_trigger_toggle, name="settings_trigger_toggle"),
    path("settings/trigger/delete", settings_views.settings_trigger_delete, name="settings_trigger_delete"),
    path("settings/escalation", settings_views.settings_escalation_save, name="settings_escalation_save"),
    path("settings/mcp/save", settings_views.settings_mcp_save, name="settings_mcp_save"),
    path("settings/mcp/delete", settings_views.settings_mcp_delete, name="settings_mcp_delete"),
    path("settings/ti/cache/stats", settings_views.settings_ti_cache_stats, name="settings_ti_cache_stats"),
    path("settings/ti/cache/clear", settings_views.settings_ti_cache_clear, name="settings_ti_cache_clear"),
    path("settings/baseline/save", settings_views.settings_baseline_subject_save, name="settings_baseline_subject_save"),
    path("settings/baseline/toggle", settings_views.settings_baseline_subject_toggle, name="settings_baseline_subject_toggle"),
    path("settings/baseline/delete", settings_views.settings_baseline_subject_delete, name="settings_baseline_subject_delete"),
    path("settings/baseline/window", settings_views.settings_baseline_window_save, name="settings_baseline_window_save"),
    path("settings/baseline/recompute", settings_views.settings_baseline_recompute, name="settings_baseline_recompute"),
    path("runs/", runs_views.runs_view, name="runs"),
    path("runs/stop-all", runs_views.runs_stop_all, name="runs_stop_all"),
    path("runs/delete-all", runs_views.runs_delete_all, name="runs_delete_all"),
    path("runs/<uuid:run_id>/review", runs_views.run_review, name="run_review"),
    path("runs/<uuid:run_id>/investigate", runs_views.run_investigate, name="run_investigate"),
    path("runs/<uuid:run_id>/restart", runs_views.run_restart, name="run_restart"),
    path("runs/<uuid:run_id>/stop", runs_views.run_stop, name="run_stop"),
    path("runs/<uuid:run_id>/delete", runs_views.run_delete, name="run_delete"),
    path("<uuid:session_id>/", views.session_view, name="session"),
    path("<uuid:session_id>/ask", views.ask_followup, name="ask_followup"),
    path("<uuid:session_id>/delete", views.delete_session, name="delete_session"),
]
