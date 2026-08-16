from __future__ import annotations

"""Every HTTP route in one place: the dashboard pages and the REST API.

Two lists rather than one, because they mount at different prefixes and only the
dashboard carries a URL namespace (`dashboard:index` is reversed from templates and
from `aci/urls.py`). `aci/urls.py` includes each list at its own prefix.
"""

from django.urls import path

from .views import settings as settings_views
from .views.dashboard import pages as dashboard_pages
from .views.dashboard import stats as dashboard_stats
from .views.runs import active as runs_active
from .views.runs import api as runs_api
from .views.runs import pages as runs_pages
from .views.webhooks import api as webhooks_api

app_name = "dashboard"

# Server-rendered dashboard, mounted at /dashboard/ under the "dashboard" namespace.
dashboard_urlpatterns = [
    path("", dashboard_pages.index, name="index"),
    path("ask", dashboard_pages.ask, name="ask"),
    path("settings/", settings_views.settings_view, name="settings"),
    path(
        "settings/model", settings_views.settings_model_save, name="settings_model_save"
    ),
    path(
        "settings/connection/save",
        settings_views.settings_connection_save,
        name="settings_connection_save",
    ),
    path(
        "settings/connection/activate",
        settings_views.settings_connection_activate,
        name="settings_connection_activate",
    ),
    path(
        "settings/connection/delete",
        settings_views.settings_connection_delete,
        name="settings_connection_delete",
    ),
    path(
        "settings/connection/test",
        settings_views.settings_connection_test,
        name="settings_connection_test",
    ),
    path(
        "settings/runtime",
        settings_views.settings_runtime_save,
        name="settings_runtime_save",
    ),
    path(
        "settings/provider",
        settings_views.settings_provider_toggle,
        name="settings_provider_toggle",
    ),
    path(
        "settings/agent", settings_views.settings_agent_save, name="settings_agent_save"
    ),
    path(
        "settings/workflow",
        settings_views.settings_workflow_save,
        name="settings_workflow_save",
    ),
    path(
        "settings/trigger/save",
        settings_views.settings_trigger_save,
        name="settings_trigger_save",
    ),
    path(
        "settings/trigger/toggle",
        settings_views.settings_trigger_toggle,
        name="settings_trigger_toggle",
    ),
    path(
        "settings/trigger/delete",
        settings_views.settings_trigger_delete,
        name="settings_trigger_delete",
    ),
    path(
        "settings/response-policy",
        settings_views.settings_response_policy_save,
        name="settings_response_policy_save",
    ),
    path(
        "settings/response-policy/reset",
        settings_views.settings_response_policy_reset,
        name="settings_response_policy_reset",
    ),
    path(
        "settings/mcp/save", settings_views.settings_mcp_save, name="settings_mcp_save"
    ),
    path(
        "settings/mcp/delete",
        settings_views.settings_mcp_delete,
        name="settings_mcp_delete",
    ),
    path(
        "settings/ti/cache/stats",
        settings_views.settings_ti_cache_stats,
        name="settings_ti_cache_stats",
    ),
    path(
        "settings/ti/cache/clear",
        settings_views.settings_ti_cache_clear,
        name="settings_ti_cache_clear",
    ),
    path(
        "settings/baseline/save",
        settings_views.settings_baseline_subject_save,
        name="settings_baseline_subject_save",
    ),
    path(
        "settings/baseline/toggle",
        settings_views.settings_baseline_subject_toggle,
        name="settings_baseline_subject_toggle",
    ),
    path(
        "settings/baseline/delete",
        settings_views.settings_baseline_subject_delete,
        name="settings_baseline_subject_delete",
    ),
    path(
        "settings/baseline/window",
        settings_views.settings_baseline_window_save,
        name="settings_baseline_window_save",
    ),
    path(
        "settings/baseline/recompute",
        settings_views.settings_baseline_recompute,
        name="settings_baseline_recompute",
    ),
    path("runs/", runs_pages.runs_view, name="runs"),
    path("runs/stop-all", runs_pages.runs_stop_all, name="runs_stop_all"),
    path("runs/delete-all", runs_pages.runs_delete_all, name="runs_delete_all"),
    path(
        "runs/delete-selected",
        runs_pages.runs_delete_selected,
        name="runs_delete_selected",
    ),
    path(
        "sessions/delete-selected",
        dashboard_pages.delete_sessions_selected,
        name="delete_sessions_selected",
    ),
    path("runs/<uuid:run_id>/detail", runs_pages.run_detail, name="run_detail"),
    path("runs/<uuid:run_id>/review", runs_pages.run_review, name="run_review"),
    path(
        "runs/<uuid:run_id>/investigate",
        runs_pages.run_investigate,
        name="run_investigate",
    ),
    path("runs/<uuid:run_id>/restart", runs_pages.run_restart, name="run_restart"),
    path("runs/<uuid:run_id>/stop", runs_pages.run_stop, name="run_stop"),
    path("runs/<uuid:run_id>/delete", runs_pages.run_delete, name="run_delete"),
    path("<uuid:session_id>/", dashboard_pages.session_view, name="session"),
    path("<uuid:session_id>/ask", dashboard_pages.ask_followup, name="ask_followup"),
    path("<uuid:session_id>/delete", dashboard_pages.delete_session, name="delete_session"),
]

# JSON API for programmatic clients and inbound webhooks, mounted at /api/agent/.
api_urlpatterns = [
    path("runs/", runs_api.AgentRunView.as_view(), name="agent_run_create"),
    path(
        "runs/<uuid:run_id>/",
        runs_api.AgentRunDetailView.as_view(),
        name="agent_run_detail",
    ),
    path(
        "runs/<uuid:run_id>/status/",
        runs_api.AgentRunStatusView.as_view(),
        name="agent_run_status",
    ),
    path(
        "runs/<uuid:run_id>/events/",
        runs_api.AgentRunEventsView.as_view(),
        name="agent_run_events",
    ),
    path(
        "runs/<uuid:run_id>/cancel/",
        runs_api.AgentRunCancelView.as_view(),
        name="agent_run_cancel",
    ),
    path(
        "runs/<uuid:run_id>/resume/",
        runs_api.AgentRunResumeView.as_view(),
        name="agent_run_resume",
    ),
    path(
        "runs/<uuid:run_id>/restart/",
        runs_api.AgentRunRestartView.as_view(),
        name="agent_run_restart",
    ),
    path(
        "runs/<uuid:run_id>/feedback/",
        runs_api.AgentRunFeedbackView.as_view(),
        name="agent_run_feedback",
    ),
    path(
        "webhooks/thehive/", webhooks_api.TheHiveWebhookView.as_view(), name="thehive_webhook"
    ),
    path(
        "webhooks/<slug:trigger_id>/",
        webhooks_api.ConfiguredWebhookView.as_view(),
        name="configured_webhook",
    ),
    path("stats/verdicts/", dashboard_stats.VerdictStatsView.as_view(), name="verdict_stats"),
    path("runs/active/", runs_active.ActiveRunsView.as_view(), name="active_runs"),
    path(
        "cases/<str:case_id>/queues/<str:agent_name>/tasks/",
        runs_api.CaseQueueTasksView.as_view(),
        name="case_queue_tasks",
    ),
    path(
        "cases/<str:case_id>/workspace/",
        runs_api.CaseWorkspaceView.as_view(),
        name="case_workspace",
    ),
    path(
        "cases/<str:case_id>/reports/latest/",
        runs_api.CaseLatestReportView.as_view(),
        name="case_latest_report",
    ),
]

# `include("agent.web.urls")` resolves `urlpatterns`; that is the dashboard.
urlpatterns = dashboard_urlpatterns
