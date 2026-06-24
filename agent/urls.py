from django.urls import path
from . import views

urlpatterns = [
    path("runs/", views.AgentRunView.as_view(), name="agent_run_create"),
    path("runs/<uuid:run_id>/", views.AgentRunDetailView.as_view(), name="agent_run_detail"),
    path("runs/<uuid:run_id>/status/", views.AgentRunStatusView.as_view(), name="agent_run_status"),
    path("runs/<uuid:run_id>/events/", views.AgentRunEventsView.as_view(), name="agent_run_events"),
    path("runs/<uuid:run_id>/cancel/", views.AgentRunCancelView.as_view(), name="agent_run_cancel"),
    path("runs/<uuid:run_id>/resume/", views.AgentRunResumeView.as_view(), name="agent_run_resume"),
    path("runs/<uuid:run_id>/restart/", views.AgentRunRestartView.as_view(), name="agent_run_restart"),
    path("runs/<uuid:run_id>/feedback/", views.AgentRunFeedbackView.as_view(), name="agent_run_feedback"),
    path("webhooks/thehive/", views.TheHiveWebhookView.as_view(), name="thehive_webhook"),
    path("webhooks/<slug:trigger_id>/", views.ConfiguredWebhookView.as_view(), name="configured_webhook"),
    path("stats/verdicts/", views.VerdictStatsView.as_view(), name="verdict_stats"),
    path("runs/active/", views.ActiveRunsView.as_view(), name="active_runs"),
    path("cases/<str:case_id>/queues/<str:agent_name>/tasks/", views.CaseQueueTasksView.as_view(), name="case_queue_tasks"),
    path("cases/<str:case_id>/workspace/", views.CaseWorkspaceView.as_view(), name="case_workspace"),
    path("cases/<str:case_id>/reports/latest/", views.CaseLatestReportView.as_view(), name="case_latest_report"),
]
