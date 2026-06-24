from django.contrib import admin
from django.utils import timezone

from .models import (
    AgentConfig,
    AgentEvent,
    AgentRun,
    BaselineComputeConfig,
    BaselineSnapshot,
    BaselineSubjectConfig,
    EscalationRule,
    FeedbackEntry,
    MCPServerConfig,
    ModelProviderConfig,
    PatternCandidate,
    PatternEntry,
    ProviderConfig,
    WorkflowConfig,
    WorkflowTriggerConfig,
)


@admin.register(AgentConfig)
class AgentConfigAdmin(admin.ModelAdmin):
    list_display = ("agent_name", "max_steps", "max_tool_calls", "stream_intent", "updated_at")


@admin.register(WorkflowConfig)
class WorkflowConfigAdmin(admin.ModelAdmin):
    list_display = ("event_type", "enabled", "dedupe_window", "updated_at")


@admin.register(WorkflowTriggerConfig)
class WorkflowTriggerConfigAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "provider_key", "event_type", "enabled", "dedupe_window", "updated_at")
    list_filter = ("provider_key", "enabled")
    search_fields = ("id", "name", "provider_key", "event_type")


@admin.register(EscalationRule)
class EscalationRuleAdmin(admin.ModelAdmin):
    list_display = ("verdict", "action", "updated_at")


@admin.register(ProviderConfig)
class ProviderConfigAdmin(admin.ModelAdmin):
    list_display = ("key", "kind", "enabled", "updated_at")
    list_filter = ("kind", "enabled")
    search_fields = ("key",)


@admin.register(AgentRun)
class AgentRunAdmin(admin.ModelAdmin):
    list_display = ("id", "agent_name", "case_id", "status", "verdict_value", "trigger", "created_at")
    list_filter = ("agent_name", "status", "trigger")
    search_fields = ("case_id", "id")

    @admin.display(description="Verdict")
    def verdict_value(self, obj):
        if isinstance(obj.verdict, dict):
            return obj.verdict.get("verdict", "—")
        return "—"


@admin.register(AgentEvent)
class AgentEventAdmin(admin.ModelAdmin):
    list_display = ("id", "session_id", "source", "kind", "summary", "created_at")
    list_filter = ("source", "kind")
    search_fields = ("session_id", "summary")


@admin.register(MCPServerConfig)
class MCPServerConfigAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "transport", "enabled", "health_status", "updated_at")
    list_filter = ("transport", "enabled", "health_status")
    search_fields = ("id", "name", "command_or_url")


@admin.register(ModelProviderConfig)
class ModelProviderConfigAdmin(admin.ModelAdmin):
    list_display = ("id", "model", "base_url", "tool_calling_mode", "enabled", "updated_at")
    list_filter = ("tool_calling_mode", "enabled")
    search_fields = ("id", "model", "base_url")


# ── Memory layer ───────────────────────────────────────────────────────────────


@admin.register(FeedbackEntry)
class FeedbackEntryAdmin(admin.ModelAdmin):
    list_display = ("id", "case_id", "agent_name", "created_by", "created_at")
    list_filter = ("agent_name",)
    search_fields = ("case_id", "run_id", "created_by")
    readonly_fields = ("created_at",)


@admin.register(PatternEntry)
class PatternEntryAdmin(admin.ModelAdmin):
    list_display = ("name", "verdict", "confidence", "enabled", "owner", "expires_at", "updated_at")
    list_filter = ("verdict", "confidence", "enabled")
    search_fields = ("name", "owner")


def _promote_candidate(candidate: PatternCandidate, reviewer: str) -> PatternEntry:
    """Copy an approved candidate into a live PatternEntry."""
    pattern = PatternEntry.objects.create(
        name=candidate.name,
        verdict=candidate.verdict,
        conditions=candidate.conditions,
        required_evidence=candidate.required_evidence,
        invalidators=candidate.invalidators,
        confidence=candidate.confidence,
        owner=reviewer or candidate.reviewer,
    )
    candidate.status = PatternCandidate.STATUS_APPROVED
    candidate.reviewer = reviewer or candidate.reviewer
    candidate.reviewed_at = timezone.now()
    candidate.promoted_pattern = pattern
    candidate.save(update_fields=["status", "reviewer", "reviewed_at", "promoted_pattern"])
    return pattern


@admin.register(PatternCandidate)
class PatternCandidateAdmin(admin.ModelAdmin):
    list_display = ("name", "verdict", "confidence", "status", "reviewer", "created_at")
    list_filter = ("status", "verdict", "confidence")
    search_fields = ("name",)
    actions = ["approve_candidates", "reject_candidates"]

    @admin.action(description="Approve selected → promote to live pattern")
    def approve_candidates(self, request, queryset):
        reviewer = request.user.get_username()
        promoted = 0
        for candidate in queryset.filter(status=PatternCandidate.STATUS_PENDING):
            _promote_candidate(candidate, reviewer)
            promoted += 1
        self.message_user(request, f"Promoted {promoted} candidate(s) to live patterns.")

    @admin.action(description="Reject selected")
    def reject_candidates(self, request, queryset):
        reviewer = request.user.get_username()
        rejected = queryset.filter(status=PatternCandidate.STATUS_PENDING).update(
            status=PatternCandidate.STATUS_REJECTED,
            reviewer=reviewer,
            reviewed_at=timezone.now(),
        )
        self.message_user(request, f"Rejected {rejected} candidate(s).")


@admin.register(BaselineSnapshot)
class BaselineSnapshotAdmin(admin.ModelAdmin):
    list_display = ("subject_type", "subject_id", "feature", "health", "window_days", "computed_at")
    list_filter = ("subject_type", "health")
    search_fields = ("subject_id", "feature")


@admin.register(BaselineSubjectConfig)
class BaselineSubjectConfigAdmin(admin.ModelAdmin):
    list_display = ("subject_type", "subject_id", "enabled", "updated_at")
    list_filter = ("subject_type", "enabled")
    search_fields = ("subject_id",)


@admin.register(BaselineComputeConfig)
class BaselineComputeConfigAdmin(admin.ModelAdmin):
    list_display = ("id", "window_days", "updated_at")
