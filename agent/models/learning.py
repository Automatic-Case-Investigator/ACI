import uuid
from django.db import models



class FeedbackEntry(models.Model):
    """An analyst correction or confirmation of an agent verdict.

    One entry per run — subsequent submissions update the existing row rather
    than appending a new one. The `updated_at` timestamp reflects the most
    recent analyst change and is used by cross-case feedback queries to surface
    only recent corrections.
    """

    run_id = models.CharField(max_length=64, unique=True)
    case_id = models.CharField(max_length=256, db_index=True)
    agent_name = models.CharField(max_length=64, blank=True)
    original_verdict = models.JSONField(null=True, blank=True, default=None)
    analyst_verdict = models.JSONField(null=True, blank=True, default=None)
    # Structured pivots from the case: {rule_ids, users, hosts, alert_types}.
    # Populated at submission time so future cross-case queries can filter by
    # overlap without re-fetching the original case.
    context = models.JSONField(default=dict, blank=True)
    note = models.TextField(blank=True)
    created_by = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"feedback {self.case_id} ({self.created_by or 'anon'})"


class PatternEntry(models.Model):
    """A reviewed, reusable TP/FP pattern with structured matching logic.

    Promoted from a PatternCandidate after human review. Read by the pattern
    matcher (deterministic, no LLM) and by the aci-memory MCP server.
    """

    VERDICT_TP = "tp"
    VERDICT_FP = "fp"
    VERDICT_CHOICES = [(VERDICT_TP, "True positive"), (VERDICT_FP, "False positive")]

    CONFIDENCE_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High")]

    name = models.CharField(max_length=256)
    verdict = models.CharField(max_length=8, choices=VERDICT_CHOICES, default=VERDICT_FP)
    # conditions: {rule_ids: [], users: [], path_prefixes: [], time_window: "..."}
    conditions = models.JSONField(default=dict, blank=True)
    required_evidence = models.JSONField(default=list, blank=True)
    invalidators = models.JSONField(default=list, blank=True)
    confidence = models.CharField(max_length=8, choices=CONFIDENCE_CHOICES, default="medium")
    owner = models.CharField(max_length=128, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True, default=None)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.name} [{self.verdict}]"


class PatternCandidate(models.Model):
    """A proposed pattern awaiting human review.

    Created from analyst feedback that contradicts an agent verdict. An approved
    candidate is copied into a PatternEntry; nothing here ever matches live until
    that promotion happens.
    """

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending review"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_REJECTED, "Rejected"),
    ]

    name = models.CharField(max_length=256)
    verdict = models.CharField(max_length=8, choices=PatternEntry.VERDICT_CHOICES, default=PatternEntry.VERDICT_FP)
    conditions = models.JSONField(default=dict, blank=True)
    required_evidence = models.JSONField(default=list, blank=True)
    invalidators = models.JSONField(default=list, blank=True)
    confidence = models.CharField(max_length=8, choices=PatternEntry.CONFIDENCE_CHOICES, default="medium")
    source_feedback = models.ForeignKey(
        FeedbackEntry, null=True, blank=True, on_delete=models.SET_NULL, related_name="candidates"
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    reviewer = models.CharField(max_length=128, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True, default=None)
    promoted_pattern = models.ForeignKey(
        PatternEntry, null=True, blank=True, on_delete=models.SET_NULL, related_name="source_candidates"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"candidate {self.name} [{self.status}]"


class BaselineSnapshot(models.Model):
    """A computed behavioral window for one subject + feature.

    e.g. (user, "alice", "active_hours") → {"hours": [8..18]}. Health reflects how
    current/dense the underlying data is, so consumers can discount stale baselines.
    """

    SUBJECT_ENDPOINT = "endpoint"
    SUBJECT_USER = "user"
    SUBJECT_SERVICE = "service"
    SUBJECT_CHOICES = [
        (SUBJECT_ENDPOINT, "Endpoint"),
        (SUBJECT_USER, "User"),
        (SUBJECT_SERVICE, "Service"),
    ]

    HEALTH_FRESH = "fresh"
    HEALTH_STALE = "stale"
    HEALTH_MISSING = "missing"
    HEALTH_LOW_DATA = "low_data"
    HEALTH_CHOICES = [
        (HEALTH_FRESH, "Fresh"),
        (HEALTH_STALE, "Stale"),
        (HEALTH_MISSING, "Missing"),
        (HEALTH_LOW_DATA, "Low data"),
    ]

    subject_type = models.CharField(max_length=16, choices=SUBJECT_CHOICES)
    subject_id = models.CharField(max_length=256)
    feature = models.CharField(max_length=64)
    value = models.JSONField(default=dict, blank=True)
    window_days = models.PositiveIntegerField(default=30)
    health = models.CharField(max_length=16, choices=HEALTH_CHOICES, default=HEALTH_FRESH)
    computed_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["subject_type", "subject_id", "feature"]
        unique_together = [("subject_type", "subject_id", "feature")]
        indexes = [models.Index(fields=["subject_type", "subject_id"])]

    def __str__(self):
        return f"{self.subject_type}:{self.subject_id}/{self.feature} [{self.health}]"


class BaselineComputeConfig(models.Model):
    """Singleton runtime config for baseline computation.

    Persists the operator-chosen lookback window so both the manual "Recompute
    now" action and the nightly scheduler use the same value. Falls back to the
    BASELINE_WINDOW_DAYS setting when no row exists.
    """

    SINGLETON_ID = 1

    id = models.PositiveSmallIntegerField(primary_key=True, default=SINGLETON_ID, editable=False)
    window_days = models.PositiveIntegerField(default=30)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.id = self.SINGLETON_ID
        super().save(*args, **kwargs)

    def __str__(self):
        return f"baseline window: {self.window_days}d"


class BaselineSubjectConfig(models.Model):
    """An operator-selected subject to compute behavioral baselines for.

    When one or more enabled rows exist, baseline computation targets exactly
    these subjects instead of auto-discovering subjects from Wazuh. With no
    rows configured, computation falls back to Wazuh-wide discovery.
    """

    SUBJECT_CHOICES = BaselineSnapshot.SUBJECT_CHOICES

    subject_type = models.CharField(max_length=16, choices=SUBJECT_CHOICES)
    subject_id = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["subject_type", "subject_id"]
        unique_together = [("subject_type", "subject_id")]

    def __str__(self):
        return f"{self.subject_type}:{self.subject_id} ({'on' if self.enabled else 'off'})"

