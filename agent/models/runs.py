import uuid
from django.db import models



class AgentRun(models.Model):
    STATUS_CREATED = "created"
    STATUS_QUEUED = "queued"
    STATUS_RUNNING = "running"
    STATUS_WAITING = "waiting"
    STATUS_COMPLETED = "completed"
    STATUS_INCOMPLETE_BUDGET = "incomplete_budget"
    STATUS_CANCELLED = "cancelled"
    STATUS_BLOCKED = "blocked"
    STATUS_FAILED = "failed"

    STATUS_CHOICES = [
        (STATUS_CREATED, "Created"),
        (STATUS_QUEUED, "Queued"),
        (STATUS_RUNNING, "Running"),
        (STATUS_WAITING, "Waiting"),
        (STATUS_COMPLETED, "Completed"),
        (STATUS_INCOMPLETE_BUDGET, "Incomplete — budget exhausted"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_BLOCKED, "Blocked"),
        (STATUS_FAILED, "Failed"),
    ]

    # How this run was initiated. `interactive` = analyst via dashboard; `auto` =
    # fired by a workflow binding (new case/alert); `scheduled` = future cron-style.
    TRIGGER_INTERACTIVE = "interactive"
    TRIGGER_AUTO = "auto"
    TRIGGER_SCHEDULED = "scheduled"
    TRIGGER_CHOICES = [
        (TRIGGER_INTERACTIVE, "Interactive"),
        (TRIGGER_AUTO, "Automatic (workflow)"),
        (TRIGGER_SCHEDULED, "Scheduled"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case_id = models.CharField(max_length=256)
    agent_name = models.CharField(max_length=64)
    question = models.TextField()
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_CREATED)
    trigger = models.CharField(max_length=16, choices=TRIGGER_CHOICES, default=TRIGGER_INTERACTIVE)
    result = models.TextField(blank=True)
    error = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    # Structured diagnosis contract (TP/FP/inconclusive/needs_investigation) parsed
    # from the agent's final message. Null until a run produces a parseable verdict.
    verdict = models.JSONField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.agent_name}/{self.case_id} [{self.status}]"


class AgentEvent(models.Model):
    """A single structured log event (from logbus) persisted for the live dashboard.

    Grouped by `session_id` (the orchestrator AgentRun id that one analyst question
    maps to). `seq` is logbus's process-wide monotonic counter, kept for display;
    DB insertion order (auto `id`) is the canonical stream order used for tailing.
    `detail` holds the full, untruncated payload — nothing is redacted.
    """

    session_id = models.CharField(max_length=64, db_index=True)
    run_id = models.CharField(max_length=64, blank=True)
    seq = models.BigIntegerField(default=0)
    source = models.CharField(max_length=16)
    kind = models.CharField(max_length=16)
    summary = models.TextField()
    detail = models.TextField(blank=True)
    expand = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
        indexes = [models.Index(fields=["session_id", "id"])]

    def __str__(self):
        return f"[{self.source}/{self.kind}] {self.summary[:60]}"

