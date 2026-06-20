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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.agent_name}/{self.case_id} [{self.status}]"


class ProviderConfig(models.Model):
    """DB-backed connection settings for one MCP provider (SOAR / SIEM / utility).

    Resolved by `runtime/config.py`, which merges `settings` over the provider's
    env-backed defaults. Editable in Django admin today; the settings UI binds here
    next. Absence of a row means "use env defaults, enabled" — so this table is
    purely additive and existing deployments need no rows.
    """

    KIND_SOAR = "soar"
    KIND_SIEM = "siem"
    KIND_UTILITY = "utility"
    KIND_FILESYSTEM = "filesystem"
    KIND_CHOICES = [
        (KIND_SOAR, "SOAR"),
        (KIND_SIEM, "SIEM"),
        (KIND_UTILITY, "Utility"),
        (KIND_FILESYSTEM, "Filesystem"),
    ]

    key = models.CharField(max_length=64, unique=True)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default=KIND_UTILITY)
    enabled = models.BooleanField(default=True)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self):
        return f"{self.key} ({'enabled' if self.enabled else 'disabled'})"


class MCPServerConfig(models.Model):
    """Operator-editable MCP server registration.

    The runtime still loads built-in providers from `agent.runtime.providers`.
    This model is the durable public contract for adding external MCP servers
    without changing the core runner.
    """

    TRANSPORT_STDIO = "stdio"
    TRANSPORT_HTTP = "http"
    TRANSPORT_CHOICES = [
        (TRANSPORT_STDIO, "stdio"),
        (TRANSPORT_HTTP, "http"),
    ]

    HEALTH_UNKNOWN = "unknown"
    HEALTH_HEALTHY = "healthy"
    HEALTH_DEGRADED = "degraded"
    HEALTH_ERROR = "error"
    HEALTH_CHOICES = [
        (HEALTH_UNKNOWN, "Unknown"),
        (HEALTH_HEALTHY, "Healthy"),
        (HEALTH_DEGRADED, "Degraded"),
        (HEALTH_ERROR, "Error"),
    ]

    id = models.CharField(max_length=64, primary_key=True)
    name = models.CharField(max_length=128)
    transport = models.CharField(max_length=16, choices=TRANSPORT_CHOICES)
    command_or_url = models.TextField()
    env = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    health_status = models.CharField(max_length=16, choices=HEALTH_CHOICES, default=HEALTH_UNKNOWN)
    allowed_agents = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.id} ({self.transport})"


class ModelProviderConfig(models.Model):
    """OpenAI-compatible model provider settings."""

    TOOL_CALLING_AUTO = "auto"
    TOOL_CALLING_NATIVE = "native"
    TOOL_CALLING_NONE = "none"
    TOOL_CALLING_CHOICES = [
        (TOOL_CALLING_AUTO, "Auto"),
        (TOOL_CALLING_NATIVE, "Native"),
        (TOOL_CALLING_NONE, "None"),
    ]

    id = models.CharField(max_length=64, primary_key=True, default="default")
    base_url = models.URLField()
    api_key = models.CharField(max_length=512, blank=True)
    model = models.CharField(max_length=256)
    tool_calling_mode = models.CharField(max_length=16, choices=TOOL_CALLING_CHOICES, default=TOOL_CALLING_AUTO)
    timeout = models.PositiveIntegerField(null=True, blank=True, default=None)
    retry_policy = models.JSONField(default=dict, blank=True)
    sampling_params = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.id}: {self.model}"


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
