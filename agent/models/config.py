import uuid
from django.db import models



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
    # Model context window in tokens; drives compaction thresholds. Null → fall
    # back to the built-in default in agent/runtime/model_client.py.
    context_length = models.PositiveIntegerField(null=True, blank=True, default=None)
    retry_policy = models.JSONField(default=dict, blank=True)
    sampling_params = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.id}: {self.model}"


class AgentConfig(models.Model):
    """Analyst-editable overrides for a code-defined agent.

    The agent registry (`agent/agents/registry.py`) supplies the defaults; a row
    here overrides budget and tool policy for that agent at run time. A null field
    means "use the code default", so a row is purely additive.
    """

    agent_name = models.CharField(max_length=64, unique=True)
    max_steps = models.PositiveIntegerField(null=True, blank=True, default=None)
    max_tool_calls = models.PositiveIntegerField(null=True, blank=True, default=None)
    # Override the agent's MCP tool policy (list of provider keys). Null = default.
    tool_policy = models.JSONField(null=True, blank=True, default=None)
    stream_intent = models.BooleanField(null=True, blank=True, default=None)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["agent_name"]

    def __str__(self):
        return f"AgentConfig({self.agent_name})"


class WorkflowConfig(models.Model):
    """Analyst-editable overrides for a code-defined workflow trigger binding."""

    event_type = models.CharField(max_length=64, unique=True)
    enabled = models.BooleanField(default=True)
    dedupe_window = models.PositiveIntegerField(default=600)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["event_type"]

    def __str__(self):
        return f"WorkflowConfig({self.event_type})"


class WorkflowTriggerConfig(models.Model):
    """Analyst-editable webhook that fires a registered workflow binding.

    A trigger exposes a stable webhook URL (`/api/agent/webhooks/<id>/`); the SIEM
    or SOAR is configured to POST its event payload there. Each trigger names the
    provider whose payload shape is expected and the workflow event to dispatch.
    """

    id = models.SlugField(max_length=64, primary_key=True)
    name = models.CharField(max_length=128)
    provider_key = models.CharField(max_length=64)
    event_type = models.CharField(max_length=64)
    enabled = models.BooleanField(default=True)
    dedupe_window = models.PositiveIntegerField(default=600)
    secret = models.CharField(max_length=256, blank=True)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider_key", "event_type", "name"]

    def __str__(self):
        return f"{self.name} ({self.provider_key} → {self.event_type})"


class EscalationRule(models.Model):
    """Analyst-editable verdict → action mapping for automatic workflows."""

    ACTION_AUTO_CLOSE = "auto_close"
    ACTION_AUTO_ESCALATE = "auto_escalate"
    ACTION_HOLD = "hold"
    ACTION_NONE = "none"
    ACTION_CHOICES = [
        (ACTION_AUTO_CLOSE, "Auto-close"),
        (ACTION_AUTO_ESCALATE, "Auto-escalate"),
        (ACTION_HOLD, "Hold for analyst"),
        (ACTION_NONE, "No action"),
    ]

    verdict = models.CharField(max_length=32, unique=True)
    action = models.CharField(max_length=16, choices=ACTION_CHOICES, default=ACTION_HOLD)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["verdict"]

    def __str__(self):
        return f"{self.verdict} → {self.action}"


class RuntimeConfig(models.Model):
    """Singleton for global runtime toggles previously settable only via `.env`.

    Each field is nullable/blank: a null/empty value means "fall back to the
    environment-backed Django setting", so existing `.env`-only deployments keep
    working until an operator overrides a value in the settings UI.
    """

    SINGLETON_ID = 1

    id = models.PositiveSmallIntegerField(primary_key=True, default=SINGLETON_ID, editable=False)
    # None → use settings.WORKFLOWS_ENABLED; True/False → explicit override.
    workflows_enabled = models.BooleanField(null=True, blank=True, default=None)
    # "" → use settings.BASELINE_SIEM_ADAPTER.
    baseline_siem_adapter = models.CharField(max_length=64, blank=True, default="")
    # None → use settings.BASELINE_COMPUTE_INTERVAL_HOURS (applies on next restart).
    baseline_interval_hours = models.PositiveIntegerField(null=True, blank=True, default=None)
    # None/False → off; True → surface all internal tool calls and node transitions.
    debug_mode = models.BooleanField(null=True, blank=True, default=None)
    # None → use settings.TI_CACHE_TTL_HOURS; the shared TI cache entry lifetime.
    ti_cache_ttl_hours = models.PositiveIntegerField(null=True, blank=True, default=None)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.id = self.SINGLETON_ID
        super().save(*args, **kwargs)

    def __str__(self):
        return "runtime config"

