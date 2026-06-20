from django.contrib import admin

from .models import AgentEvent, AgentRun, MCPServerConfig, ModelProviderConfig, ProviderConfig


@admin.register(ProviderConfig)
class ProviderConfigAdmin(admin.ModelAdmin):
    list_display = ("key", "kind", "enabled", "updated_at")
    list_filter = ("kind", "enabled")
    search_fields = ("key",)


@admin.register(AgentRun)
class AgentRunAdmin(admin.ModelAdmin):
    list_display = ("id", "agent_name", "case_id", "status", "trigger", "created_at")
    list_filter = ("agent_name", "status", "trigger")
    search_fields = ("case_id", "id")


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
