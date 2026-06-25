import os

from django.db import migrations


def _timeout():
    raw = (os.environ.get("LLM_TIMEOUT", "") or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def _float(name, default):
    try:
        return float(os.environ.get(name, default) or default)
    except (TypeError, ValueError):
        return float(default)


def _int(name, default):
    try:
        return int(os.environ.get(name, default) or default)
    except (TypeError, ValueError):
        return int(default)


def seed_default(apps, schema_editor):
    """Migrate model provider config out of `.env` into the database.

    Reads the legacy LLM_* environment variables (if still set) so an existing
    deployment carries its configuration into the settings UI. Skips if a row
    already exists so operator edits are never clobbered.
    """
    ModelProviderConfig = apps.get_model("agent", "ModelProviderConfig")
    if ModelProviderConfig.objects.filter(id="default").exists():
        return
    ModelProviderConfig.objects.create(
        id="default",
        base_url=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.environ.get("LLM_API_KEY", "ollama"),
        model=os.environ.get("LLM_MODEL_NAME", "llama3.2"),
        tool_calling_mode="auto",
        timeout=_timeout(),
        context_length=_int("LLM_CONTEXT_LENGTH", 131072),
        retry_policy={},
        sampling_params={
            "temperature": _float("LLM_TEMPERATURE", 0),
            "max_tokens": _int("LLM_MAX_TOKENS", 4096),
        },
        enabled=True,
    )


def unseed(apps, schema_editor):
    # No-op: keep operator-edited config on reverse.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("agent", "0019_modelproviderconfig_context_length"),
    ]

    operations = [
        migrations.RunPython(seed_default, unseed),
    ]
