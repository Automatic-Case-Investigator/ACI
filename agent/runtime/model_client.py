from __future__ import annotations

from django.conf import settings
from langchain_openai import ChatOpenAI


def build_model() -> ChatOpenAI:
    cfg = _model_config()
    sampling = cfg.get("sampling_params") or {}
    kwargs = {
        "base_url": cfg["base_url"],
        "api_key": cfg["api_key"],
        "model": cfg["model"],
        "temperature": sampling.get("temperature", settings.LLM_TEMPERATURE),
        "max_tokens": sampling.get("max_tokens", settings.LLM_MAX_TOKENS),
    }
    timeout = _normalize_timeout(cfg.get("timeout"))
    if timeout is not None:
        kwargs["timeout"] = timeout
    return ChatOpenAI(**kwargs)


def _model_config() -> dict:
    defaults = {
        "base_url": settings.LLM_BASE_URL,
        "api_key": settings.LLM_API_KEY,
        "model": settings.LLM_MODEL_NAME,
        "tool_calling_mode": "auto",
        "timeout": _env_timeout(),
        "retry_policy": {},
        "sampling_params": {
            "temperature": settings.LLM_TEMPERATURE,
            "max_tokens": settings.LLM_MAX_TOKENS,
        },
    }
    try:
        from agent.models import ModelProviderConfig

        row = ModelProviderConfig.objects.filter(id="default", enabled=True).first()
    except Exception:
        row = None
    if row is None:
        return defaults
    return {
        "base_url": row.base_url or defaults["base_url"],
        "api_key": row.api_key or defaults["api_key"],
        "model": row.model or defaults["model"],
        "tool_calling_mode": row.tool_calling_mode or defaults["tool_calling_mode"],
        "timeout": row.timeout,
        "retry_policy": row.retry_policy or defaults["retry_policy"],
        "sampling_params": {**defaults["sampling_params"], **(row.sampling_params or {})},
    }


def _env_timeout():
    value = getattr(settings, "LLM_TIMEOUT", None)
    return _normalize_timeout(value)


def _normalize_timeout(value):
    """Return a positive timeout in seconds, or None for no request timeout."""
    if value in (None, "", 0, "0", "none", "None", "null", "NULL", False):
        return None
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return None
    return timeout if timeout > 0 else None
