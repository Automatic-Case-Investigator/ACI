from __future__ import annotations

from langchain_openai import ChatOpenAI

# Built-in fallback for the model provider. The database row
# (`ModelProviderConfig`, edited in Settings → Model provider) is the source of
# truth at run time; these values only apply when no row exists yet. Model
# configuration lives entirely in the settings UI — not in Django settings/.env.
DEFAULTS = {
    "base_url": "http://localhost:11434/v1",
    "api_key": "ollama",
    "model": "llama3.2",
    "tool_calling_mode": "auto",
    "timeout": None,
    "context_length": 131072,
    "retry_policy": {},
    "sampling_params": {
        "temperature": 0,
        "max_tokens": 4096,
    },
}


def _is_reasoning_model(model_name: str) -> bool:
    """OpenAI o-series reasoning models don't accept temperature != 1."""
    name = (model_name or "").lower()
    return name.startswith(("o1", "o3", "o4"))


async def build_model() -> ChatOpenAI:
    cfg = await _model_config()

    sampling = cfg.get("sampling_params") or {}
    model_name = cfg["model"]

    kwargs = {
        "base_url": cfg["base_url"],
        "api_key": cfg["api_key"],
        "model": model_name,
        "max_tokens": sampling.get(
            "max_tokens",
            DEFAULTS["sampling_params"]["max_tokens"],
        ),
        # Most dashboard-visible model calls stream. Ask OpenAI-compatible
        # providers to include usage in the stream so the context wheel can show
        # the active agent's real prompt-token count instead of staying empty.
        "stream_usage": True,
    }

    # Reasoning models (o1/o3/o4 family) reject temperature != 1; omit it so
    # the provider uses its default. Non-reasoning models default to 0.
    if not _is_reasoning_model(model_name):
        kwargs["temperature"] = sampling.get(
            "temperature",
            DEFAULTS["sampling_params"]["temperature"],
        )

    timeout = _normalize_timeout(cfg.get("timeout"))
    if timeout is not None:
        kwargs["timeout"] = timeout

    return ChatOpenAI(**kwargs)


async def model_context_length() -> int:
    """Effective model context window in tokens (from ModelProviderConfig)."""

    cfg = await _model_config()

    try:
        value = int(cfg.get("context_length"))
    except (TypeError, ValueError):
        value = 0

    return value if value > 0 else int(DEFAULTS["context_length"])


def model_context_length_sync() -> int:
    """Sync variant — safe for sync helpers (e.g. _should_compact) called in any context."""
    try:
        from agent.models import ModelProviderConfig

        row = ModelProviderConfig.objects.filter(id="default", enabled=True).first()
        value = int(row.context_length or 0) if row else 0
    except Exception:
        value = 0
    return value if value > 0 else int(DEFAULTS["context_length"])


async def _model_config() -> dict:
    defaults = {
        **DEFAULTS,
        "sampling_params": dict(DEFAULTS["sampling_params"]),
    }

    try:
        from agent.models import ModelProviderConfig

        row = await ModelProviderConfig.objects.filter(
            id="default",
            enabled=True,
        ).afirst()

    except Exception as e:
        print(f"ModelProviderConfig lookup unavailable; using defaults: {e}")
        row = None

    if row is None:
        return defaults

    return {
        "base_url": row.base_url or defaults["base_url"],
        "api_key": row.api_key or defaults["api_key"],
        "model": row.model or defaults["model"],
        "tool_calling_mode": row.tool_calling_mode
        or defaults["tool_calling_mode"],
        "timeout": row.timeout,
        "context_length": row.context_length
        or defaults["context_length"],
        "retry_policy": row.retry_policy
        or defaults["retry_policy"],
        "sampling_params": {
            **defaults["sampling_params"],
            **(row.sampling_params or {}),
        },
    }


def _normalize_timeout(value):
    """Return a positive timeout in seconds, or None for no request timeout."""

    if value in (
        None,
        "",
        0,
        "0",
        "none",
        "None",
        "null",
        "NULL",
        False,
    ):
        return None

    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return None

    return timeout if timeout > 0 else None