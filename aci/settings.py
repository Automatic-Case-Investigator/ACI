import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
DEBUG = os.environ.get("DEBUG", "true").lower() == "true"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",")]

# "daphne" must precede staticfiles so its ASGI runserver takes over (Channels).
INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "channels",
    "django_cotton",
    "rest_framework",
    "rest_framework_simplejwt",
    "agent",
]

# Admin (used to edit ProviderConfig — the settings UI binds here next sprint)
# needs sessions/auth/messages middleware in addition to the base two.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "aci.urls"
WSGI_APPLICATION = "aci.wsgi.application"
ASGI_APPLICATION = "aci.asgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# django-cotton (v2) auto-wraps the loaders + builtins from this TEMPLATES entry.
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

# Live agent log uses WebSockets. InMemory layer is per-process: fine for local
# runserver; use a Redis layer (channels-redis) for multi-worker deployments.
CHANNEL_LAYERS = {
    "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"},
}

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

USE_TZ = True
TIME_ZONE = "UTC"

# ── LLM (OpenAI-compatible) ───────────────────────────────────────────────────
# Model provider settings (base URL, API key, model name, sampling params,
# context length, request timeout) live in the database (`ModelProviderConfig`)
# and are edited in Settings → Model provider. Built-in defaults and the
# resolution logic are in agent/runtime/model_client.py.
# Comma-separated agent names that should spend an extra LLM call before each
# action to produce dashboard-visible progress narration. Keep investigation off
# by default because tool-heavy investigations are latency-sensitive.
PUBLIC_INTENT_AGENTS = {
    item.strip()
    for item in os.environ.get("PUBLIC_INTENT_AGENTS", "triage").split(",")
    if item.strip()
}

# ── AVFS ──────────────────────────────────────────────────────────────────────
AVFS_URL = os.environ.get("AVFS_URL", "http://127.0.0.1:8765/")
AVFS_AUTH_TOKEN = os.environ.get("AVFS_AUTH_TOKEN", "change-me-avfs-token")
AVFS_AGENT_ID = os.environ.get("AVFS_AGENT_ID", "agent_1")

# ── Baselines ────────────────────────────────────────────────────────────────
# Which SIEM adapter computes behavioral baselines. Must match a registered
# adapter name in agent/runtime/baseline_adapters/ (e.g. "wazuh").
BASELINE_SIEM_ADAPTER = os.environ.get("BASELINE_SIEM_ADAPTER", "wazuh")
# Lookback window and scheduler cadence for the in-process baseline thread.
BASELINE_WINDOW_DAYS = int(os.environ.get("BASELINE_WINDOW_DAYS", "30"))
BASELINE_COMPUTE_INTERVAL_HOURS = int(os.environ.get("BASELINE_COMPUTE_INTERVAL_HOURS", "24"))


# ── Task queue (passed to aci-taskqueue subprocess as env) ───────────────────
TASKQUEUE_DB_PATH = os.environ.get("TASKQUEUE_DB_PATH", str(BASE_DIR / "taskqueue.db"))

# ── Fact/hypothesis board (passed to aci-board subprocess as env) ─────────────
BOARD_DB_PATH = os.environ.get("BOARD_DB_PATH", str(BASE_DIR / "board.db"))

# ── Threat Intelligence (TI) enrichment ──────────────────────────────────────
# Settings UI (ProviderConfig for "aci-ti") overrides these env-backed defaults.
VT_API_KEY               = os.environ.get("VT_API_KEY", "")
VT_BASE_URL              = os.environ.get("VT_BASE_URL", "https://www.virustotal.com")
TI_CACHE_DB_PATH         = os.environ.get("TI_CACHE_DB_PATH", str(BASE_DIR / "ti_cache.db"))
TI_CACHE_TTL_HOURS       = int(os.environ.get("TI_CACHE_TTL_HOURS", "24"))
TI_CALLS_PER_MINUTE      = int(os.environ.get("TI_CALLS_PER_MINUTE", "4"))

# ── Automatic workflows (C4 trigger seam) ────────────────────────────────────
# Off by default: only the manual `run_workflow` management command honours this
# until real event ingestion (webhooks/pollers) lands.
WORKFLOWS_ENABLED = os.environ.get("WORKFLOWS_ENABLED", "false").lower() == "true"
