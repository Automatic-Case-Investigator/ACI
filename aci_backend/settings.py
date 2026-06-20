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

ROOT_URLCONF = "aci_backend.urls"
WSGI_APPLICATION = "aci_backend.wsgi.application"
ASGI_APPLICATION = "aci_backend.asgi.application"
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
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "ollama")
LLM_MODEL_NAME = os.environ.get("LLM_MODEL_NAME", "llama3.2")
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0"))
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "4096"))
LLM_CONTEXT_LENGTH = int(os.environ.get("LLM_CONTEXT_LENGTH", "131072"))
# Empty/0 means no client-side model request timeout. This is intentional for
# long-running local vLLM/Ollama tool-calling turns.
LLM_TIMEOUT = os.environ.get("LLM_TIMEOUT", "")

# ── AVFS ──────────────────────────────────────────────────────────────────────
AVFS_URL = os.environ.get("AVFS_URL", "http://127.0.0.1:8765/")
AVFS_AUTH_TOKEN = os.environ.get("AVFS_AUTH_TOKEN", "change-me-avfs-token")
AVFS_AGENT_ID = os.environ.get("AVFS_AGENT_ID", "agent_1")

# ── Wazuh (passed to aci-wazuh subprocess as env) ────────────────────────────
WAZUH_URL = os.environ.get("WAZUH_URL", "")          # preferred: full URL
WAZUH_HOST = os.environ.get("WAZUH_HOST", "")         # fallback if WAZUH_URL not set
WAZUH_PORT = os.environ.get("WAZUH_PORT", "9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")
WAZUH_VERIFY_TLS = os.environ.get("WAZUH_VERIFY_TLS", "false")
WAZUH_INDEX_PATTERN = os.environ.get("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")

# ── TheHive (passed to aci-thehive subprocess as env) ────────────────────────
THEHIVE_HOST = os.environ.get("THEHIVE_HOST", "")
THEHIVE_PORT = os.environ.get("THEHIVE_PORT", "9000")
THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY", "")
THEHIVE_VERIFY_TLS = os.environ.get("THEHIVE_VERIFY_TLS", "true")

# ── Task queue (passed to aci-taskqueue subprocess as env) ───────────────────
TASKQUEUE_DB_PATH = os.environ.get("TASKQUEUE_DB_PATH", str(BASE_DIR / "taskqueue.db"))

# ── Fact/hypothesis board (passed to aci-board subprocess as env) ─────────────
BOARD_DB_PATH = os.environ.get("BOARD_DB_PATH", str(BASE_DIR / "board.db"))

# ── Automatic workflows (C4 trigger seam) ────────────────────────────────────
# Off by default: only the manual `run_workflow` management command honours this
# until real event ingestion (webhooks/pollers) lands.
WORKFLOWS_ENABLED = os.environ.get("WORKFLOWS_ENABLED", "false").lower() == "true"
