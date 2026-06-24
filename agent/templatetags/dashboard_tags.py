"""Template helpers for rendering log events (ported from the old TUI's renderer)."""
from __future__ import annotations

import json
import os

from django import template
from django.http import QueryDict
from django.templatetags.static import static
from django.contrib.staticfiles import finders

register = template.Library()


@register.simple_tag(takes_context=True)
def query_replace(context, key, value):
    """Current querystring with `key` set to `value`, other params preserved.

    Lets independent pagers (e.g. ?sp= and ?rp=) update one page number without
    clobbering the other. Usage: href="?{% query_replace 'sp' page.next_page_number %}".
    """
    request = context.get("request")
    params = request.GET.copy() if request is not None else QueryDict(mutable=True)
    params[key] = value
    return params.urlencode()


@register.simple_tag
def static_v(path: str) -> str:
    """Like {% static %} but appends the file's mtime as ?v= for cache-busting.

    Without this, browsers cache app.js/app.css at a stable URL and keep running
    the old code after a deploy — which left a fixed dashboard bug looking unfixed.
    """
    url = static(path)
    try:
        abs_path = finders.find(path)
        if abs_path and os.path.exists(abs_path):
            return f"{url}?v={int(os.path.getmtime(abs_path))}"
    except Exception:
        pass
    return url

# glyph per event kind (a small fixed marker, like the TUI's two-char column)
_GLYPH = {
    "think": "··",
    "stream": "~",
    "intent_delta": "~",
    "intent": "»",
    "call": "→",
    "result": "←",
    "task": "#",
    "route": "⇒",
    "note": "–",
    "error": "!!",
    "answer": "=",
    "done": "✓",
    "finding": "★",
}


@register.simple_tag
def event_glyph(ev) -> str:
    if ev.kind == "result" and ev.summary.startswith("ERROR"):
        return _GLYPH["error"]
    return _GLYPH.get(ev.kind, "–")


@register.simple_tag
def event_css(ev) -> str:
    """CSS class for color-coding; results that report an error read as errors."""
    if ev.kind == "result" and ev.summary.startswith("ERROR"):
        return "ev-error"
    return f"ev-{ev.kind}"


# Human-readable agent names for the sub-agent box header (B2).
_AGENT_NAME = {"tri": "triage", "inv": "investigation", "orch": "orchestrator"}


@register.simple_tag
def event_role(ev) -> str:
    """Chatbox classification (B1): 'user', 'assistant', or 'trace'.

    Analyst questions and the orchestrator's final answers render as conversation
    bubbles; everything else is the subordinate activity trace.
    """
    if ev.source == "cli" and (ev.summary or "").startswith("analyst:"):
        return "user"
    if ev.kind == "answer":
        return "assistant"
    return "trace"


@register.filter
def bubble_text(summary: str) -> str:
    """Strip the 'analyst:' prefix from an analyst bubble's summary."""
    s = summary or ""
    return s[len("analyst:"):].strip() if s.startswith("analyst:") else s


@register.simple_tag
def agent_display(source: str) -> str:
    return _AGENT_NAME.get(source, source or "agent")


@register.filter
def pretty_detail(detail: str) -> str:
    """Indent embedded JSON for readable expansion; pass non-JSON through untouched."""
    if not detail:
        return ""
    d = detail.strip()
    for cut, ch in enumerate(d):
        if ch not in "{[":
            continue
        blob = d[cut:].rstrip()
        trailer = ""
        if blob.endswith(")"):
            blob, trailer = blob[:-1], ")"
        try:
            obj = json.loads(blob)
        except (json.JSONDecodeError, ValueError):
            continue
        prefix = d[:cut]
        body = json.dumps(obj, indent=2, default=str) + trailer
        return f"{prefix}\n{body}" if prefix.strip() else body
    return detail
