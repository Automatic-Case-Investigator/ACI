from __future__ import annotations

import json

from django.contrib import messages
from django.shortcuts import redirect, render
from django.utils.text import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from agent.models import (
    AgentConfig,
    BaselineSnapshot,
    BaselineSubjectConfig,
    EscalationRule,
    MCPServerConfig,
    ModelProviderConfig,
    ProviderConfig,
    RuntimeConfig,
    WorkflowConfig,
    WorkflowTriggerConfig,
)
from django.http import JsonResponse



@csrf_exempt
@require_POST
def settings_baseline_subject_save(request):
    """Add or update an operator-configured baseline subject."""
    p = request.POST
    subject_type = (p.get("subject_type") or "").strip()
    subject_id = (p.get("subject_id") or "").strip()

    valid_types = {c[0] for c in BaselineSubjectConfig.SUBJECT_CHOICES}
    if subject_type not in valid_types:
        messages.error(request, f"Unknown subject type: {subject_type}")
        return redirect("dashboard:settings")
    if not subject_id:
        messages.error(request, "Subject ID is required.")
        return redirect("dashboard:settings")

    BaselineSubjectConfig.objects.update_or_create(
        subject_type=subject_type,
        subject_id=subject_id,
        defaults={"enabled": p.get("enabled") == "1"},
    )
    messages.success(request, f"Baseline subject '{subject_type}:{subject_id}' saved.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_baseline_subject_toggle(request):
    subject_id = (request.POST.get("id") or "").strip()
    enabled = request.POST.get("enabled") == "1"
    updated = BaselineSubjectConfig.objects.filter(id=subject_id).update(enabled=enabled)
    if updated:
        messages.success(request, f"Baseline subject {'enabled' if enabled else 'disabled'}.")
    else:
        messages.error(request, "Baseline subject not found.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_baseline_subject_delete(request):
    subject_id = (request.POST.get("id") or "").strip()
    deleted, _ = BaselineSubjectConfig.objects.filter(id=subject_id).delete()
    if deleted:
        messages.success(request, "Baseline subject deleted.")
    else:
        messages.error(request, "Baseline subject not found.")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_baseline_window_save(request):
    """Persist the lookback window without recomputing."""
    from agent.runtime.learning.baselines import get_window_days, set_window_days

    raw = (request.POST.get("window_days") or "").strip()
    if not raw.isdigit() or int(raw) < 1:
        messages.error(request, "Lookback window must be a positive number of days.")
        return redirect("dashboard:settings")
    days = set_window_days(int(raw))
    messages.success(request, f"Baseline lookback window set to {days} day(s).")
    return redirect("dashboard:settings")


@csrf_exempt
@require_POST
def settings_baseline_recompute(request):
    """Recompute baselines now and report the outcome.

    Runs independently of any in-progress agent sessions. Executes inline so the
    result (or the underlying SIEM error) is surfaced to the operator instead of
    being swallowed by a detached thread. The lookback window submitted with the
    form is persisted so the nightly scheduler uses the same value.
    """
    from agent.runtime.learning.baseline_adapters import active_adapter_name
    from agent.runtime.learning.baselines import compute_all_baselines, get_window_days, set_window_days

    raw = (request.POST.get("window_days") or "").strip()
    if raw.isdigit() and int(raw) >= 1:
        days = set_window_days(int(raw))
    else:
        days = get_window_days()
    adapter = active_adapter_name()
    try:
        written, skipped = compute_all_baselines(days=days)
    except Exception as exc:
        messages.error(request, f"Baseline recompute failed ({adapter}): {exc}")
        return redirect("dashboard:settings")

    if written:
        messages.success(
            request,
            f"Baseline recompute complete via '{adapter}': "
            f"{written} feature(s) written, {skipped} skipped.",
        )
    else:
        has_subjects = BaselineSubjectConfig.objects.filter(enabled=True).exists()
        if has_subjects:
            messages.error(
                request,
                f"No baselines written via '{adapter}'. The configured subjects "
                "returned too few events, or the SIEM is unreachable — check the "
                "subject IDs and the adapter's connection settings.",
            )
        else:
            messages.error(
                request,
                f"No baselines written via '{adapter}'. No subjects are configured "
                "and auto-discovery returned nothing — add subjects below or verify "
                "the SIEM connection.",
            )
    return redirect("dashboard:settings")

