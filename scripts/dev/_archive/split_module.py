"""One-shot generic splitter: turns a large module into a same-name package whose
submodules hold cohesive slices, with a re-exporting __init__. Kept under _archive/
for provenance; not used at runtime.

Reuses the original import header verbatim in each submodule (depth-shifted by one
since submodules live one level deeper), auto-computes intra-package imports from
referenced names, and re-aggregates every name in __init__ so existing
`from pkg import X` / `pkg.X` access keeps working.
"""
import ast
import re
import sys
import pathlib

CONFIGS = {
    "agent/dashboard/settings_views.py": {
        "out": "agent/dashboard/settings_views",
        "name2mod": {
            "rows": ["_CONNECTION_SCHEMA", "_integration_rows", "_test_connection",
                "_provider_rows", "_custom_mcp_rows", "_agent_rows", "_workflow_rows",
                "_workflow_event_options", "_provider_options", "_webhook_url",
                "_workflow_trigger_rows", "_escalation_rows", "_baseline_adapter_name",
                "_baseline_window_days", "_baseline_subject_hint", "_baseline_subject_rows",
                "_baseline_vis", "_baseline_snapshot_rows", "_runtime_context"],
            "pages": ["settings_view"],
            "agents": ["settings_agent_save", "settings_workflow_save", "settings_trigger_save",
                "settings_trigger_toggle", "settings_trigger_delete", "settings_escalation_save"],
            "baselines": ["settings_baseline_subject_save", "settings_baseline_subject_toggle",
                "settings_baseline_subject_delete", "settings_baseline_window_save",
                "settings_baseline_recompute"],
            "integrations": ["settings_model_save", "settings_provider_toggle", "settings_mcp_save",
                "settings_mcp_delete", "settings_connection_save", "settings_connection_test",
                "settings_runtime_save", "settings_ti_cache_stats", "settings_ti_cache_clear"],
        },
        "docstring": '"""Analyst-editable settings dashboard (split into cohesive view groups)."""',
    },
    "agent/runtime/orchestrator.py": {
        "out": "agent/runtime/orchestrator",
        "name2mod": {
            "messages": ["_serialize_messages", "_deserialize_messages", "render_conversation",
                "_visible_transcript_from_messages", "_normalize_visible_transcript",
                "_append_visible", "_summarize_conversation"],
            "session": ["OrchestratorSession"],
            "tools": ["_format_subagent_issues", "_make_tools", "_make_agent_tool", "_agent_run_summary"],
            "prompts": ["_orchestrator_system_prompt", "_ORCHESTRATOR_TOOL_POLICY",
                "_embedded_convo_char_budget"],
            "driver": ["_INV_NEG_RE", "_INV_TRIAGE_ONLY_RE", "_INV_INQUIRY_RE", "_INV_IMPERATIVE_RE",
                "_analyst_requested_investigation", "run_orchestrator", "_run_orchestrator_impl"],
        },
        "drop": ["log"],
        "docstring": '"""Conversational orchestrator (split into messages / session / tools / prompts / driver)."""',
    },
    "agent/dashboard/runner.py": {
        "out": "agent/dashboard/runner",
        "name2mod": {
            "_base": ["_active_sessions", "_loops", "_processing", "_lock", "_RESTARTABLE_AGENTS",
                "_RESTART_CONTEXT_LIMIT", "_EVENT_DETAIL_LIMIT", "_ACTIVE_SPECIALIST_STATES",
                "_set_status", "_load_session_state", "_save_session_state", "_current_context_run",
                "_events_for_run", "_clip", "_append_with_limit", "_prior_tasks", "_prior_board_entries"],
            "restart": ["can_restart_from_prior_run", "restart_from_prior_run", "_restart_question",
                "_build_restart_context", "_copy_investigation_restart_state", "_start_agent_thread"],
            "lifecycle": ["start_session", "start_investigation_from_triage", "send_message",
                "stop_processing", "stop_session", "is_processing", "active_specialist_for_session",
                "is_active", "get_ctx", "_session_loop", "_run_review_investigation"],
        },
        "docstring": '"""Session/run lifecycle for the dashboard (state / restart / lifecycle)."""',
    },
    "agent/views.py": {
        "out": "agent/views",
        "name2mod": {
            "public": ["PublicAPIView", "VerdictStatsView", "ActiveRunsView"],
            "runs": ["AgentRunView", "AgentRunDetailView", "AgentRunStatusView", "AgentRunEventsView",
                "AgentRunCancelView", "AgentRunResumeView", "AgentRunRestartView", "AgentRunFeedbackView",
                "CaseQueueTasksView", "CaseWorkspaceView", "CaseLatestReportView"],
            "webhooks": ["_request_secret", "_payload_dict", "_trigger_metadata", "_start_trigger_dispatch",
                "_handle_configured_webhook", "ConfiguredWebhookView", "TheHiveWebhookView"],
        },
        "drop": ["log"],
        "docstring": '"""Agent REST API views (runs / webhooks / public)."""',
    },
    "agent/models.py": {
        "out": "agent/models",
        "name2mod": {
            "runs": ["AgentRun", "AgentEvent"],
            "config": ["ProviderConfig", "MCPServerConfig", "ModelProviderConfig", "AgentConfig",
                "WorkflowConfig", "WorkflowTriggerConfig", "EscalationRule", "RuntimeConfig"],
            "learning": ["FeedbackEntry", "PatternEntry", "PatternCandidate", "BaselineSnapshot",
                "BaselineComputeConfig", "BaselineSubjectConfig"],
        },
        "docstring": '"""Django ORM models for the agent app (runs / config / learning)."""',
    },
}


def shift(text):
    """Add one leading dot to every relative `from .…` import (submodules are one level deeper)."""
    return re.sub(r"(?m)^(\s*from\s+)(\.+)", r"\1.\2", text)


def node_name(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name):
                return t.id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def split(src_path, cfg):
    src = pathlib.Path(src_path).read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    tree = ast.parse(src)
    name2mod = {n: m for m, names in cfg["name2mod"].items() for n in names}
    mod_order = list(cfg["name2mod"].keys())
    drop = set(cfg.get("drop", []))

    # docstring + header span
    doc_end = 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        doc_end = tree.body[0].end_lineno

    def is_header_node(n):
        return isinstance(n, (ast.Import, ast.ImportFrom)) or (
            isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "log" for t in n.targets)
        )

    # contiguous leading block of imports / log (stops at first real content node)
    header_end = doc_end
    for n in tree.body:
        if n.end_lineno <= doc_end:
            continue
        if is_header_node(n):
            header_end = n.end_lineno
        else:
            break
    # any further top-level imports (placed mid-file) are pulled into the shared header
    extra = [
        "".join(lines[n.lineno - 1:n.end_lineno])
        for n in tree.body
        if n.lineno > header_end and isinstance(n, (ast.Import, ast.ImportFrom))
    ]
    header_src = shift("".join(lines[doc_end:header_end]))
    if extra:
        header_src = header_src.rstrip() + "\n" + shift("".join(extra))

    segments = {m: [] for m in mod_order}
    names_in = {m: set() for m in mod_order}
    current = None
    prev_end = header_end
    for n in tree.body:
        if n.end_lineno <= header_end:
            continue
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            prev_end = n.end_lineno
            continue
        nm = node_name(n)
        if nm in drop:
            prev_end = n.end_lineno
            continue
        if nm is not None:
            if nm not in name2mod:
                raise SystemExit(f"UNMAPPED {nm!r} in {src_path} (line {n.lineno})")
            current = name2mod[nm]
        if current is None:
            raise SystemExit(f"orphan before named node at line {n.lineno} in {src_path}")
        segments[current].append((n.lineno, "".join(lines[prev_end:n.end_lineno])))
        for sub in ast.walk(n):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                names_in[current].add(sub.id)
        prev_end = n.end_lineno

    out = pathlib.Path(cfg["out"])
    out.mkdir(parents=True, exist_ok=True)
    for mod in mod_order:
        intra = {}
        for name in sorted(names_in[mod]):
            tgt = name2mod.get(name)
            if tgt and tgt != mod:
                intra.setdefault(tgt, set()).add(name)
        intra_lines = [f"from .{t} import {', '.join(sorted(intra[t]))}" for t in sorted(intra)]
        body = shift("".join(s for _, s in sorted(segments[mod], key=lambda x: x[0])))
        parts = [header_src.rstrip()]
        if intra_lines:
            parts.append("\n".join(intra_lines))
        parts.append(body)
        (out / f"{mod}.py").write_text("\n\n".join(p for p in parts if p.strip()) + "\n", encoding="utf-8")
        print(f"  {mod}.py: {len((out / f'{mod}.py').read_text(encoding='utf-8').splitlines())} lines")

    agg = ", ".join(mod_order)
    init = (
        f"{cfg['docstring']}\n"
        f"from . import {agg}\n\n"
        f"_submodules = [{agg}]\n"
        "for _m in _submodules:\n"
        "    for _n in dir(_m):\n"
        "        if not _n.startswith(\"__\"):\n"
        "            globals()[_n] = getattr(_m, _n)\n"
        "del _m, _n, _submodules\n"
    )
    (out / "__init__.py").write_text(init, encoding="utf-8")
    print(f"  __init__.py written ({cfg['out']})")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    for path, cfg in CONFIGS.items():
        if target and target not in path:
            continue
        print(f"=== {path} ===")
        split(path, cfg)
