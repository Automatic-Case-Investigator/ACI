"""One-shot tool that split the 2223-line agent/runtime/graph.py monolith into the
agent/runtime/graph/ package. Kept under _archive/ for provenance; not used at runtime.
"""
import ast
import re
import pathlib

SRC = pathlib.Path("_graph_orig_backup.py")
OUT = pathlib.Path("agent/runtime/graph")

# top-level name -> target submodule
NAME2MOD = {
    # state
    "AgentState": "state",
    # sanitize
    "_HARMONY_TOKEN_RE": "sanitize", "_LEAKED_TOOL_HEADER_RE": "sanitize",
    "_LEAKED_ROLE_LINE_RE": "sanitize", "_strip_harmony": "sanitize",
    "_sanitize_message": "sanitize", "_sanitize_history": "sanitize", "_normalize": "sanitize",
    # parsing
    "_extract_report_section": "parsing", "_section_has_concrete_items": "parsing",
    "_NEW_LEADS_HEADER_RE": "parsing", "_NEW_LEADS_RE": "parsing",
    "_CONFIRMED_FACTS_RE": "parsing", "_HYPOTHESES_RE": "parsing",
    "_TRIAGE_SOAR_ONLY_RE": "parsing", "_TRIAGE_EVIDENCE_GAPS_RE": "parsing",
    "_SECTION_HEADER_RE": "parsing", "_section_body": "parsing", "_FACT_BULLET_RE": "parsing",
    "_NONE_BULLETS": "parsing", "_NONE_PREFIXES": "parsing", "_is_none_bullet": "parsing",
    "_is_provenance_only": "parsing", "_EVENT_ID_TOKEN_RE": "parsing", "_event_ids_in": "parsing",
    "_fact_dedup_key": "parsing", "_STATUS_TOKEN_RE": "parsing", "_ID_MARKER_RE": "parsing",
    "_EMPH_RE": "parsing", "_NON_HYPOTHESIS_RE": "parsing", "_SOURCE_REF_RE": "parsing",
    "_ISO_TS_RE": "parsing", "_CHAR_TRANSLATION": "parsing", "_ascii_dashes": "parsing",
    "_EVENT_ID_DUMP_RE": "parsing", "_IP_LITERAL_RE": "parsing", "_DOMAIN_LITERAL_RE": "parsing",
    "_HASH_LITERAL_RE": "parsing", "_PATH_LITERAL_RE": "parsing", "_JSON_EVENT_ID_RE": "parsing",
    "_COMMAND_LITERAL_PATTERNS": "parsing", "_LONG_HEX_RE": "parsing", "_BRUTE_FORCE_RE": "parsing",
    "_REVERSE_SHELL_RE": "parsing", "_PERSISTENCE_RE": "parsing", "_TROJAN_RE": "parsing",
    "_ANTI_FORENSIC_RE": "parsing", "_NEGATED_EVIDENCE_RE": "parsing", "_strip_markers": "parsing",
    "_looks_like_lead": "parsing", "_extract_source_refs": "parsing", "_lines_with_ips": "parsing",
    "_has_positive_pattern": "parsing", "_ACTIVE_COMPROMISE_INDICATORS_RE": "parsing",
    "_DANGLING_FACT_RE": "parsing", "_normalize_fact_key": "parsing", "_section_count": "parsing",
    # toolio
    "_tmap": "toolio", "_SEED_TASK_TITLE": "toolio", "_GRAPH_MANAGED_TOOLS": "toolio",
    "_MAX_SYNTHESIS_FINDINGS_CHARS": "toolio", "_model_tools_for_agent": "toolio",
    "_invoke_bound_model": "toolio", "_first_int": "toolio", "_extract_input_tokens": "toolio",
    "_should_compact": "toolio", "_compact_history": "toolio", "_call": "toolio",
    "_emit_node_entry": "toolio", "_list_tasks": "toolio", "_has_pending_tasks": "toolio",
    "_parse_claimed_task": "toolio", "_reclaim_stale_tasks": "toolio",
    "_MAX_TOOL_RESULT_CHARS": "toolio", "_cap_tool_result": "toolio",
    "_is_error_tool_result": "toolio", "_expand_tilde_args": "toolio",
    "_ensure_parent_dir": "toolio", "_cancel_requested": "toolio",
    # board
    "_format_board_context": "board", "_record_board_entry": "board",
    "_record_hypotheses_text": "board", "_entry_line": "board",
    # validation
    "_collect_escalation_facts": "validation", "_artifact_literals_in": "validation",
    "_positive_artifact_literals": "validation", "_iter_leaf_strings": "validation",
    "_board_entries_for_validation": "validation", "_trusted_artifacts_for_validation": "validation",
    "_artifact_display": "validation", "_derive_report_guardrails": "validation",
    # synthesis
    "_execution_record": "synthesis", "_build_investigation_summary": "synthesis",
    "_ANALYST_REPORT_SYSTEM": "synthesis", "_FINDINGS_RE": "synthesis",
    "_clip_findings_for_synthesis": "synthesis", "_task_summary_for_synthesis": "synthesis",
    "_synthesize_analyst_report": "synthesis",
    # nodes_loop
    "seed": "nodes_loop", "claim": "nodes_loop", "think": "nodes_loop",
    "use_tools": "nodes_loop", "_enrich_artifacts_async": "nodes_loop",
    # nodes_flow
    "_MAX_PIVOT_TASKS": "nodes_flow", "assess": "nodes_flow", "pivot": "nodes_flow",
    "finish": "nodes_flow",
    # builder
    "_route_claim": "builder", "_route_use_tools": "builder", "_route_think": "builder",
    "_route_assess": "builder", "build_graph": "builder", "GRAPH": "builder",
}

DROP = {"log"}  # defined fresh per-module via header

EXT = {
    "emit": "..infra.logbus", "src_label": "..infra.logbus", "summarize_args": "..infra.logbus",
    "summarize_result": "..infra.logbus", "summarize_think": "..infra.logbus",
    "update_context_usage": "..infra.logbus", "invoke_streaming": "..engine.streaming",
    "record_artifacts": "..analysis.artifacts", "parse_verdict": "..analysis.verdict",
    "apply_citation_policy": "..analysis.verdict", "apply_open_gaps_policy": "..analysis.verdict",
    "validate_verdict": "..analysis.verdict", "reports_dir": "..infra.avfs",
    "findings_dir": "..infra.avfs", "case_dir": "..infra.avfs", "home_dir": "..infra.avfs",
    "update_memory_indexes": "...workspace.avfs_writer", "write_file": "...workspace.avfs_writer",
    "Handoff": "...agents.base", "SystemMessage": "langchain_core.messages",
    "HumanMessage": "langchain_core.messages", "ToolMessage": "langchain_core.messages",
    "StateGraph": "langgraph.graph", "END": "langgraph.graph",
    "TypedDict": "typing_extensions", "Optional": "typing",
}

MOD_ORDER = ["state", "sanitize", "parsing", "toolio", "board", "validation",
             "synthesis", "nodes_loop", "nodes_flow", "builder"]

src_text = SRC.read_text(encoding="utf-8")
lines = src_text.splitlines(keepends=True)
tree = ast.parse(src_text)

# Collect top-level statements (skip the header: imports, __future__, module docstring, `log=`)
segments = {m: [] for m in MOD_ORDER}  # module -> list of (lineno, text)
names_in = {m: set() for m in MOD_ORDER}  # module -> set of referenced Name ids
current_mod = None
prev_end = 0

# find end line of header (last Import/ImportFrom or `log =`)
header_end = 0
for node in tree.body:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        header_end = max(header_end, node.end_lineno)
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "log" for t in node.targets
    ):
        header_end = max(header_end, node.end_lineno)
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and node is tree.body[0]:
        header_end = max(header_end, node.end_lineno)  # module docstring
prev_end = header_end

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

for node in tree.body:
    if node.end_lineno <= header_end:
        continue
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        prev_end = node.end_lineno
        continue
    nm = node_name(node)
    if nm in DROP:
        prev_end = node.end_lineno
        continue
    if nm is not None:
        if nm not in NAME2MOD:
            raise SystemExit(f"UNMAPPED top-level name: {nm!r} (line {node.lineno})")
        current_mod = NAME2MOD[nm]
    # orphan statements (e.g. _CHAR_TRANSLATION.update(...)) inherit current module
    if current_mod is None:
        raise SystemExit(f"orphan before any named node at line {node.lineno}")
    seg = "".join(lines[prev_end:node.end_lineno])
    segments[current_mod].append((node.lineno, seg))
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            names_in[current_mod].add(n.id)
    prev_end = node.end_lineno


def build_header(mod):
    body_text = "".join(s for _, s in segments[mod])
    out = ["from __future__ import annotations", ""]
    # stdlib
    std = []
    if re.search(r"\bjson\.", body_text):
        std.append("import json")
    if re.search(r"\bre\.", body_text):
        std.append("import re")
    if re.search(r"\bipaddress\.", body_text):
        std.append("import ipaddress")
    uses_log = bool(re.search(r"\blog\.", body_text))
    if uses_log:
        std.append("import logging")
    if std:
        out += sorted(std) + [""]
    # external imports grouped by module path
    ext_groups = {}
    for name in sorted(names_in[mod]):
        if name in EXT and NAME2MOD.get(name) != mod:
            ext_groups.setdefault(EXT[name], set()).add(name)
    # stable ordering: stdlib-ish third party first, then runtime
    def keyfn(p):
        return (0 if "." not in p.lstrip(".") and not p.startswith(".") else 1, p)
    third = {p: n for p, n in ext_groups.items() if not p.startswith(".")}
    rel = {p: n for p, n in ext_groups.items() if p.startswith(".")}
    for p in sorted(third):
        out.append(f"from {p} import {', '.join(sorted(third[p]))}")
    if third:
        out.append("")
    for p in sorted(rel):
        out.append(f"from {p} import {', '.join(sorted(rel[p]))}")
    # intra-package imports
    intra = {}
    for name in sorted(names_in[mod]):
        tgt = NAME2MOD.get(name)
        if tgt and tgt != mod:
            intra.setdefault(tgt, set()).add(name)
    if rel and intra:
        out.append("")
    for tgt in sorted(intra):
        out.append(f"from .{tgt} import {', '.join(sorted(intra[tgt]))}")
    if uses_log:
        out += ["", "log = logging.getLogger(__name__)"]
    out.append("")
    out.append("")
    return "\n".join(out)


def fix_depths(text):
    text = text.replace("from .infra.", "from ..infra.")
    text = text.replace("from .engine.", "from ..engine.")
    text = text.replace("from .analysis.", "from ..analysis.")
    text = text.replace("from .config.", "from ..config.")
    text = text.replace("from ..models", "from ...models")
    text = text.replace("from ..agents.", "from ...agents.")
    text = text.replace("from ..workspace.", "from ...workspace.")
    return text


OUT.mkdir(parents=True, exist_ok=True)
for mod in MOD_ORDER:
    segs = sorted(segments[mod], key=lambda x: x[0])
    body = "".join(s for _, s in segs)
    content = build_header(mod) + body
    content = fix_depths(content)
    (OUT / f"{mod}.py").write_text(content, encoding="utf-8")
    print(f"  {mod}.py: {len(content.splitlines())} lines, {len(segs)} segments")

# __init__.py: re-aggregate every public+private name so `graph.X` keeps working
init = '''"""LangGraph agent graph (queue-driven loop shared by triage and investigation).

This package was split from a single 2223-line module; the submodules below own
cohesive slices of the original. Every public and private name is re-exported here
so the historical ``from agent.runtime.graph import X`` / ``graph._helper`` access
pattern (used across the runtime and the test suite) keeps working unchanged.
"""
from . import (
    state, sanitize, parsing, toolio, board, validation, synthesis,
    nodes_loop, nodes_flow, builder,
)

_submodules = [
    state, sanitize, parsing, toolio, board, validation, synthesis,
    nodes_loop, nodes_flow, builder,
]
for _m in _submodules:
    for _n in dir(_m):
        if not _n.startswith("__"):
            globals()[_n] = getattr(_m, _n)
del _m, _n, _submodules
'''
(OUT / "__init__.py").write_text(init, encoding="utf-8")
print("  __init__.py written")
