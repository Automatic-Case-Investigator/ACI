from __future__ import annotations

import posixpath
from dataclasses import dataclass
from datetime import datetime, timezone


MEMORY_FILE = "memory.md"


@dataclass(frozen=True)
class MemoryEntry:
    path: str
    kind: str
    summary: str
    created_by: str
    updated: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_kind(path: str) -> str:
    suffix = posixpath.splitext(path)[1].lower()
    if suffix == ".json":
        return "JSON"
    if suffix == ".jsonl":
        return "JSONL"
    if suffix == ".md":
        return "Markdown"
    if suffix:
        return suffix.lstrip(".").upper()
    return "File"


def path_summary(path: str) -> str:
    name = posixpath.basename(path)
    if name == "case.json":
        return "Normalized SOAR case metadata."
    if name == "brief.md":
        return "Human-readable case brief."
    if name == "timeline.md":
        return "Append-friendly case chronology."
    if name == "final.md":
        return "Final report artifact."
    if name == "citations.json":
        return "Validated report citation map."
    if "/evidence/events/" in path:
        return "Raw SIEM event evidence."
    if "/evidence/queries/" in path:
        return "SIEM query record and result metadata."
    if "/findings/" in path:
        return "Evidence-backed investigation finding."
    return "Workspace artifact."


def render_memory(
    *,
    purpose: str,
    files: list[MemoryEntry] | None = None,
    child_directories: list[MemoryEntry] | None = None,
    notes: str = "",
) -> str:
    files = files or []
    child_directories = child_directories or []
    lines = [
        "# Memory",
        "",
        "## Purpose",
        purpose or "Directory index for agent workspace files.",
        "",
        "## Files",
        "| Path | Type | Summary | Created By | Updated |",
        "|---|---|---|---|---|",
    ]
    if files:
        for entry in sorted(files, key=lambda e: e.path):
            lines.append(_row(entry))
    else:
        lines.append("| _none_ |  |  |  |  |")
    lines.extend([
        "",
        "## Child Directories",
        "| Path | Type | Summary | Created By | Updated |",
        "|---|---|---|---|---|",
    ])
    if child_directories:
        for entry in sorted(child_directories, key=lambda e: e.path):
            lines.append(_row(entry))
    else:
        lines.append("| _none_ |  |  |  |  |")
    lines.extend(["", "## Notes", notes or ""])
    return "\n".join(lines).rstrip() + "\n"


def upsert_memory_content(
    existing: str | None,
    *,
    directory: str,
    changed_path: str,
    created_by: str,
    summary: str | None = None,
    updated: str | None = None,
) -> str:
    """Return a `memory.md` body with `changed_path` indexed.

    The parser intentionally supports only the table shape we emit. If an agent
    hand-edits the file into another shape, we preserve the purpose/notes best
    effort and rebuild the index table.
    """
    directory = directory.rstrip("/")
    basename = posixpath.basename(changed_path.rstrip("/"))
    updated = updated or now_iso()
    existing_files, existing_dirs = _parse_tables(existing or "")
    if basename == MEMORY_FILE:
        return existing or render_memory(purpose=_purpose_for(directory))

    if changed_path.rstrip("/") == directory:
        return existing or render_memory(purpose=_purpose_for(directory))

    rel = _direct_child(directory, changed_path)
    if not rel:
        return existing or render_memory(purpose=_purpose_for(directory))

    is_child_dir = "/" in rel
    direct_name = rel.split("/", 1)[0]
    target = existing_dirs if is_child_dir else existing_files
    target[direct_name] = MemoryEntry(
        path=direct_name,
        kind="Directory" if is_child_dir else file_kind(direct_name),
        summary=summary or ("Contains workspace artifacts." if is_child_dir else path_summary(changed_path)),
        created_by=created_by,
        updated=updated,
    )
    return render_memory(
        purpose=_extract_section(existing or "", "Purpose") or _purpose_for(directory),
        files=list(existing_files.values()),
        child_directories=list(existing_dirs.values()),
        notes=_extract_section(existing or "", "Notes"),
    )


def parent_index_dirs(path: str, *, stop_at: str) -> list[str]:
    """Directories whose memory.md should reflect a write to `path`."""
    path = path.rstrip("/")
    stop_at = stop_at.rstrip("/")
    directory = posixpath.dirname(path)
    out: list[str] = []
    while directory and directory != "/" and directory.startswith(stop_at):
        out.append(directory)
        if directory == stop_at:
            break
        directory = posixpath.dirname(directory)
    return out


def _row(entry: MemoryEntry) -> str:
    vals = [_escape(entry.path), _escape(entry.kind), _escape(entry.summary), _escape(entry.created_by), _escape(entry.updated)]
    return "| " + " | ".join(vals) + " |"


def _escape(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _direct_child(directory: str, path: str) -> str:
    directory = directory.rstrip("/")
    path = path.rstrip("/")
    prefix = directory + "/"
    if not path.startswith(prefix):
        return ""
    return path[len(prefix):]


def _purpose_for(directory: str) -> str:
    if directory.endswith("/evidence"):
        return "Evidence root for stored queries, raw events, artifacts, enrichments, and documents."
    if "/evidence/events" in directory:
        return "Raw event evidence and source-specific event folders."
    if directory.endswith("/findings"):
        return "Evidence-backed findings produced by agents or analysts."
    if directory.endswith("/reports"):
        return "Report drafts, final reports, citation maps, and exports."
    if "/cases/" in directory:
        return "Shared case workspace for agent and analyst investigation artifacts."
    if directory.endswith("/memory"):
        return "Long-term reusable memory for future ACI runs."
    return "Directory index for agent workspace files."


def _parse_tables(content: str) -> tuple[dict[str, MemoryEntry], dict[str, MemoryEntry]]:
    files: dict[str, MemoryEntry] = {}
    dirs: dict[str, MemoryEntry] = {}
    section = ""
    for line in content.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or line.startswith("| Path ") or line.startswith("|---"):
            continue
        cols = [c.strip().replace("\\|", "|") for c in line.strip("|").split("|")]
        if len(cols) < 5 or cols[0] == "_none_":
            continue
        entry = MemoryEntry(cols[0], cols[1], cols[2], cols[3], cols[4])
        if section == "Files":
            files[entry.path] = entry
        elif section == "Child Directories":
            dirs[entry.path] = entry
    return files, dirs


def _extract_section(content: str, heading: str) -> str:
    marker = f"## {heading}"
    if marker not in content:
        return ""
    after = content.split(marker, 1)[1].lstrip()
    if "\n## " in after:
        after = after.split("\n## ", 1)[0]
    return after.strip()
