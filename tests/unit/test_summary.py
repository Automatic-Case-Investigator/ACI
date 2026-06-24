"""Offline test of _build_investigation_summary using a real completed run."""
import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aci.settings")
# Navigate from .claude/skills/run-aci-backend/tests/ up to project root (4 levels)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, project_root)
import django; django.setup()

from agent.models import AgentRun
from aci_taskqueue import store as tq_store
from aci_board import store as board_store

def main():
    # Find a completed investigation run with tasks
    runs = list(AgentRun.objects.filter(agent_name="investigation", status="completed").order_by("-created_at")[:5])
    if not runs:
        print("No completed investigation runs found")
        return 0

    run = runs[0]
    print(f"Using run {run.id} (case={run.case_id})")

    tasks = tq_store.list_tasks(run.case_id, str(run.id), "investigation")
    board_store.init_db()
    entries = board_store.list_entries(run.case_id, str(run.id), "investigation")

    print(f"Tasks: {len(tasks)}  Board entries: {len(entries)}")

    # Simulate what _build_investigation_summary would produce
    SEED_TITLE = "populate investigation queue"
    completed = [t for t in tasks if t.get("status") == "completed"
                 and SEED_TITLE not in (t.get("title") or "").lower()]
    incomplete = [t for t in tasks if t.get("status") not in ("completed", "dismissed")
                  and SEED_TITLE not in (t.get("title") or "").lower()]
    facts = [e["content"] for e in entries if e.get("kind") == "fact"]
    hypotheses = [e["content"] for e in entries if e.get("kind") == "hypothesis"]

    lines = [
        f"# Investigation Summary — Case {run.case_id}",
        f"**Run:** {run.id}  \n**Question:** {run.question}",
        "",
    ]
    if facts:
        lines.append("## Confirmed Facts")
        for f in facts:
            lines.append(f"- {f}")
        lines.append("")
    if hypotheses:
        lines.append("## Hypotheses")
        for h in hypotheses:
            lines.append(f"- {h}")
        lines.append("")
    if completed:
        lines.append("## Completed Tasks")
        for t in completed:
            lines.append(f"### {t.get('title', '(untitled)')}")
            summary = (t.get("summary") or "").strip()
            if summary:
                lines.append(summary)
            lines.append("")
    if incomplete:
        lines.append("## Incomplete / Pending Tasks")
        for t in incomplete:
            lines.append(f"- [{t.get('status', '?')}] {t.get('title', '(untitled)')}")
        lines.append("")
    if not completed and not facts:
        lines.append("No tasks completed and no facts confirmed.")

    print("\n" + "="*60)
    print("\n".join(lines))
    print("="*60)
    print(f"\nSummary length: {len(chr(10).join(lines))} chars")
    return 0


if __name__ == "__main__":
    sys.exit(main())
