from .base import AgentDefinition, Budget
from .registry import register

triage = register(
    AgentDefinition(
        name="triage",
        description="First-line lightweight SOC triage agent. Accepts a SOAR case id, a "
        "standalone SOAR alert id, or a SIEM alert/event reference; determines which kind "
        "it has, reads the relevant case/alert/SIEM evidence, diagnoses severity and "
        "category, and returns a triage report with a prioritized investigation plan.",
        prompt_layers=["platform", "triage", "siem_methodology", "playbook"],
        tool_policy=["aci-thehive", "aci-wazuh", "aci-taskqueue", "aci-memory", "avfs"],
        # Flat-loop budget: one step per reasoning cycle, several tool calls per step.
        # The old 12/18 was sized for the ledger loop, where interpret compressed the
        # history between cycles; a flat loop that must actually READ the raw events
        # downstream of the alert needs roughly what the orchestrator spends (~20 calls
        # over ~7 rounds) plus headroom, while staying well under investigation (40/60).
        budget=Budget(max_steps=16, max_tool_calls=40),
        produces_handoff=True,
    )
)
