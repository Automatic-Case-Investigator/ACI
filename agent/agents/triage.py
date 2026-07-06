from .base import AgentDefinition, Budget
from .registry import register

triage = register(
    AgentDefinition(
        name="triage",
        description="First-line lightweight SOC triage agent. Reads SOAR case and alerts, diagnoses severity and category, and returns a triage report with a prioritized investigation plan.",
        prompt_layers=["platform", "triage", "siem_methodology", "playbook"],
        tool_policy=["aci-thehive", "aci-wazuh", "aci-taskqueue", "aci-memory", "avfs"],
        budget=Budget(max_steps=12, max_tool_calls=18),
        produces_handoff=True,
    )
)
