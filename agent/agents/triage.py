from .base import AgentDefinition, Budget
from .registry import register

triage = register(
    AgentDefinition(
        name="triage",
        description="Broad-scope SOC triage agent. Reads TheHive case and alerts, diagnoses severity and category, and returns a triage report with a prioritized investigation plan.",
        prompt_layers=["platform", "triage"],
        tool_policy=["aci-thehive", "aci-taskqueue", "avfs"],
        budget=Budget(max_steps=20, max_tool_calls=40),
        produces_handoff=True,
    )
)
