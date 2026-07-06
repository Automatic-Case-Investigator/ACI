from .base import AgentDefinition, Budget
from .registry import register

investigation = register(
    AgentDefinition(
        name="investigation",
        description="Deep SOC investigation agent. Performs in-depth SIEM analysis, enriches artifacts, and produces a grounded report.",
        prompt_layers=["platform", "investigation", "siem_methodology", "playbook"],
        tool_policy=["aci-thehive", "aci-wazuh", "aci-taskqueue", "aci-board", "aci-memory", "avfs"],
        budget=Budget(max_steps=40, max_tool_calls=60),
        consumes_handoff=True,
    )
)
