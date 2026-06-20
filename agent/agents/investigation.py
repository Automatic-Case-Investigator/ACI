from .base import AgentDefinition, Budget
from .registry import register

investigation = register(
    AgentDefinition(
        name="investigation",
        description="Deep SOC investigation agent. Queries SIEM, enriches artifacts, writes findings to AVFS, produces a grounded report.",
        prompt_layers=["platform", "investigation"],
        tool_policy=["aci-thehive", "aci-wazuh", "aci-taskqueue", "aci-board", "avfs"],
        budget=Budget(max_steps=100, max_tool_calls=100),
        consumes_handoff=True,
    )
)
