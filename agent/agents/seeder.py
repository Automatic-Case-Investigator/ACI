from .base import AgentDefinition, Budget
from .registry import register

seeder = register(
    AgentDefinition(
        name="seeder",
        description="Internal agent: parses a triage report and populates the investigation task queue.",
        prompt_layers=["platform", "seeder"],
        tool_policy=["aci-taskqueue"],
        budget=Budget(max_steps=20, max_tool_calls=25),
        orchestrator_routable=False,
        stream_intent=False,
    )
)
