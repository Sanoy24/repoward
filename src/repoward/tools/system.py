"""Tools with no external effects."""

from repoward.catalog import RiskClass
from repoward.policy.engine import Target
from repoward.registry import ToolInput, ToolOutput, ToolRegistry, ToolSpec


class PingInput(ToolInput):
    pass


async def _ping(_: ToolInput) -> ToolOutput:
    return ToolOutput("pong")


def register(registry: ToolRegistry) -> None:
    registry.register(
        ToolSpec(
            name="ping",
            description="Check that the server is reachable and governed.",
            risk=RiskClass.READ,
            input_model=PingInput,
            handler=_ping,
            target=lambda _: Target(),
        )
    )
