"""The only way to add a tool. Tools are data here; only the pipeline ever runs them."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from mcp.types import Tool
from pydantic import BaseModel, ConfigDict

from repoward.catalog import TOOL_CATALOG, RiskClass
from repoward.flow import Taint
from repoward.policy.engine import Target
from repoward.sanitize import UntrustedContent


class ToolInput(BaseModel):
    """Base for tool arguments: unknown fields rejected, no type coercion."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


@dataclass(frozen=True)
class ToolOutput:
    """`text` is written by this server. Anything GitHub users control goes in `untrusted`."""

    text: str
    untrusted: tuple[UntrustedContent, ...] = ()
    taints: tuple[Taint, ...] = ()
    head_sha: str | None = None  # A commit this call created or opened for review.


class ToolError(Exception):
    """A failure whose message is safe to show the agent."""


@dataclass(frozen=True)
class ReviewApproval:
    """A qualifying human review on GitHub."""

    login: str
    review_id: int


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    risk: RiskClass
    input_model: type[ToolInput]
    handler: Callable[[ToolInput], Awaitable[ToolOutput]]
    target: Callable[[ToolInput], Target]
    approval_context: Callable[[ToolInput], Awaitable[str]] | None = None
    review_approval: Callable[[ToolInput], Awaitable[ReviewApproval | None]] | None = None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if TOOL_CATALOG.get(spec.name) is not spec.risk:
            raise ValueError(f"{spec.name} does not match the tool catalog")
        if spec.name in self._tools:
            raise ValueError(f"{spec.name} is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def list_tools(self) -> list[Tool]:
        """Every registered tool in a stable order. Enforcement happens on call."""
        return [
            Tool(
                name=spec.name,
                description=spec.description,
                input_schema=spec.input_model.model_json_schema(),
            )
            for _, spec in sorted(self._tools.items())
        ]
