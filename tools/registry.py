"""Centralized tool registry implementation."""

from dataclasses import dataclass, field
from typing import Sequence

from tools.contracts import ToolDescriptor, ToolRegistry


@dataclass
class InMemoryToolRegistry(ToolRegistry):
    """Simple centralized tool registry for local usage and tests."""

    _tools: dict[str, ToolDescriptor] = field(default_factory=dict)

    def register(self, tool: ToolDescriptor) -> None:
        self._tools[tool.name] = tool

    def get(self, tool_name: str) -> ToolDescriptor | None:
        return self._tools.get(tool_name)

    def list_allowlisted(self) -> Sequence[ToolDescriptor]:
        return tuple(tool for tool in self._tools.values() if tool.allowed)
