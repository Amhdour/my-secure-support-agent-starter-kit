"""Centralized tool registry implementation."""

from dataclasses import dataclass, field
<<<<<<< HEAD
from typing import Sequence

from tools.contracts import ToolDescriptor, ToolRegistry
=======
from typing import Mapping

from tools.contracts import DirectToolExecutionDeniedError, ToolDescriptor, ToolExecutor, ToolInvocation, ToolRegistry
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)


@dataclass
class InMemoryToolRegistry(ToolRegistry):
    """Simple centralized tool registry for local usage and tests."""

    _tools: dict[str, ToolDescriptor] = field(default_factory=dict)
<<<<<<< HEAD

    def register(self, tool: ToolDescriptor) -> None:
        self._tools[tool.name] = tool
=======
    _executors: dict[str, ToolExecutor] = field(default_factory=dict)
    _execution_secret: object | None = None

    def register(self, tool: ToolDescriptor, executor: ToolExecutor | None = None) -> None:
        self._tools[tool.name] = tool
        if executor is not None:
            self._executors[tool.name] = executor
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)

    def get(self, tool_name: str) -> ToolDescriptor | None:
        return self._tools.get(tool_name)

<<<<<<< HEAD
    def list_allowlisted(self) -> Sequence[ToolDescriptor]:
        return tuple(tool for tool in self._tools.values() if tool.allowed)
=======
    def list_allowlisted(self):
        return tuple(tool for tool in self._tools.values() if tool.allowed)

    def bind_execution_secret(self, secret: object) -> None:
        self._execution_secret = secret

    def execute(self, invocation: ToolInvocation, execution_secret: object) -> Mapping[str, object]:
        if self._execution_secret is None or execution_secret is not self._execution_secret:
            raise DirectToolExecutionDeniedError(
                "direct tool execution is blocked: use SecureToolRouter.mediate_and_execute"
            )

        executor = self._executors.get(invocation.tool_name)
        if executor is None:
            raise DirectToolExecutionDeniedError(
                f"tool '{invocation.tool_name}' has no registered executor"
            )

        return executor(invocation)
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
