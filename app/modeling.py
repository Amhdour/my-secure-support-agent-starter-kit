"""Model interaction contracts for support-agent orchestration."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from retrieval.contracts import RetrievalDocument


@dataclass(frozen=True)
class ModelInput:
    """RAG-first model input envelope."""

    request_id: str
    user_text: str
    retrieved_context: Sequence[RetrievalDocument]
    metadata: Mapping[str, str] = field(default_factory=dict)


class LanguageModel(Protocol):
    """Model interface consumed by orchestration layer."""

    def generate(self, model_input: ModelInput) -> str:
        """Generate a draft answer from user input + retrieved context."""
        ...
