"""In-memory source registry for retrieval boundary enforcement."""

from dataclasses import dataclass, field
<<<<<<< HEAD
from typing import Sequence
=======
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)

from retrieval.contracts import SourceRegistration, SourceRegistry


@dataclass
class InMemorySourceRegistry(SourceRegistry):
    """Simple source registry for local development and tests."""

    _sources: dict[str, SourceRegistration] = field(default_factory=dict)

    def register(self, source: SourceRegistration) -> None:
        self._sources[source.source_id] = source

    def get(self, source_id: str) -> SourceRegistration | None:
        return self._sources.get(source_id)

<<<<<<< HEAD
    def list_for_tenant(self, tenant_id: str) -> Sequence[SourceRegistration]:
=======
    def list_for_tenant(self, tenant_id: str):
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
        return tuple(source for source in self._sources.values() if source.tenant_id == tenant_id)
