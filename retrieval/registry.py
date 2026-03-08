"""In-memory source registry for retrieval boundary enforcement."""

from dataclasses import dataclass, field
from typing import Sequence

from retrieval.contracts import SourceRegistration, SourceRegistry


@dataclass
class InMemorySourceRegistry(SourceRegistry):
    """Simple source registry for local development and tests.

    Source IDs are globally unique in this registry. Registering the same source ID
    for a different tenant is rejected to avoid ambiguous boundary enforcement.
    """

    _sources: dict[str, SourceRegistration] = field(default_factory=dict)

    def register(self, source: SourceRegistration) -> None:
        existing = self._sources.get(source.source_id)
        if existing is not None and existing.tenant_id != source.tenant_id:
            raise ValueError(
                f"source_id '{source.source_id}' already registered for tenant '{existing.tenant_id}'"
            )
        self._sources[source.source_id] = source

    def get(self, source_id: str) -> SourceRegistration | None:
        return self._sources.get(source_id)

    def list_for_tenant(self, tenant_id: str) -> Sequence[SourceRegistration]:
        return tuple(source for source in self._sources.values() if source.tenant_id == tenant_id)
