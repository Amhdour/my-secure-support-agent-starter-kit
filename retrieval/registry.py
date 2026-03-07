"""In-memory source registry for retrieval boundary enforcement."""

from dataclasses import dataclass, field

from retrieval.contracts import SourceRegistration, SourceRegistry


@dataclass
class InMemorySourceRegistry(SourceRegistry):
    """Simple source registry for local development and tests."""

    _sources: dict[str, SourceRegistration] = field(default_factory=dict)

    def register(self, source: SourceRegistration) -> None:
        self._sources[source.source_id] = source

    def get(self, source_id: str) -> SourceRegistration | None:
        return self._sources.get(source_id)

    def list_for_tenant(self, tenant_id: str):
        return tuple(source for source in self._sources.values() if source.tenant_id == tenant_id)
