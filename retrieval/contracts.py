"""Retrieval contracts with source registration and provenance structures."""

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence


@dataclass(frozen=True)
class SourceRegistration:
    """Registered retrieval source bound to an explicit tenant boundary."""

    source_id: str
    tenant_id: str
    display_name: str
    enabled: bool = True
    trust_domain: str = "internal"


@dataclass(frozen=True)
class SourceTrustMetadata:
    """Trust metadata required for safe retrieval acceptance."""

    source_id: str
    tenant_id: str
    checksum: str
    ingested_at: str


@dataclass(frozen=True)
class DocumentProvenance:
    """Citation-friendly provenance metadata for each retrieved document/chunk."""

    citation_id: str
    source_id: str
    document_uri: str
    chunk_id: str


@dataclass(frozen=True)
class RetrievalQuery:
    """Tenant-aware retrieval query envelope."""

    request_id: str
    tenant_id: str
    query_text: str
    top_k: int
    allowed_source_ids: Sequence[str] = tuple()


@dataclass(frozen=True)
class RetrievalDocument:
    """Retrieved chunk with required trust and provenance metadata."""

    document_id: str
    content: str
    trust: SourceTrustMetadata
    provenance: DocumentProvenance
    attributes: Mapping[str, str]


class Retriever(Protocol):
    def search(self, query: RetrievalQuery) -> Sequence[RetrievalDocument]:
        """Search trusted documents relevant to the query."""
        ...


class SourceRegistry(Protocol):
    def register(self, source: SourceRegistration) -> None:
        """Register or update one retrieval source."""
        ...

    def get(self, source_id: str) -> SourceRegistration | None:
        """Get one source registration by ID."""
        ...

    def list_for_tenant(self, tenant_id: str) -> Sequence[SourceRegistration]:
        """List sources explicitly registered for a tenant."""
        ...


class RetrievalFilterHook(Protocol):
    def allow(
        self,
        query: RetrievalQuery,
        document: RetrievalDocument,
        source: SourceRegistration,
    ) -> bool:
        """Return True when document is acceptable for this query context."""
        ...
