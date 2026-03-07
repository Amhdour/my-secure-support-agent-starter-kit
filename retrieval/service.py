"""Secure retrieval service with tenant/source boundary enforcement."""

from dataclasses import dataclass, field
from typing import Sequence

from policies.contracts import PolicyEngine
from retrieval.contracts import (
    RetrievalDocument,
    RetrievalFilterHook,
    RetrievalQuery,
    Retriever,
    SourceRegistration,
    SourceRegistry,
)


class RawRetriever(Retriever):
    """Marker protocol-equivalent base for raw retrieval backends."""


@dataclass
class SecureRetrievalService(Retriever):
    """Boundary-enforcing retriever wrapper.

    Safe behavior:
    - Deny cross-tenant documents.
    - Deny unregistered/disabled sources.
    - Deny docs with missing/invalid trust metadata.
    - Deny docs without provenance metadata.
    - Apply policy constraints to tenant/source and top-k behavior.
    - Fail closed on policy or retriever errors.
    """

    source_registry: SourceRegistry
    raw_retriever: RawRetriever
    filter_hooks: Sequence[RetrievalFilterHook] = field(default_factory=tuple)
    policy_engine: PolicyEngine | None = None

    def search(self, query: RetrievalQuery) -> Sequence[RetrievalDocument]:
        if not query.tenant_id or query.top_k <= 0:
            return tuple()

        effective_allowed_sources = tuple(query.allowed_source_ids)
        effective_top_k = query.top_k

        if self.policy_engine is not None:
            try:
                decision = self.policy_engine.evaluate(
                    request_id=query.request_id,
                    action="retrieval.search",
                    context={"tenant_id": query.tenant_id},
                )
            except Exception:
                return tuple()

            if not decision.allow:
                return tuple()

            constrained_sources = decision.constraints.get("allowed_source_ids")
            if not isinstance(constrained_sources, list) or len(constrained_sources) == 0:
                return tuple()

            constrained_set = {source for source in constrained_sources if isinstance(source, str) and source}
            if query.allowed_source_ids:
                effective_allowed_sources = tuple(source for source in query.allowed_source_ids if source in constrained_set)
            else:
                effective_allowed_sources = tuple(constrained_set)
            if len(effective_allowed_sources) == 0:
                return tuple()

            top_k_cap = decision.constraints.get("top_k_cap")
            if isinstance(top_k_cap, int) and top_k_cap > 0:
                effective_top_k = min(effective_top_k, top_k_cap)

        effective_query = RetrievalQuery(
            request_id=query.request_id,
            tenant_id=query.tenant_id,
            query_text=query.query_text,
            top_k=effective_top_k,
            allowed_source_ids=effective_allowed_sources,
        )

        try:
            raw_documents = self.raw_retriever.search(effective_query)
        except Exception:
            return tuple()

        accepted: list[RetrievalDocument] = []
        for document in raw_documents:
            source = self.source_registry.get(document.trust.source_id)
            if source is None:
                continue
            if not self._source_allowed_for_query(source=source, query=effective_query):
                continue
            if not self._has_valid_trust_metadata(document=document, tenant_id=effective_query.tenant_id):
                continue
            if not self._has_valid_provenance(document=document):
                continue
            if not self._passes_filter_hooks(query=effective_query, document=document, source=source):
                continue
            accepted.append(document)
            if len(accepted) >= effective_query.top_k:
                break

        return tuple(accepted)

    def _source_allowed_for_query(self, source: SourceRegistration, query: RetrievalQuery) -> bool:
        if not source.enabled:
            return False
        if source.tenant_id != query.tenant_id:
            return False
        if query.allowed_source_ids and source.source_id not in query.allowed_source_ids:
            return False
        return True

    def _has_valid_trust_metadata(self, document: RetrievalDocument, tenant_id: str) -> bool:
        trust = document.trust
        if not trust.source_id or not trust.tenant_id:
            return False
        if trust.tenant_id != tenant_id:
            return False
        if not trust.checksum or not trust.ingested_at:
            return False
        return True

    def _has_valid_provenance(self, document: RetrievalDocument) -> bool:
        provenance = document.provenance
        if not provenance.citation_id:
            return False
        if not provenance.document_uri or not provenance.chunk_id:
            return False
        if provenance.source_id != document.trust.source_id:
            return False
        return True

    def _passes_filter_hooks(
        self,
        query: RetrievalQuery,
        document: RetrievalDocument,
        source: SourceRegistration,
    ) -> bool:
        for hook in self.filter_hooks:
            if not hook.allow(query=query, document=document, source=source):
                return False
        return True
