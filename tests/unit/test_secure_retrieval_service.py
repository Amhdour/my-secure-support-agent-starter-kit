"""Tests for secure retrieval tenant/source boundaries and provenance behavior."""

from retrieval.contracts import (
    DocumentProvenance,
    RetrievalDocument,
    RetrievalQuery,
    SourceRegistration,
    SourceTrustMetadata,
)
from retrieval.registry import InMemorySourceRegistry
from retrieval.service import SecureRetrievalService


class FakeRawRetriever:
    def __init__(self, documents):
        self.documents = tuple(documents)

    def search(self, query: RetrievalQuery):
        return self.documents


def _make_document(
    *,
    doc_id: str,
    source_id: str,
    tenant_id: str,
    checksum: str = "abc123",
    ingested_at: str = "2026-01-01T00:00:00Z",
    citation_id: str = "c1",
    document_uri: str = "kb://password-reset",
    chunk_id: str = "chunk-1",
) -> RetrievalDocument:
    return RetrievalDocument(
        document_id=doc_id,
        content="Support content",
        trust=SourceTrustMetadata(
            source_id=source_id,
            tenant_id=tenant_id,
            checksum=checksum,
            ingested_at=ingested_at,
        ),
        provenance=DocumentProvenance(
            citation_id=citation_id,
            source_id=source_id,
            document_uri=document_uri,
            chunk_id=chunk_id,
        ),
        attributes={"topic": "auth"},
    )


def _query(*, tenant_id: str, allowed_source_ids=()) -> RetrievalQuery:
    return RetrievalQuery(
        request_id="req-1",
        tenant_id=tenant_id,
        query_text="password reset",
        top_k=5,
        allowed_source_ids=allowed_source_ids,
    )


def test_valid_retrieval_returns_document() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-main",
            tenant_id="tenant-a",
            display_name="Main KB",
            enabled=True,
        )
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].document_id == "d1"


def test_unauthorized_source_retrieval_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True)
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("another-source",)))

    assert results == ()


def test_cross_tenant_retrieval_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True)
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-b", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_missing_metadata_fails_closed() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True)
    )
    raw = FakeRawRetriever(
        [
            _make_document(
                doc_id="d1",
                source_id="kb-main",
                tenant_id="tenant-a",
                checksum="",
            )
        ]
    )
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_provenance_presence_in_valid_results() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True)
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].provenance.citation_id
    assert results[0].provenance.document_uri
    assert results[0].provenance.chunk_id


def test_retrieval_fails_closed_on_backend_exception() -> None:
    class RaisingRawRetriever:
        def search(self, query):
            raise RuntimeError("backend unavailable")

    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(source_registry=registry, raw_retriever=RaisingRawRetriever())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


class DenyRetrievalPolicyEngine:
    def evaluate(self, request_id: str, action: str, context: dict):
        from policies.contracts import PolicyDecision

        return PolicyDecision(request_id=request_id, allow=False, reason="retrieval denied by policy")


def test_retrieval_denied_by_policy_returns_empty() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=raw,
        policy_engine=DenyRetrievalPolicyEngine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


class AllowExternalTrustPolicyEngine:
    def evaluate(self, request_id: str, action: str, context: dict):
        from policies.contracts import PolicyDecision

        return PolicyDecision(
            request_id=request_id,
            allow=True,
            reason="retrieval allowed",
            constraints={
                "allowed_source_ids": ["kb-external"],
                "top_k_cap": 5,
                "require_trust_metadata": True,
                "require_provenance": True,
                "allowed_trust_domains": ["external"],
            },
        )


def test_low_trust_source_is_quarantined_by_default() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-external",
            tenant_id="tenant-a",
            display_name="External KB",
            enabled=True,
            trust_domain="external",
        )
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-external", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-external",)))

    assert results == ()


def test_low_trust_source_allowed_when_policy_permits_domain() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-external",
            tenant_id="tenant-a",
            display_name="External KB",
            enabled=True,
            trust_domain="external",
        )
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-external", tenant_id="tenant-a")])
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=raw,
        policy_engine=AllowExternalTrustPolicyEngine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-external",)))

    assert len(results) == 1
    assert results[0].trust.source_id == "kb-external"


def test_malformed_source_registration_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(
        SourceRegistration(
            source_id="kb-main",
            tenant_id="tenant-a",
            display_name="Main KB",
            enabled=True,
            trust_domain="",
        )
    )
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw)

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_malformed_document_shape_fails_closed() -> None:
    class MalformedRawRetriever:
        def search(self, query: RetrievalQuery):
            return ({"document_id": "d1"},)

    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    service = SecureRetrievalService(source_registry=registry, raw_retriever=MalformedRawRetriever())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


class RelaxProvenancePolicyEngine:
    def evaluate(self, request_id: str, action: str, context: dict):
        from policies.contracts import PolicyDecision

        return PolicyDecision(
            request_id=request_id,
            allow=True,
            reason="retrieval allowed",
            constraints={
                "allowed_source_ids": ["kb-main"],
                "top_k_cap": 5,
                "require_trust_metadata": True,
                "require_provenance": False,
                "allowed_trust_domains": ["internal"],
            },
        )


def test_missing_provenance_still_denied_for_accepted_results() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever(
        [
            _make_document(
                doc_id="d1",
                source_id="kb-main",
                tenant_id="tenant-a",
                citation_id="",
            )
        ]
    )
    service = SecureRetrievalService(
        source_registry=registry,
        raw_retriever=raw,
        policy_engine=RelaxProvenancePolicyEngine(),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()
