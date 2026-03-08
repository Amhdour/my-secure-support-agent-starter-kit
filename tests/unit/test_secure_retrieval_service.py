"""Tests for secure retrieval tenant/source boundaries and provenance behavior."""

from policies.engine import RuntimePolicyEngine
from policies.schema import build_runtime_policy
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


def _policy_engine(*, allowed_trust_domains: list[str] | None = None) -> RuntimePolicyEngine:
    payload = {
        "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
        "risk_tiers": {"medium": {"max_retrieval_top_k": 5, "tools_enabled": True}},
        "retrieval": {
            "allowed_tenants": ["tenant-a"],
            "tenant_allowed_sources": {"tenant-a": ["kb-main", "kb-external"]},
            "require_trust_metadata": True,
            "require_provenance": True,
            "allowed_trust_domains": allowed_trust_domains or ["internal"],
        },
        "tools": {"allowed_tools": ["ticket_lookup"]},
    }
    return RuntimePolicyEngine(policy=build_runtime_policy(environment="test", payload=payload))


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


def test_allowed_in_boundary_retrieval_returns_document() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].document_id == "d1"


def test_cross_tenant_retrieval_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-b", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_unknown_source_retrieval_is_denied() -> None:
    registry = InMemorySourceRegistry()
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="unknown-source", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("unknown-source",)))

    assert results == ()


def test_unauthorized_source_allowlist_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("another-source",)))

    assert results == ()


def test_missing_metadata_fails_closed() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
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
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_low_trust_source_is_quarantined_by_policy() -> None:
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
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-external",)))

    assert results == ()


def test_low_trust_source_can_be_allowed_by_policy() -> None:
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
        policy_engine=_policy_engine(allowed_trust_domains=["internal", "external"]),
    )

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-external",)))

    assert len(results) == 1




def test_mismatched_trust_boundary_is_denied() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-b")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()


def test_missing_provenance_fails_closed() -> None:
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
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert results == ()

def test_provenance_is_present_on_valid_results() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))
    raw = FakeRawRetriever([_make_document(doc_id="d1", source_id="kb-main", tenant_id="tenant-a")])
    service = SecureRetrievalService(source_registry=registry, raw_retriever=raw, policy_engine=_policy_engine())

    results = service.search(_query(tenant_id="tenant-a", allowed_source_ids=("kb-main",)))

    assert len(results) == 1
    assert results[0].provenance.citation_id
    assert results[0].provenance.document_uri
    assert results[0].provenance.chunk_id


def test_source_registry_rejects_cross_tenant_source_id_reuse() -> None:
    registry = InMemorySourceRegistry()
    registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-a", display_name="Main KB", enabled=True))

    try:
        registry.register(SourceRegistration(source_id="kb-main", tenant_id="tenant-b", display_name="Other KB", enabled=True))
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("expected ValueError on cross-tenant source_id reuse")
