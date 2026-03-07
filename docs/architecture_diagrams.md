# Architecture Diagrams (Runtime-Aligned)

This document visualizes the **implemented** runtime architecture and trust boundaries in this repository.

## 1) System Architecture Overview

```mermaid
flowchart LR
    U[User / Client] --> API[SupportAgentRequest + SessionContext]
    API --> ORCH[app/SupportAgentOrchestrator]

    ORCH -->|policy evaluate: retrieval.search\nmodel.generate\ntools.route| PE[policies/RuntimePolicyEngine]
    ORCH -->|retrieval query| SR[retrieval/SecureRetrievalService]
    SR --> RR[RawRetriever backend adapter]
    SR --> REG[SourceRegistry]

    ORCH -->|model input (RAG envelope)| LM[LanguageModel]

    ORCH -->|tool decision routing| TR[tools/SecureToolRouter]
    TR --> TREG[ToolRegistry]
    TR --> RL[ToolRateLimiter]
    TR -->|policy evaluate: tools.invoke| PE

    ORCH --> AUD[telemetry/audit sink]
    AUD --> JSONL[artifacts/logs/audit.jsonl]
    AUD --> REPLAY[replay artifact]

    EVAL[evals/SecurityEvalRunner] --> ORCH
    EVAL --> TR
    EVAL --> EOUT[artifacts/logs/evals/*.jsonl + *.summary.json]

    LG[launch_gate/SecurityLaunchGate] --> JSONL
    LG --> EOUT
    LG --> REPLAY
    LG --> POL[policies/bundles/default/policy.json]
```

## 2) Request / Data Flow Summary

```mermaid
sequenceDiagram
    participant C as Client
    participant O as SupportAgentOrchestrator
    participant P as RuntimePolicyEngine
    participant R as SecureRetrievalService
    participant M as LanguageModel
    participant T as SecureToolRouter
    participant A as AuditSink

    C->>O: SupportAgentRequest(session tenant/actor)
    O->>A: request.start

    O->>P: evaluate(retrieval.search)
    P-->>O: allow/deny + source/top_k constraints
    alt retrieval denied
        O->>A: deny.event(stage=retrieval)
        O->>A: request.end(blocked)
        O-->>C: blocked response
    else retrieval allowed
        O->>R: search(query + policy constraints)
        R-->>O: trusted/provenance-valid docs
        O->>A: retrieval.decision

        O->>P: evaluate(model.generate)
        alt generation denied
            O->>A: deny.event(stage=model.generate)
            O->>A: request.end(blocked)
            O-->>C: blocked response
        else generation allowed
            O->>M: generate(ModelInput with retrieved_context)
            M-->>O: draft answer

            O->>P: evaluate(tools.route)
            alt tools denied + fallback
                O->>A: fallback.event
                O->>A: request.end(ok)
                O-->>C: ok response (RAG only)
            else tools allowed
                O->>T: route(tool invocation proposals)
                T-->>O: allow/deny/require_confirmation decisions
                O->>A: tool.decision (+ deny/confirmation events as needed)
                O->>A: request.end(ok)
                O-->>C: ok response + tool decisions
            end
        end
    end
```

## 3) Trust-Boundary Map

```mermaid
flowchart TB
    subgraph BoundaryA[Untrusted Boundary]
      Client[External user input]
    end

    subgraph BoundaryB[Application Trusted Runtime]
      Orchestrator[Orchestrator + Policy Engine]
      ToolRouter[SecureToolRouter]
      RetrievalSvc[SecureRetrievalService]
      Audit[Audit pipeline]
    end

    subgraph BoundaryC[Controlled Artifacts]
      PolicyFile[Policy bundle JSON]
      AuditJsonl[Audit JSONL]
      EvalArtifacts[Eval summaries]
      ReplayArtifacts[Replay JSON]
    end

    subgraph BoundaryD[Potentially Lower-Trust Content]
      RawRetriever[Raw retrieval backend]
      Sources[Registered sources\n(trust_domain constrained)]
      RetrievedChunks[Retrieved content chunks]
    end

    Client --> Orchestrator
    Orchestrator --> RetrievalSvc
    RetrievalSvc --> RawRetriever
    RawRetriever --> RetrievedChunks
    RetrievalSvc --> Sources
    Orchestrator --> ToolRouter
    Orchestrator --> Audit

    PolicyFile --> Orchestrator
    PolicyFile --> ToolRouter
    PolicyFile --> RetrievalSvc

    Audit --> AuditJsonl
    Audit --> ReplayArtifacts
```

## 4) Retrieval Boundary Summary (Enforcement View)

```mermaid
flowchart TD
    Q[RetrievalQuery] --> V1{tenant_id + query_text + top_k valid?}
    V1 -- no --> D0[deny: empty result]
    V1 -- yes --> P1{policy_engine configured?}

    P1 -- yes --> PE[policy evaluate retrieval.search]
    PE --> A1{policy allow?}
    A1 -- no --> D1[deny: empty result]
    A1 -- yes --> C1[apply allowed_source_ids + top_k_cap + metadata/trust constraints]

    P1 -- no --> C0[use query constraints + default deny-by-default trust settings]

    C1 --> R[raw retriever search]
    C0 --> R

    R --> F{for each document}
    F --> S1{registered source + source enabled + source well-formed?}
    S1 -- no --> Skip1[drop doc]
    S1 -- yes --> S2{source tenant == query tenant?}
    S2 -- no --> Skip2[drop doc]
    S2 -- yes --> S3{source in allowlisted source_ids?}
    S3 -- no --> Skip3[drop doc]
    S3 -- yes --> S4{source trust_domain allowlisted?}
    S4 -- no --> Skip4[drop doc]
    S4 -- yes --> S5{trust metadata valid if required?}
    S5 -- no --> Skip5[drop doc]
    S5 -- yes --> S6{provenance valid if required?}
    S6 -- no --> Skip6[drop doc]
    S6 -- yes --> Keep[accept doc]
```

## 5) Tool-Routing Flow (Mediation View)

```mermaid
flowchart TD
    I[ToolInvocation] --> V0{request/actor/tenant + tool/action present?}
    V0 -- no --> D0[deny]
    V0 -- yes --> V1{tool registered + allowlisted?}
    V1 -- no --> D1[deny]
    V1 -- yes --> V2{forbidden action?}
    V2 -- yes --> D2[deny]
    V2 -- no --> V3{forbidden fields present?}
    V3 -- yes --> D3[deny]
    V3 -- no --> V4{arguments valid JSON/object keys?}
    V4 -- no --> D4[deny]
    V4 -- yes --> P{policy evaluate tools.invoke}
    P --> P0{policy allow?}
    P0 -- no --> D5[deny]
    P0 -- yes --> C{confirmation required?}
    C -- yes --> RC[require_confirmation]
    C -- no --> RL{rate limit exceeded?}
    RL -- yes --> D6[deny]
    RL -- no --> ALLOW[allow]
```

## 6) Policy Enforcement Points

- `retrieval.search` is evaluated before retrieval execution.
- `model.generate` is evaluated before model generation.
- `tools.route` is evaluated before tool decision routing in orchestrator.
- `tools.invoke` is evaluated inside tool router for each invocation.
- Kill-switch and invalid-policy states are fail-closed.

## 7) Telemetry / Audit Flow

```mermaid
flowchart LR
    O[Orchestrator] --> E[create_audit_event]
    E --> S[AuditSink]
    S --> M[InMemoryAuditSink]
    S --> J[JsonlAuditSink]
    J --> F[artifacts/logs/audit.jsonl]
    F --> R[build_replay_artifact]
    R --> RF[artifacts/logs/replay*.json]
    F --> LG[Launch Gate checks]
```

## Notes for Reviewers

- Diagrams intentionally show only implemented components and decision points.
- Tool scenarios in evals may be `router_only` by design and explicitly labeled in scenario metadata.
- Launch-gate decisions are evidence-tied; `go` is not produced without artifact-backed checks.
