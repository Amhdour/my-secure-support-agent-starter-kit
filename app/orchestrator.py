"""Core support-agent orchestration flow."""

from dataclasses import dataclass
from typing import Sequence

from app.context import build_request_context
from app.modeling import LanguageModel, ModelInput
from app.models import OrchestrationTrace, SupportAgentRequest, SupportAgentResponse
from policies.contracts import PolicyDecision, PolicyEngine
from retrieval.contracts import RetrievalQuery, Retriever
from telemetry.audit import (
    CONFIRMATION_REQUIRED_EVENT,
    DENY_EVENT,
    ERROR_EVENT,
    FALLBACK_EVENT,
    POLICY_DECISION_EVENT,
    REQUEST_END_EVENT,
    REQUEST_START_EVENT,
    RETRIEVAL_DECISION_EVENT,
    TOOL_DECISION_EVENT,
    TOOL_EXECUTION_ATTEMPT_EVENT,
)
from telemetry.audit.contracts import AuditSink
from telemetry.audit.events import create_audit_event, generate_trace_id
from tools.contracts import (
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    ToolDecision,
    ToolInvocation,
    ToolRegistry,
    ToolRouter,
)


@dataclass
class SupportAgentOrchestrator:
    """Policy-aware, RAG-first orchestration entrypoint."""

    policy_engine: PolicyEngine
    retriever: Retriever
    model: LanguageModel
    tool_registry: ToolRegistry
    tool_router: ToolRouter
    audit_sink: AuditSink

    def run(self, request: SupportAgentRequest) -> SupportAgentResponse:
        """Run one request through policy, retrieval, model, and tool-decision stages."""

        trace_id = generate_trace_id()
        context = build_request_context(request, trace_id=trace_id)
        policy_checks: list[str] = []

        self._emit(
            context=context,
            event_type=REQUEST_START_EVENT,
            payload={"session_id": context.session_id, "channel": request.session.channel},
        )

        try:
            retrieval_decision = self._evaluate_policy(
                context=context,
                action="retrieval.search",
                decision_context={"actor_id": context.actor_id, "tenant_id": context.tenant_id},
            )
            policy_checks.append(f"retrieval.search={retrieval_decision.allow}")
            if not retrieval_decision.allow:
                self._emit(context=context, event_type=DENY_EVENT, payload={"stage": "retrieval", "reason": retrieval_decision.reason})
                response = self._blocked_response(request, context, policy_checks, retrieval_decision.reason)
                self._emit_request_end(context=context, status=response.status)
                return response

            retrieval_top_k_cap = retrieval_decision.constraints.get("top_k_cap")
            top_k = 5
            if isinstance(retrieval_top_k_cap, int) and retrieval_top_k_cap > 0:
                top_k = min(top_k, retrieval_top_k_cap)

            allowed_sources = retrieval_decision.constraints.get("allowed_source_ids", [])
            allowed_source_ids: tuple[str, ...] = tuple(allowed_sources) if isinstance(allowed_sources, list) else tuple()

            query = RetrievalQuery(
                request_id=request.request_id,
                tenant_id=context.tenant_id,
                query_text=request.user_text,
                top_k=top_k,
                allowed_source_ids=allowed_source_ids,
            )
            retrieved_docs = tuple(self.retriever.search(query))
            self._emit(
                context=context,
                event_type=RETRIEVAL_DECISION_EVENT,
                payload={
                    "document_count": len(retrieved_docs),
                    "top_k": top_k,
                    "allowed_source_ids": list(allowed_source_ids),
                },
            )

            generation_decision = self._evaluate_policy(
                context=context,
                action="model.generate",
                decision_context={"retrieved_count": len(retrieved_docs), "risk_tier": retrieval_decision.risk_tier},
            )
            policy_checks.append(f"model.generate={generation_decision.allow}")
            if not generation_decision.allow:
                self._emit(context=context, event_type=DENY_EVENT, payload={"stage": "model.generate", "reason": generation_decision.reason})
                response = self._blocked_response(request, context, policy_checks, generation_decision.reason)
                self._emit_request_end(context=context, status=response.status)
                return response

            draft_answer = self.model.generate(
                ModelInput(
                    request_id=request.request_id,
                    user_text=request.user_text,
                    retrieved_context=retrieved_docs,
                    metadata={
                        "session_id": context.session_id,
                        "actor_id": context.actor_id,
                        "tenant_id": context.tenant_id,
                        "risk_tier": retrieval_decision.risk_tier,
                        "trace_id": trace_id,
                    },
                )
            )

            tool_policy_decision = self._evaluate_policy(
                context=context,
                action="tools.route",
                decision_context={"draft_answer_length": len(draft_answer), "risk_tier": retrieval_decision.risk_tier},
            )
            policy_checks.append(f"tools.route={tool_policy_decision.allow}")

            tool_decisions: tuple[ToolDecision, ...] = tuple()
            if tool_policy_decision.allow:
                allowlisted = list(self.tool_registry.list_allowlisted())
                policy_allowed_tools = tool_policy_decision.constraints.get("allowed_tools", [])
                policy_forbidden_tools = set(tool_policy_decision.constraints.get("forbidden_tools", []))

                if isinstance(policy_allowed_tools, list) and policy_allowed_tools:
                    allowlisted = [tool for tool in allowlisted if tool.name in set(policy_allowed_tools)]
                allowlisted = [tool for tool in allowlisted if tool.name not in policy_forbidden_tools]

                tool_decisions = tuple(
                    self.tool_router.route(
                        ToolInvocation(
                            request_id=request.request_id,
                            actor_id=context.actor_id,
                            tenant_id=context.tenant_id,
                            tool_name=tool.name,
                            action="propose",
                            arguments={"draft_answer_preview_length": len(draft_answer)},
                            confirmed=False,
                        )
                    )
                    for tool in allowlisted
                )
                self._emit(
                    context=context,
                    event_type=TOOL_EXECUTION_ATTEMPT_EVENT,
                    payload={"attempted_tools": [tool.name for tool in allowlisted], "attempt_count": len(allowlisted)},
                )
                self._emit(context=context, event_type=TOOL_DECISION_EVENT, payload={"decisions": [decision.status for decision in tool_decisions]})

                for decision in tool_decisions:
                    if decision.status == REQUIRE_CONFIRMATION_DECISION:
                        self._emit(
                            context=context,
                            event_type=CONFIRMATION_REQUIRED_EVENT,
                            payload={"tool_name": decision.tool_name, "reason": decision.reason},
                        )
                    if decision.status == DENY_DECISION:
                        self._emit(
                            context=context,
                            event_type=DENY_EVENT,
                            payload={"stage": "tool.route", "tool_name": decision.tool_name, "reason": decision.reason},
                        )
            elif tool_policy_decision.fallback_to_rag:
                self._emit(
                    context=context,
                    event_type=FALLBACK_EVENT,
                    payload={"mode": "rag_only", "reason": tool_policy_decision.reason},
                )
                tool_decisions = tuple()
            else:
                self._emit(context=context, event_type=DENY_EVENT, payload={"stage": "tools.route", "reason": tool_policy_decision.reason})
                response = self._blocked_response(request, context, policy_checks, tool_policy_decision.reason)
                self._emit_request_end(context=context, status=response.status)
                return response

            trace = OrchestrationTrace(
                policy_checks=tuple(policy_checks),
                retrieved_document_ids=tuple(doc.document_id for doc in retrieved_docs),
                tool_decisions=tuple(decision.tool_name for decision in tool_decisions),
            )
            response = SupportAgentResponse(
                request_id=request.request_id,
                session_id=context.session_id,
                answer_text=draft_answer,
                status="ok",
                context=context,
                retrieved_documents=retrieved_docs,
                tool_decisions=tool_decisions,
                trace=trace,
            )
            self._emit_request_end(context=context, status=response.status)
            return response
        except Exception as exc:  # fail-closed with evidence
<<<<<<< HEAD
            self._emit(context=context, event_type=ERROR_EVENT, payload={"error_type": type(exc).__name__})
=======
            self._emit(context=context, event_type=ERROR_EVENT, payload={"error_type": type(exc).__name__, "message": str(exc)})
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
            response = self._blocked_response(request, context, policy_checks, "internal error")
            self._emit_request_end(context=context, status=response.status)
            return response

    def _evaluate_policy(self, context, action: str, decision_context: dict) -> PolicyDecision:
        decision = self.policy_engine.evaluate(request_id=context.request_id, action=action, context=decision_context)
        self._emit(
            context=context,
            event_type=POLICY_DECISION_EVENT,
            payload={"action": action, "allow": decision.allow, "risk_tier": decision.risk_tier, "reason": decision.reason},
        )
        return decision

    def _blocked_response(
        self,
        request: SupportAgentRequest,
        context,
        policy_checks: Sequence[str],
        reason: str,
    ) -> SupportAgentResponse:
        return SupportAgentResponse(
            request_id=request.request_id,
            session_id=context.session_id,
            answer_text="Request cannot be processed under current policy.",
            status="blocked",
            context=context,
            trace=OrchestrationTrace(
                policy_checks=tuple(policy_checks),
                retrieved_document_ids=tuple(),
                tool_decisions=tuple(),
            ),
        )

    def _emit_request_end(self, context, status: str) -> None:
        self._emit(context=context, event_type=REQUEST_END_EVENT, payload={"status": status})

    def _emit(self, context, event_type: str, payload: dict) -> None:
        self.audit_sink.emit(
            create_audit_event(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.actor_id,
                tenant_id=context.tenant_id,
                event_type=event_type,
                payload=payload,
            )
        )
