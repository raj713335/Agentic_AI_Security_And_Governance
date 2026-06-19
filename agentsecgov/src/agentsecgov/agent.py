from __future__ import annotations

import re
from uuid import uuid4

from .approvals import ApprovalStore
from .audit import AuditLogger, redaction_counts
from .models import (
    AgentRequest,
    AgentResponse,
    AgentStatus,
    AuditEvent,
    Decision,
    PendingReview,
    Principal,
    RiskLevel,
    ToolCall,
)
from .pii import PiiRedactor
from .policy import PolicyEngine
from .tools import execute_tool, TOOL_EXECUTORS, TOOL_SPECS

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False



class DeterministicPlanner:
    """A predictable planner used so learners can test governance controls.

    Replace this class with a real LangChain/LangGraph planner in advanced labs.
    The security gate should remain unchanged.
    """

    def propose(self, safe_message: str, tenant_id: str) -> ToolCall | None:
        text = safe_message.lower()

        if "wire" in text or "transfer funds" in text or "send money" in text:
            return ToolCall(
                name="wire_funds",
                risk=RiskLevel.critical,
                arguments={"payee": "example-payee", "amount": 1000.0, "reason": safe_message[:200]},
            )

        if "delete" in text or "remove record" in text:
            match = re.search(r"\b(?:cust|rec|acct)-[a-z0-9-]+\b", safe_message, flags=re.IGNORECASE)
            record_id = match.group(0).upper() if match else "CUST-UNKNOWN"
            return ToolCall(
                name="delete_record",
                risk=RiskLevel.high,
                arguments={"record_id": record_id, "reason": safe_message[:250], "tenant_id": tenant_id},
            )

        # Redacted email addresses appear as [EMAIL], so only route to the email tool
        # when the user asks to send an email, not merely when a text contains an address.
        if "send email" in text or "send customer email" in text or "email customer" in text:
            return ToolCall(
                name="send_customer_email",
                risk=RiskLevel.high,
                arguments={
                    "customer_id": "CUST-1001",
                    "subject": "Support follow-up",
                    "body": safe_message[:1000],
                    "tenant_id": tenant_id,
                },
            )

        if "remember" in text or "store memory" in text:
            category = "preference"
            if any(word in text for word in ["policy", "ignore", "override", "admin", "secret"]):
                category = "instruction"
            return ToolCall(
                name="memory_write",
                risk=RiskLevel.medium,
                arguments={"category": category, "text": safe_message[:500], "tenant_id": tenant_id},
            )

        if "search" in text or "lookup" in text or "docs" in text:
            return ToolCall(
                name="search_public_docs",
                risk=RiskLevel.low,
                arguments={"query": safe_message[:500]},
            )

        if "ticket" in text or "issue" in text or "login" in text or "support" in text:
            return ToolCall(
                name="create_ticket",
                risk=RiskLevel.medium,
                arguments={
                    "title": "Support request",
                    "description": safe_message[:1000],
                    "severity": "medium",
                    "tenant_id": tenant_id,
                },
            )

        return None


if LANGCHAIN_AVAILABLE:
    class LangChainPlanner:
        """A live LangChain/OpenAI planner for the governed agent."""
        def __init__(self, model_name: str = "gpt-4o"):
            self.llm = ChatOpenAI(model=model_name)
            self.tools = list(TOOL_EXECUTORS.values())
            self.llm_with_tools = self.llm.bind_tools(self.tools)

        def propose(self, safe_message: str, tenant_id: str) -> ToolCall | None:
            system_prompt = f"You are a helpful support operations agent for tenant {tenant_id}. Use the provided tools to assist the user. If a tool expects a tenant_id, explicitly provide '{tenant_id}'."
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=safe_message)
            ]
            response = self.llm_with_tools.invoke(messages)
            if not response.tool_calls:
                return None
            
            tc = response.tool_calls[0]
            tool_name = tc["name"]
            tool_args = tc["args"]
            
            if "tenant_id" not in tool_args:
                tool_args["tenant_id"] = tenant_id
                
            spec = TOOL_SPECS.get(tool_name)
            risk = spec.risk if spec else RiskLevel.medium
            
            return ToolCall(
                name=tool_name,
                arguments=tool_args,
                risk=risk
            )
else:
    class LangChainPlanner:
        def propose(self, safe_message: str, tenant_id: str) -> ToolCall | None:
            raise NotImplementedError("LangChain dependencies are not installed.")


class GovernedAgent:
    def __init__(
            self,
            audit_logger: AuditLogger,
            approval_store: ApprovalStore,
            policy_engine: PolicyEngine,
            redactor: PiiRedactor | None = None,
            planner: DeterministicPlanner | LangChainPlanner | None = None,
    ) -> None:
        self.audit_logger = audit_logger
        self.approval_store = approval_store
        self.policy_engine = policy_engine
        self.redactor = redactor or PiiRedactor()
        self.planner = planner or DeterministicPlanner()

    def run(self, request: AgentRequest, principal: Principal) -> AgentResponse:
        request_id = str(uuid4())

        if request.tenant_id != principal.tenant_id:
            event = AuditEvent(
                request_id=request_id,
                event_type="request_denied",
                principal_id=principal.user_id,
                tenant_id=principal.tenant_id,
                decision="deny",
                reason="request tenant does not match principal tenant",
                status="denied",
            )
            self.audit_logger.record(event)
            return AgentResponse(
                request_id=request_id,
                status=AgentStatus.denied,
                message="Request denied: tenant mismatch.",
                risk_summary="Denied before planning because tenant mismatch was detected.",
            )

        redaction = self.redactor.redact(request.message)
        self.audit_logger.record(
            AuditEvent(
                request_id=request_id,
                event_type="request_received",
                principal_id=principal.user_id,
                tenant_id=principal.tenant_id,
                redaction_counts=redaction_counts(redaction.findings),
                safe_message=redaction.text,
                status="received",
            )
        )

        tool_call = self.planner.propose(redaction.text, request.tenant_id)

        if tool_call is None:
            self.audit_logger.record(
                AuditEvent(
                    request_id=request_id,
                    event_type="no_tool_proposed",
                    principal_id=principal.user_id,
                    tenant_id=principal.tenant_id,
                    redaction_counts=redaction_counts(redaction.findings),
                    safe_message=redaction.text,
                    status="no_action",
                )
            )
            return AgentResponse(
                request_id=request_id,
                status=AgentStatus.no_action,
                message="No tool action was needed. Provide a support, search, memory, email, delete, or transfer request for the lab.",
                redaction_findings=redaction.findings,
                risk_summary="No action proposed.",
            )

        self.audit_logger.record(
            AuditEvent(
                request_id=request_id,
                event_type="tool_proposed",
                principal_id=principal.user_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_call.name,
                risk=tool_call.risk.value,
                redaction_counts=redaction_counts(redaction.findings),
                safe_message=redaction.text,
                status="proposed",
                metadata={"tool_args_preview": self._safe_args_preview(tool_call.arguments)},
            )
        )

        policy_decision, policy_ms = self.policy_engine.evaluate(
            principal=principal,
            tool_call=tool_call,
            redaction_findings=redaction.findings,
            safe_message=redaction.text,
        )

        if policy_decision.decision == Decision.deny:
            self.audit_logger.record(
                AuditEvent(
                    request_id=request_id,
                    event_type="policy_decision",
                    principal_id=principal.user_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_call.name,
                    risk=policy_decision.risk.value,
                    decision=policy_decision.decision.value,
                    reason=policy_decision.reason,
                    redaction_counts=redaction_counts(redaction.findings),
                    status="denied",
                    policy_version=policy_decision.policy_version,
                    policy_ms=policy_ms,
                    safe_message=redaction.text,
                )
            )
            return AgentResponse(
                request_id=request_id,
                status=AgentStatus.denied,
                message=f"Action denied: {policy_decision.reason}.",
                tool_call=tool_call,
                policy_decision=policy_decision,
                redaction_findings=redaction.findings,
                risk_summary=f"{policy_decision.risk.value} risk; denied by policy.",
            )

        if policy_decision.decision == Decision.review or policy_decision.requires_review:
            review = PendingReview(
                request_id=request_id,
                requester=principal,
                tool_call=tool_call,
                policy_decision=policy_decision,
                redaction_findings=redaction.findings,
            )
            self.approval_store.create(review)
            self.audit_logger.record(
                AuditEvent(
                    request_id=request_id,
                    event_type="review_created",
                    principal_id=principal.user_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_call.name,
                    risk=policy_decision.risk.value,
                    decision=policy_decision.decision.value,
                    reason=policy_decision.reason,
                    review_id=review.review_id,
                    redaction_counts=redaction_counts(redaction.findings),
                    status="pending_review",
                    policy_version=policy_decision.policy_version,
                    policy_ms=policy_ms,
                    safe_message=redaction.text,
                )
            )
            return AgentResponse(
                request_id=request_id,
                status=AgentStatus.pending_review,
                message=f"Action requires human review: {policy_decision.reason}.",
                tool_call=tool_call,
                policy_decision=policy_decision,
                review_id=review.review_id,
                redaction_findings=redaction.findings,
                risk_summary=f"{policy_decision.risk.value} risk; human review required.",
            )

        result = execute_tool(tool_call)
        self.audit_logger.record(
            AuditEvent(
                request_id=request_id,
                event_type="tool_executed",
                principal_id=principal.user_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_call.name,
                risk=policy_decision.risk.value,
                decision=policy_decision.decision.value,
                reason=policy_decision.reason,
                redaction_counts=redaction_counts(redaction.findings),
                status="executed",
                policy_version=policy_decision.policy_version,
                policy_ms=policy_ms,
                safe_message=redaction.text,
                metadata={"result_status": result.get("status")},
            )
        )
        return AgentResponse(
            request_id=request_id,
            status=AgentStatus.executed,
            message="Action executed after policy approval.",
            tool_call=tool_call,
            policy_decision=policy_decision,
            redaction_findings=redaction.findings,
            result=result,
            risk_summary=f"{policy_decision.risk.value} risk; executed within policy.",
        )

    def _safe_args_preview(self, args: dict[str, object]) -> dict[str, object]:
        preview: dict[str, object] = {}
        for key, value in args.items():
            if key in {"body", "description", "reason", "text", "query"}:
                preview[key] = str(value)[:120]
            else:
                preview[key] = value
        return preview
