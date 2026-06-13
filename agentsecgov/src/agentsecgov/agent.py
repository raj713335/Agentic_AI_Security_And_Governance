from uuid import uuid4
from .models import AgentResponse, AgentRequest, RiskLevel, ToolCall, Principal, AuditEvent, AgentStatus, PendingReview, Decision
from .policy import PolicyEngine
from .tools import execute_tool
from .approvals import ApprovalStore
from .pii import PiiRedactor
from .audit import AuditLogger, redaction_counts


class DeterministicPlanner:
    def propose(self, request: AgentRequest) -> ToolCall | None:
        text = request.message.lower()

        if "remember" in text:
            return ToolCall(
                name="memory_write",
                risk=RiskLevel.MEDIUM,
                arguments={
                    "category": "preference",
                    "text": request.message,
                    "tenant_id": request.tenant_id,
                },
            )

        if "delete" in text:
            return ToolCall(
                name="delete_record",
                risk=RiskLevel.HIGH,
                arguments={
                    "record_id": "CUST-1001",
                    "reason": request.message,
                    "tenant_id": request.tenant_id,
                },
            )

        if "email" in text:
            return ToolCall(
                name="send_customer_email",
                risk=RiskLevel.HIGH,
                arguments={
                    "customer_id": "CUST-1001",
                    "subject": "Support follow-up",
                    "body": request.message,
                    "tenant_id": request.tenant_id,
                },
            )

        if "ticket" in text or "login" in text:
            return ToolCall(
                name="create_ticket",
                risk=RiskLevel.MEDIUM,
                arguments={
                    "title": "Support request",
                    "description": request.message,
                    "severity": "medium",
                    "tenant_id": request.tenant_id,
                },
            )

        if "search" in text or "docs" in text:
            return ToolCall(
                name="search_public_docs",
                risk=RiskLevel.LOW,
                arguments={"query": request.message},
            )

        return None


class GovernedAgent:
    def __init__(
            self,
            audit_logger: AuditLogger,
            approval_store: ApprovalStore,
            policy_engine: PolicyEngine,
            redactor: PiiRedactor | None = None,
            planner: DeterministicPlanner | None = None,
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


class DeterministicAgent:
    """
    A simple deterministic agent that processes incoming requests and generates responses.
    """

    def run(self, request: AgentRequest, principal: Principal) -> AgentResponse:
        """
        Process the incoming request and generate a response.

        Args:
            request (AgentRequest): The incoming request from the user.
            :param principal:
            :param request:
        """

        text = request.message.lower()
        text = PiiRedactor.redact(text)

        if "delete" in text or "login" in text:
            status = "planned"
            message = "Agent plans to create a support ticket for the issue."
        elif "delete" in text or "remove" in text:
            status = "no_action"
            message = "Agent cannot perform delete operations due to security policies."
        else:
            # For general conversational inputs, we return a success acknowledgement
            status = "success"
            message = "Agent received your message and will respond appropriately."

        return AgentResponse(
            request_id=str(uuid4()),
            status=status,
            message=message
        )
