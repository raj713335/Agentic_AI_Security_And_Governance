from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, status

from .agent import GovernedAgent
from .approvals import ApprovalStore
from .audit import AuditLogger, redaction_counts
from .auth import get_current_principal, require_scope
from .models import (
    AgentRequest,
    AgentResponse,
    AgentStatus,
    AuditEvent,
    Decision,
    PendingReview,
    Principal,
    ReviewDecision,
    ReviewDecisionRequest,
    ReviewStatus,
    ToolCall,
)
from .policy import PolicyEngine
from .tools import TOOL_SPECS, execute_tool
from .monitoring import detect_anomalies
from .kill_switch import disable_tool

APP_VERSION = "0.1.0"

app = FastAPI(
    title="AgentSecGov API",
    description="API for AgentSecGov, a framework for secure and compliant AI agents.",
    version=APP_VERSION,
)

AUDIT_LOGGER = AuditLogger()
APPROVAL_STORE = ApprovalStore()
POLICY_ENGINE = PolicyEngine()
AGENT = GovernedAgent(AUDIT_LOGGER, APPROVAL_STORE, POLICY_ENGINE)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/agent/run", response_model=AgentResponse)
async def run_agent(request: AgentRequest, principal: Principal = Depends(get_current_principal)) -> AgentResponse:
    # In a real implementation, you would have logic here to process the request
    # and generate a response based on the agent's capabilities and the input message.

    return AGENT.run(request, principal)


@app.get("/reviews/pending")
def list_pending_reviews(
        principal: Principal = Depends(get_current_principal),
):
    require_scope(principal, "review:decide")
    return APPROVAL_STORE.list_pending()


@app.post("/reviews/{review_id}/decision", response_model=AgentResponse)
def decide_review(
        review_id: str,
        decision_request: ReviewDecisionRequest,
        principal: Principal = Depends(get_current_principal),
):
    require_scope(principal, "review:decide")

    review = APPROVAL_STORE.get(review_id)

    if review is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review not found")
    if review.status != ReviewStatus.pending:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Review is no longer pending")

    final_tool_call = review.tool_call
    if decision_request.decision == ReviewDecision.edit:
        if not decision_request.edit_args:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="edit_args are required for edit")
        merged_args = {**review.tool_call.arguments, **decision_request.edit_args}
        final_tool_call = ToolCall(
            id=review.tool_call.id,
            name=review.tool_call.name,
            risk=review.tool_call.risk,
            arguments=merged_args,
        )

    if decision_request.decision == ReviewDecision.reject:
        review.status = ReviewStatus.rejected
        review.reviewer_id = principal.user_id
        review.reviewer_justification = decision_request.justification
        APPROVAL_STORE.save(review)
        AUDIT_LOGGER.record(
            AuditEvent(
                request_id=review.request_id,
                event_type="review_rejected",
                principal_id=review.requester.user_id,
                tenant_id=review.requester.tenant_id,
                tool_name=review.tool_call.name,
                risk=review.policy_decision.risk.value,
                decision="reject",
                reason=decision_request.justification,
                review_id=review.review_id,
                reviewer_id=principal.user_id,
                redaction_counts=redaction_counts(review.redaction_findings),
                status="rejected",
            )
        )
        return AgentResponse(
            request_id=review.request_id,
            status=AgentStatus.denied,
            message="Reviewer rejected the action.",
            tool_call=review.tool_call,
            policy_decision=review.policy_decision,
            review_id=review.review_id,
            redaction_findings=review.redaction_findings,
            risk_summary=f"{review.policy_decision.risk.value} risk; rejected by reviewer.",
        )

    if decision_request.decision == ReviewDecision.respond:
        if not decision_request.response:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="response is required for respond")
        review.status = ReviewStatus.rejected
        review.reviewer_id = principal.user_id
        review.reviewer_justification = decision_request.justification
        review.reviewer_response = decision_request.response
        APPROVAL_STORE.save(review)
        AUDIT_LOGGER.record(
            AuditEvent(
                request_id=review.request_id,
                event_type="review_responded",
                principal_id=review.requester.user_id,
                tenant_id=review.requester.tenant_id,
                tool_name=review.tool_call.name,
                risk=review.policy_decision.risk.value,
                decision="respond",
                reason=decision_request.justification,
                review_id=review.review_id,
                reviewer_id=principal.user_id,
                redaction_counts=redaction_counts(review.redaction_findings),
                status="responded_no_tool_execution",
            )
        )
        return AgentResponse(
            request_id=review.request_id,
            status=AgentStatus.denied,
            message=decision_request.response,
            tool_call=review.tool_call,
            policy_decision=review.policy_decision,
            review_id=review.review_id,
            redaction_findings=review.redaction_findings,
            risk_summary=f"{review.policy_decision.risk.value} risk; reviewer responded without tool execution.",
        )

    if decision_request.decision in {ReviewDecision.approve, ReviewDecision.edit}:
        # Re-run policy on the final arguments. Deny decisions remain binding.
        rechecked_decision, policy_ms = POLICY_ENGINE.evaluate(
            principal=review.requester,
            tool_call=final_tool_call,
            redaction_findings=review.redaction_findings,
            safe_message="reviewed action",
        )
        if rechecked_decision.decision == Decision.deny:
            review.status = ReviewStatus.rejected
            review.reviewer_id = principal.user_id
            review.reviewer_justification = f"Policy denied after review: {rechecked_decision.reason}"
            APPROVAL_STORE.save(review)
            AUDIT_LOGGER.record(
                AuditEvent(
                    request_id=review.request_id,
                    event_type="review_policy_recheck_denied",
                    principal_id=review.requester.user_id,
                    tenant_id=review.requester.tenant_id,
                    tool_name=final_tool_call.name,
                    risk=rechecked_decision.risk.value,
                    decision="deny",
                    reason=rechecked_decision.reason,
                    review_id=review.review_id,
                    reviewer_id=principal.user_id,
                    redaction_counts=redaction_counts(review.redaction_findings),
                    status="denied_after_recheck",
                    policy_version=rechecked_decision.policy_version,
                    policy_ms=policy_ms,
                )
            )
            return AgentResponse(
                request_id=review.request_id,
                status=AgentStatus.denied,
                message=f"Policy denied the reviewed action: {rechecked_decision.reason}.",
                tool_call=final_tool_call,
                policy_decision=rechecked_decision,
                review_id=review.review_id,
                redaction_findings=review.redaction_findings,
                risk_summary=f"{rechecked_decision.risk.value} risk; denied after policy recheck.",
            )

        result = execute_tool(final_tool_call)
        review.status = ReviewStatus.edited_and_approved if decision_request.decision == ReviewDecision.edit else ReviewStatus.approved
        review.reviewer_id = principal.user_id
        review.reviewer_justification = decision_request.justification
        review.final_arguments = final_tool_call.arguments
        APPROVAL_STORE.save(review)
        AUDIT_LOGGER.record(
            AuditEvent(
                request_id=review.request_id,
                event_type="review_approved_tool_executed",
                principal_id=review.requester.user_id,
                tenant_id=review.requester.tenant_id,
                tool_name=final_tool_call.name,
                risk=rechecked_decision.risk.value,
                decision="approve" if decision_request.decision == ReviewDecision.approve else "edit",
                reason=decision_request.justification,
                review_id=review.review_id,
                reviewer_id=principal.user_id,
                redaction_counts=redaction_counts(review.redaction_findings),
                status="executed_after_review",
                policy_version=rechecked_decision.policy_version,
                policy_ms=policy_ms,
                metadata={"result_status": result.get("status")},
            )
        )
        return AgentResponse(
            request_id=review.request_id,
            status=AgentStatus.executed,
            message="Action executed after human review.",
            tool_call=final_tool_call,
            policy_decision=rechecked_decision,
            review_id=review.review_id,
            redaction_findings=review.redaction_findings,
            result=result,
            risk_summary=f"{rechecked_decision.risk.value} risk; executed after human review.",
        )

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported review decision")


@app.get("/audit/events", response_model=list[AuditEvent])
def audit_events(principal: Principal = Depends(get_current_principal)) -> list[AuditEvent]:
    # In this lab, any authenticated user can inspect audit events for learning.
    # Production systems should enforce auditor roles and tenant filters.
    return AUDIT_LOGGER.list_events()


@app.get("/monitoring/alerts")
def monitoring_alerts(
        principal: Principal = Depends(get_current_principal),
):
    return detect_anomalies(AUDIT_LOGGER.list_events())


@app.post("/admin/kill-switch/tools/{tool_name}/disable")
def disable_tool_endpoint(
        tool_name: str,
        principal: Principal = Depends(get_current_principal),
):
    require_scope(principal, "review:decide")
    disable_tool(tool_name)
    return {"status": "disabled", "tool": tool_name}


@app.get("/governance/system-card")
def system_card(
    principal: Principal = Depends(get_current_principal),
):
    return {
        "system_name": "Support Operations Agent",
        "purpose": "Governed agentic support automation",
        "controls": [
            "authentication",
            "least privilege",
            "policy gate",
            "human review",
            "PII redaction",
            "audit logging",
            "anomaly detection",
            "kill switch",
        ],
        "tools": list(TOOL_SPECS.keys()),
    }
