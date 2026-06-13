from fastapi import FastAPI, Depends, HTTPException

from .models import AgentRequest, AgentResponse, Principal, ReviewDecisionRequest
from .agent import GovernedAgent
from .auth import get_current_principal, require_scope
from .approvals import ApprovalStore, APPROVAL_STORE
from .tools import TOOL_SPECS, execute_tool, ToolCall

app = FastAPI(
    title="AgentSecGov API",
    description="API for AgentSecGov, a framework for secure and compliant AI agents.",
    version="0.1.0",
)

AGENT = GovernedAgent(approval_store=APPROVAL_STORE)


@app.get("/health")
async def health_check():
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


@app.post("/reviews/{review_id}/decision")
def decide_review(
    review_id: str,
    decision_request: ReviewDecisionRequest,
    principal: Principal = Depends(get_current_principal),
):
    require_scope(principal, "review:decide")

    review = APPROVAL_STORE.get(review_id)

    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")

    if decision_request.decision == "edit":
        if not decision_request.edit_args:
            raise HTTPException(status_code=422, detail="edit_args required")

        final_args = {
            **review.tool_call.arguments,
            **decision_request.edit_args,
        }

        edited_tool_call = ToolCall(
            name=review.tool_call.name,
            risk=review.tool_call.risk,
            arguments=final_args,
        )

        result = execute_tool(edited_tool_call)
        review.status = "edited_and_approved"

        return {
            "status": "executed",
            "message": "Edited action executed after human review",
            "review_id": review.review_id,
            "result": result,
        }

    if decision_request.decision == "reject":
        review.status = "rejected"
        return {
            "status": "denied",
            "message": "Reviewer rejected the action",
            "review_id": review.review_id,
        }

    if decision_request.decision == "approve":
        result = execute_tool(review.tool_call)
        review.status = "approved"
        return {
            "status": "executed",
            "message": "Action executed after human review",
            "review_id": review.review_id,
            "result": result,
        }

    if decision_request.decision == "respond":
        if not decision_request.response:
            raise HTTPException(status_code=422, detail="response required")

        review.status = "responded"

        return {
            "status": "responded",
            "message": decision_request.response,
            "review_id": review.review_id,
        }

    raise HTTPException(status_code=400, detail="Unsupported decision")
