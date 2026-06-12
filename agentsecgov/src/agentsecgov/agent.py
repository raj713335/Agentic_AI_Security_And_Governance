from uuid import uuid4
from .models import AgentResponse, AgentRequest, RiskLevel, ToolCall, Principal


class DeterministicPlanner:
    def propose(self, request: AgentRequest) -> ToolCall | None:
        text = request.message.lower()

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


class DeterministicAgent:
    """
    A simple deterministic agent that processes incoming requests and generates responses.
    """

    def run(self, request: AgentRequest, principal: Principal) -> AgentResponse:
        """
        Process the incoming request and generate a response.

        Args:
            request (AgentRequest): The incoming request from the user.
            :param request:
        """

        text = request.message.lower()

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
