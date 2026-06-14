from pydantic import BaseModel


class AgentIdentity(BaseModel):
    agent_id: str
    purpose: str
    allowed_tools: set[str]
    tenant_id: str


class AgentMessage(BaseModel):
    from_agent: str
    to_agent: str
    tenant_id: str
    requested_action: str
    signed: bool
    correlation_id: str


DELEGATION_POLICY = {
    ("support-agent", "billing-agent"): {"search_public_docs"},
}

APPROVED_AGENTS = {
    "support-agent": AgentIdentity(
        agent_id="support-agent",
        purpose="Handle support workflows",
        allowed_tools={"search_public_docs", "create_ticket", "send_customer_email"},
        tenant_id="tenant-a",
    ),
    "billing-agent": AgentIdentity(
        agent_id="billing-agent",
        purpose="Handle billing workflows",
        allowed_tools={"search_public_docs"},
        tenant_id="tenant-a",
    ),
}


def validate_agent_message(message: AgentMessage) -> tuple[bool, str]:
    if not message.signed:
        return False, "unsigned agent message denied"

    if message.from_agent not in APPROVED_AGENTS:
        return False, "unknown sending agent"

    if message.to_agent not in APPROVED_AGENTS:
        return False, "unknown receiving agent"

    allowed_actions = DELEGATION_POLICY.get(
        (message.from_agent, message.to_agent),
        set(),
    )

    if message.requested_action not in allowed_actions:
        return False, "delegation not allowed"

    return True, "agent message allowed"
