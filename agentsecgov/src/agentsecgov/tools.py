from .models import RiskLevel, ToolSpec, ToolCall
from .sandbox import sandbox_precheck

TOOL_SPECS: dict[str, ToolSpec] = {
    "search_public_docs": ToolSpec(
        name="search_public_docs",
        description="Search public support documentation.",
        risk=RiskLevel.LOW,
        required_scope="docs:search",
        side_effect="read_only",
    ),
    "create_ticket": ToolSpec(
        name="create_ticket",
        description="Create an internal support ticket.",
        risk=RiskLevel.MEDIUM,
        required_scope="ticket:create",
        side_effect="write_support_record",
    ),
    "send_customer_email": ToolSpec(
        name="send_customer_email",
        description="Send an external customer email.",
        risk=RiskLevel.HIGH,
        required_scope="customer_email:request",
        side_effect="external_communication",
        requires_review=True,
        business_needs_pii=True,
    ),
    "delete_record": ToolSpec(
        name="delete_record",
        description="Delete a duplicate customer record.",
        risk=RiskLevel.HIGH,
        required_scope="record:delete:request",
        side_effect="destructive_write",
        requires_review=True,
    ),
    "wire_funds": ToolSpec(
        name="wire_funds",
        description="Demo critical payment tool.",
        risk=RiskLevel.CRITICAL,
        required_scope="breakglass:critical",
        side_effect="financial_transfer",
        requires_review=True,
    ),
}


def get_tool_spec(tool_name: str) -> ToolSpec | None:
    return TOOL_SPECS.get(tool_name)


def execute_tool(tool_call: ToolCall) -> dict:
    sandbox_precheck(tool_call.name, tool_call.arguments)

    if tool_call.name == "search_public_docs":
        return {
            "status": "searched",
            "answer": "Password reset guidance found in public support docs.",
        }

    if tool_call.name == "create_ticket":
        return {
            "status": "created",
            "ticket_id": "TCK-1001",
            **tool_call.arguments,
        }

    if tool_call.name == "send_customer_email":
        return {
            "status": "sent",
            "message_id": "MSG-1001",
            **tool_call.arguments,
        }

    if tool_call.name == "delete_record":
        return {
            "status": "deleted",
            **tool_call.arguments,
        }

    raise ValueError(f"Unknown tool: {tool_call.name}")
