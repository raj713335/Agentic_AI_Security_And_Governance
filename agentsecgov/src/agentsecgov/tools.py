from .models import RiskLevel, ToolSpec

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
