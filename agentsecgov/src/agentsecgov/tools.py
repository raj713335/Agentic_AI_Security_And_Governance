from __future__ import annotations

from typing import Any, Callable

from .models import RiskLevel, ToolCall, ToolSpec

try:
    from langchain_core.tools import tool as langchain_tool
except Exception:  # pragma: no cover - optional dependency
    def langchain_tool(func: Callable[..., Any]) -> Callable[..., Any]:
        return func

TOOL_SPECS: dict[str, ToolSpec] = {
    "search_public_docs": ToolSpec(
        name="search_public_docs",
        description="Search public support documentation. Must not access private customer data.",
        risk=RiskLevel.low,
        required_scope="docs:search",
        side_effect="read_only",
        requires_review=False,
        business_needs_pii=False,
    ),
    "create_ticket": ToolSpec(
        name="create_ticket",
        description="Create an internal support ticket for a customer support issue.",
        risk=RiskLevel.medium,
        required_scope="ticket:create",
        side_effect="write_support_record",
        requires_review=False,
        business_needs_pii=True,
    ),
    "send_customer_email": ToolSpec(
        name="send_customer_email",
        description="Send an external customer email. Requires human review before execution.",
        risk=RiskLevel.high,
        required_scope="customer_email:request",
        side_effect="external_communication",
        requires_review=True,
        business_needs_pii=True,
    ),
    "delete_record": ToolSpec(
        name="delete_record",
        description="Delete a duplicate customer record. Destructive and requires human review.",
        risk=RiskLevel.high,
        required_scope="record:delete:request",
        side_effect="destructive_write",
        requires_review=True,
        business_needs_pii=False,
    ),
    "wire_funds": ToolSpec(
        name="wire_funds",
        description="Demo critical payment tool. Should be denied unless break-glass conditions exist.",
        risk=RiskLevel.critical,
        required_scope="breakglass:critical",
        side_effect="financial_transfer",
        requires_review=True,
        business_needs_pii=False,
    ),
    "memory_write": ToolSpec(
        name="memory_write",
        description="Store a user preference or task state. Must not store new security rules from user text.",
        risk=RiskLevel.medium,
        required_scope="docs:search",
        side_effect="persistent_memory",
        requires_review=False,
        business_needs_pii=False,
    ),
}


@langchain_tool
def search_public_docs(query: str) -> dict[str, Any]:
    """Search public support documentation."""
    return {
        "source": "public_support_docs",
        "query": query,
        "answer": "Password reset and login troubleshooting steps are available in the public support guide.",
    }


@langchain_tool
def create_ticket(title: str, description: str, severity: str = "medium", tenant_id: str | None = None) -> dict[str, Any]:
    """Create an internal support ticket."""
    return {
        "ticket_id": "TCK-1001",
        "title": title,
        "description": description,
        "severity": severity,
        "status": "created",
        "tenant_id": tenant_id,
    }


@langchain_tool
def send_customer_email(customer_id: str, subject: str, body: str, tenant_id: str | None = None) -> dict[str, Any]:
    """Send a customer email. This is high risk and should be approval gated."""
    return {
        "message_id": "MSG-1001",
        "customer_id": customer_id,
        "subject": subject,
        "status": "sent",
        "tenant_id": tenant_id,
    }


@langchain_tool
def delete_record(record_id: str, reason: str, tenant_id: str | None = None) -> dict[str, Any]:
    """Delete a duplicate record. This is destructive and should be approval gated."""
    return {
        "record_id": record_id,
        "reason": reason,
        "status": "deleted",
        "tenant_id": tenant_id,
    }


@langchain_tool
def wire_funds(payee: str, amount: float, reason: str) -> dict[str, Any]:
    """Demo critical payment tool. Do not auto-execute in normal workflows."""
    return {
        "payee": payee,
        "amount": amount,
        "reason": reason,
        "status": "wired",
    }


@langchain_tool
def memory_write(category: str, text: str, tenant_id: str | None = None) -> dict[str, Any]:
    """Persist a safe memory item."""
    return {
        "category": category,
        "text": text,
        "status": "stored",
        "tenant_id": tenant_id,
    }


TOOL_EXECUTORS: dict[str, Callable[..., dict[str, Any]]] = {
    "search_public_docs": search_public_docs,
    "create_ticket": create_ticket,
    "send_customer_email": send_customer_email,
    "delete_record": delete_record,
    "wire_funds": wire_funds,
    "memory_write": memory_write,
}


def get_tool_spec(tool_name: str) -> ToolSpec | None:
    return TOOL_SPECS.get(tool_name)


def execute_tool(tool_call: ToolCall) -> dict[str, Any]:
    executor = TOOL_EXECUTORS.get(tool_call.name)
    if hasattr(executor, "invoke"):
        return executor.invoke(tool_call.arguments)
    if executor is None:
        raise ValueError(f"Unknown tool: {tool_call.name}")
    return executor(**tool_call.arguments)
