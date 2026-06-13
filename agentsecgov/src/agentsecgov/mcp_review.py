from pydantic import BaseModel


class MCPToolReview(BaseModel):
    server_name: str
    tool_name: str
    risk: str
    approved: bool
    reason: str


APPROVED_MCP_TOOLS = {
    ("support-mcp", "create_ticket"),
    ("support-mcp", "search_docs"),
}

DENIED_MCP_TOOLS = {
    "run_shell",
    "raw_sql",
    "read_secrets",
    "write_file",
}


def review_mcp_tool(server_name: str, tool_name: str) -> MCPToolReview:
    if tool_name in DENIED_MCP_TOOLS:
        return MCPToolReview(
            server_name=server_name,
            tool_name=tool_name,
            risk="critical",
            approved=False,
            reason="Dangerous MCP tool denied",
        )

    if (server_name, tool_name) not in APPROVED_MCP_TOOLS:
        return MCPToolReview(
            server_name=server_name,
            tool_name=tool_name,
            risk="unknown",
            approved=False,
            reason="MCP tool has not been reviewed",
        )

    return MCPToolReview(
        server_name=server_name,
        tool_name=tool_name,
        risk="approved",
        approved=True,
        reason="MCP tool approved",
    )
