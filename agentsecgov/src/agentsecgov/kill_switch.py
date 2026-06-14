DISABLED_TOOLS: set[str] = set()


def disable_tool(tool_name: str) -> None:
    DISABLED_TOOLS.add(tool_name)


def enable_tool(tool_name: str) -> None:
    DISABLED_TOOLS.discard(tool_name)


def is_tool_disabled(tool_name: str) -> bool:
    return tool_name in DISABLED_TOOLS