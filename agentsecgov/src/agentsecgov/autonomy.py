class AutonomyBudgetExceeded(Exception):
    pass


MAX_TOOL_CALLS_PER_REQUEST = 3


def enforce_autonomy_budget(tool_call_count: int) -> None:
    if tool_call_count > MAX_TOOL_CALLS_PER_REQUEST:
        raise AutonomyBudgetExceeded("Maximum tool calls per request exceeded")
