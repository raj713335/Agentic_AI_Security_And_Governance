ALLOWED_GOAL_TOOLS = {
    "login_support": {"search_public_docs", "create_ticket"},
    "customer_email": {"send_customer_email"},
    "record_cleanup": {"delete_record"},
    "general_support": {"search_public_docs", "create_ticket"},
}


def classify_goal(message: str) -> str:
    text = message.lower()

    if "login" in text or "password" in text:
        return "login_support"

    if "send email" in text or "email customer" in text or "customer email" in text:
        return "customer_email"

    if "delete record" in text or "duplicate record" in text:
        return "record_cleanup"

    return "general_support"


def goal_integrity_check(message: str, tool_name: str) -> tuple[bool, str]:
    goal = classify_goal(message)
    allowed_tools = ALLOWED_GOAL_TOOLS.get(goal, {"search_public_docs", "create_ticket"})

    if tool_name not in allowed_tools:
        return False, f"Tool {tool_name} does not match classified goal {goal}"

    return True, "Tool matches user goal"
