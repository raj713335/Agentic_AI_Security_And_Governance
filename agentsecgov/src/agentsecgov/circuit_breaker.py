def detect_multi_agent_cascade(events: list) -> tuple[bool, str]:
    high_risk_events = [
        event
        for event in events
        if getattr(event, "risk", None) in {"high", "critical"}
    ]

    agent_ids = {
        event.principal_id
        for event in high_risk_events
        if getattr(event, "principal_id", None)
    }

    if len(high_risk_events) >= 3 and len(agent_ids) >= 2:
        return True, "possible cascading multi-agent high-risk activity"

    return False, "no cascade detected"
