def detect_attack_signals(events: list[dict]) -> list[str]:
    alerts: list[str] = []

    denied_count = sum(1 for event in events if event.get("status") == "denied")
    high_risk_count = sum(1 for event in events if event.get("risk") in {"high", "critical"})

    if denied_count >= 5:
        alerts.append("Repeated denied actions detected")

    if high_risk_count >= 3:
        alerts.append("High-risk tool activity spike detected")

    return alerts