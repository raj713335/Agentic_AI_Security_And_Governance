def detect_attack_signals(events: list[dict]) -> list[str]:
    alerts: list[str] = []

    denied_count = sum(1 for event in events if event.get("status") == "denied")
    high_risk_count = sum(1 for event in events if event.get("risk") in {"high", "critical"})

    if denied_count >= 5:
        alerts.append("Repeated denied actions detected")

    if high_risk_count >= 3:
        alerts.append("High-risk tool activity spike detected")

    return alerts


def detect_anomalies(events: list) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []

    denied_count = sum(1 for event in events if event.status == "denied")
    high_risk_count = sum(1 for event in events if event.risk in {"high", "critical"})
    review_count = sum(1 for event in events if event.status == "pending_review")

    if denied_count >= 5:
        alerts.append(
            {
                "severity": "medium",
                "message": "Repeated denied actions detected",
            }
        )

    if high_risk_count >= 3:
        alerts.append(
            {
                "severity": "high",
                "message": "High-risk tool activity spike detected",
            }
        )

    if review_count >= 5:
        alerts.append(
            {
                "severity": "medium",
                "message": "Approval queue spike detected",
            }
        )

    return alerts
