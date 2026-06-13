SUSPICIOUS_PROMPT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "bypass approval",
    "admin mode",
    "disable guardrails",
    "reveal system prompt",
    "show system prompt",
    "forget the rules",
]


def detect_prompt_injection(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_PROMPT_PATTERNS)
