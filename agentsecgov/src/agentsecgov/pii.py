import re
from collections import Counter


class PiiRedactor:
    patterns = [
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        ("ACCOUNT_NUMBER", re.compile(r"\bACCT-\d{6,}\b", re.IGNORECASE)),
        ("PHONE", re.compile(r"(?<!\d)\+?\d[\d\s().-]{7,}\d(?!\d)")),
    ]

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        redacted = text
        counts: Counter[str] = Counter()

        for entity_type, pattern in self.patterns:
            matches = pattern.findall(redacted)

            if matches:
                counts[entity_type] += len(matches)
                redacted = pattern.sub(f"[{entity_type}]", redacted)

        return redacted, dict(counts)
