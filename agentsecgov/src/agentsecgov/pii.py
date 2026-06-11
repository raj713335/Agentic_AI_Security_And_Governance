from __future__ import annotations

import re
from collections import Counter

from .models import RedactionFinding, RedactionResult


class PiiRedactor:
    """Small local redactor used for repeatable teaching tests.

    Production systems can replace or extend this with Microsoft Presidio.
    The control pattern remains the same: analyze before prompt/logging, redact values,
    and retain non-sensitive evidence such as entity type and count.
    """

    PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
        ("PHONE", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)"), "[PHONE]"),
        ("ACCOUNT_NUMBER", re.compile(r"\bACCT-\d{6,}\b", re.IGNORECASE), "[ACCOUNT_NUMBER]"),
    ]

    def redact(self, text: str) -> RedactionResult:
        counts: Counter[str] = Counter()
        redacted = text
        for entity_type, pattern, replacement in self.PATTERNS:
            matches = pattern.findall(redacted)
            if matches:
                counts[entity_type] += len(matches)
                redacted = pattern.sub(replacement, redacted)
        findings = [RedactionFinding(entity_type=k, count=v) for k, v in sorted(counts.items())]
        return RedactionResult(text=redacted, findings=findings)
