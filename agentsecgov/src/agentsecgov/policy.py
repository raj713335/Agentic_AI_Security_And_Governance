from __future__ import annotations

import os
from time import perf_counter

from .models import Decision, PolicyDecision, Principal, RedactionFinding, RiskLevel, ToolCall, ToolSpec
from .tools import get_tool_spec

POLICY_VERSION = "local-python-policy-v1"


def _contains_instruction_injection(text: str) -> bool:
    lowered = text.lower()
    suspicious = [
        "ignore previous",
        "ignore all previous",
        "override policy",
        "bypass approval",
        "admin mode",
        "reveal system prompt",
        "show system prompt",
        "disable guardrails",
        "forget the rules",
    ]
    return any(token in lowered for token in suspicious)


def _memory_write_is_unsafe(tool_call: ToolCall) -> bool:
    if tool_call.name != "memory_write":
        return False
    text = str(tool_call.arguments.get("text", ""))
    lowered = text.lower()
    risky_terms = ["policy", "ignore", "override", "secret", "admin", "credential", "approval", "bypass"]
    return any(term in lowered for term in risky_terms)


class PolicyEngine:
    """Local policy engine mirroring the Rego policy for easy teaching tests."""

    def __init__(self, disabled_tools: set[str] | None = None) -> None:
        env_disabled = {
            item.strip()
            for item in os.getenv("DISABLED_TOOLS", "").split(",")
            if item.strip()
        }
        self.disabled_tools = disabled_tools or env_disabled

    def evaluate(
        self,
        principal: Principal,
        tool_call: ToolCall,
        redaction_findings: list[RedactionFinding] | None = None,
        safe_message: str = "",
    ) -> tuple[PolicyDecision, float]:
        start = perf_counter()
        decision = self._evaluate(principal, tool_call, redaction_findings or [], safe_message)
        elapsed_ms = (perf_counter() - start) * 1000
        return decision, elapsed_ms

    def _evaluate(
        self,
        principal: Principal,
        tool_call: ToolCall,
        redaction_findings: list[RedactionFinding],
        safe_message: str,
    ) -> PolicyDecision:
        spec = get_tool_spec(tool_call.name)
        has_pii = bool(redaction_findings)

        if spec is None:
            return PolicyDecision(
                decision=Decision.deny,
                reason="unknown tool is not allowed",
                risk=tool_call.risk,
                policy_version=POLICY_VERSION,
            )

        if tool_call.name in self.disabled_tools:
            return PolicyDecision(
                decision=Decision.deny,
                reason="tool disabled by kill switch",
                risk=spec.risk,
                policy_version=POLICY_VERSION,
            )

        if _contains_instruction_injection(safe_message):
            # We do not deny every request with suspicious wording; we deny risky side effects.
            if spec.risk in {RiskLevel.high, RiskLevel.critical}:
                return PolicyDecision(
                    decision=Decision.deny,
                    reason="possible prompt injection targeting high-risk action",
                    risk=spec.risk,
                    policy_version=POLICY_VERSION,
                )

        if _memory_write_is_unsafe(tool_call):
            return PolicyDecision(
                decision=Decision.deny,
                reason="memory write attempts to persist policy-changing or credential-related text",
                risk=spec.risk,
                policy_version=POLICY_VERSION,
            )

        if spec.required_scope and not principal.has_scope(spec.required_scope):
            return PolicyDecision(
                decision=Decision.deny,
                reason=f"missing required scope: {spec.required_scope}",
                risk=spec.risk,
                policy_version=POLICY_VERSION,
            )

        if spec.risk == RiskLevel.critical:
            if principal.environment == "production" and not principal.has_scope("breakglass:critical"):
                return PolicyDecision(
                    decision=Decision.deny,
                    reason="critical action denied in production without break-glass scope",
                    risk=spec.risk,
                    policy_version=POLICY_VERSION,
                )
            if not principal.has_scope("breakglass:critical"):
                return PolicyDecision(
                    decision=Decision.deny,
                    reason="critical action requires break-glass scope",
                    risk=spec.risk,
                    policy_version=POLICY_VERSION,
                )
            return PolicyDecision(
                decision=Decision.review,
                reason="critical action requires human review even with break-glass scope",
                risk=spec.risk,
                requires_review=True,
                policy_version=POLICY_VERSION,
            )

        if principal.tenant_id not in str(tool_call.arguments.get("tenant_id", principal.tenant_id)):
            return PolicyDecision(
                decision=Decision.deny,
                reason="cross-tenant action denied",
                risk=spec.risk,
                policy_version=POLICY_VERSION,
            )

        if has_pii and spec.risk in {RiskLevel.high, RiskLevel.critical} and not spec.business_needs_pii:
            return PolicyDecision(
                decision=Decision.review,
                reason="sensitive data detected in high-risk action context",
                risk=spec.risk,
                requires_review=True,
                policy_version=POLICY_VERSION,
            )

        if spec.requires_review or spec.risk == RiskLevel.high:
            return PolicyDecision(
                decision=Decision.review,
                reason="high-risk tool requires human review",
                risk=spec.risk,
                requires_review=True,
                policy_version=POLICY_VERSION,
            )

        return PolicyDecision(
            decision=Decision.allow,
            reason="principal has required scope and tool risk is within autonomy budget",
            risk=spec.risk,
            requires_review=False,
            policy_version=POLICY_VERSION,
        )