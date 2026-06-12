from .goal import goal_integrity_check
from .models import Principal, ToolCall
from .security_signals import detect_prompt_injection
from .tools import get_tool_spec


class PolicyDecision:
    def __init__(
        self,
        decision: str,
        reason: str,
        risk: str,
        requires_review: bool = False,
    ) -> None:
        self.decision = decision
        self.reason = reason
        self.risk = risk
        self.requires_review = requires_review


class PolicyEngine:
    def __init__(self, disabled_tools: set[str] | None = None) -> None:
        self.disabled_tools = disabled_tools or set()

    def evaluate(
        self,
        principal: Principal,
        tool_call: ToolCall,
        original_message: str,
    ) -> PolicyDecision:
        spec = get_tool_spec(tool_call.name)

        if spec is None:
            return PolicyDecision(
                decision="deny",
                reason="unknown tool is not allowed",
                risk=tool_call.risk.value,
            )

        if tool_call.name in self.disabled_tools:
            return PolicyDecision(
                decision="deny",
                reason="tool disabled by kill switch",
                risk=spec.risk.value,
            )

        goal_ok, goal_reason = goal_integrity_check(original_message, tool_call.name)

        if not goal_ok:
            return PolicyDecision(
                decision="deny",
                reason=goal_reason,
                risk=spec.risk.value,
            )

        if detect_prompt_injection(original_message) and spec.risk.value in {"high", "critical"}:
            return PolicyDecision(
                decision="deny",
                reason="possible prompt injection targeting high-risk action",
                risk=spec.risk.value,
            )

        if spec.required_scope and not principal.has_scope(spec.required_scope):
            return PolicyDecision(
                decision="deny",
                reason=f"missing required scope: {spec.required_scope}",
                risk=spec.risk.value,
            )

        if spec.risk.value == "critical":
            return PolicyDecision(
                decision="deny",
                reason="critical tool denied by default",
                risk=spec.risk.value,
            )

        if spec.requires_review or spec.risk.value == "high":
            return PolicyDecision(
                decision="review",
                reason="high-risk tool requires human review",
                risk=spec.risk.value,
                requires_review=True,
            )

        return PolicyDecision(
            decision="allow",
            reason="principal has required scope and tool risk is within policy",
            risk=spec.risk.value,
        )