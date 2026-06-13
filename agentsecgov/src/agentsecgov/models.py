from pydantic import BaseModel, Field
from enum import Enum
from typing import Any
from datetime import datetime, timezone
from uuid import uuid4


class AgentRequest(BaseModel):
    """
    Model for incoming agent requests.
    """
    message: str = Field(min_length=5, max_length=100, description="message from the user to the agent")
    tenant_id: str = "tenant-a"

class AgentStatus(str, Enum):
    executed = "executed"
    denied = "denied"
    pending_review = "pending_review"
    no_action = "no_action"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolSpec(BaseModel):
    name: str = Field(description="name of the tool")
    description: str = Field(description="description of the tool's functionality")
    risk: RiskLevel = Field(description="risk level associated with using this tool")
    required_scope: str | None = Field(default=None, description="required scope for using this tool, if any")
    requires_review: bool = Field(default=False, description="whether this tool call requires human review")
    side_effect: str | None = False
    business_needs_pii: bool = False


class ToolCall(BaseModel):
    name: str = Field(description="name of the tool being called")
    arguments: dict[str, Any] = Field(description="arguments for the tool call")
    risk: RiskLevel = Field(description="risk level of this tool call")


class Principal(BaseModel):
    user_id: str
    tenant_id: str
    role: str
    scopes: set[str]
    department: str = "support"
    environment: str = "local"
    agent_id: str = "support-agent"

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class PendingReview(BaseModel):
    review_id: str
    request_id: str
    requester_id: str
    tenant_id: str
    tool_call: ToolCall
    policy_reason: str
    risk: str
    status: str = "pending"


class ReviewDecisionRequest(BaseModel):
    decision: str
    justification: str
    edit_args: dict | None = None
    response: str | None = None


class RedactionFinding(BaseModel):
    entity_type: str
    count: int = 1


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"
    review = "review"


class ReviewStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    edited_and_approved = "edited_and_approved"
    rejected = "rejected"


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    risk: RiskLevel
    requires_review: bool = False
    policy_version: str = "local-python-policy-v1"

    @property
    def allowed_to_execute(self) -> bool:
        return self.decision == Decision.allow and not self.requires_review


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str
    event_type: str
    principal_id: str | None = None
    tenant_id: str | None = None
    tool_name: str | None = None
    risk: str | None = None
    decision: str | None = None
    reason: str | None = None
    review_id: str | None = None
    reviewer_id: str | None = None
    redaction_counts: dict[str, int] = Field(default_factory=dict)
    status: str | None = None
    policy_version: str = "local-python-policy-v1"
    app_version: str = "0.1.0"
    policy_ms: float | None = None
    safe_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    request_id: str
    status: AgentStatus
    message: str
    tool_call: ToolCall | None = None
    policy_decision: PolicyDecision | None = None
    review_id: str | None = None
    redaction_findings: list[RedactionFinding] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    risk_summary: str | None = None
