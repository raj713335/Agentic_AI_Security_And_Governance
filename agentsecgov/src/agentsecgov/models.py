from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"
    review = "review"


class AgentStatus(str, Enum):
    executed = "executed"
    denied = "denied"
    pending_review = "pending_review"
    no_action = "no_action"


class Principal(BaseModel):
    user_id: str
    tenant_id: str
    role: str
    scopes: set[str] = Field(default_factory=set)
    department: str = "support"
    environment: Literal["local", "dev", "staging", "production"] = "local"

    model_config = ConfigDict(extra="forbid")

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class AgentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    tenant_id: str = "tenant-a"
    session_id: str | None = None


class ToolSpec(BaseModel):
    name: str
    description: str
    risk: RiskLevel
    required_scope: str | None = None
    side_effect: str = "none"
    requires_review: bool = False
    business_needs_pii: bool = False


class ToolCall(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel


class RedactionFinding(BaseModel):
    entity_type: str
    count: int = 1


class RedactionResult(BaseModel):
    text: str
    findings: list[RedactionFinding] = Field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    risk: RiskLevel
    requires_review: bool = False
    policy_version: str = "local-python-policy-v1"

    @property
    def allowed_to_execute(self) -> bool:
        return self.decision == Decision.allow and not self.requires_review


class ReviewStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    edited_and_approved = "edited_and_approved"
    rejected = "rejected"


class ReviewDecision(str, Enum):
    approve = "approve"
    edit = "edit"
    reject = "reject"
    respond = "respond"


class PendingReview(BaseModel):
    review_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    requester: Principal
    tool_call: ToolCall
    policy_decision: PolicyDecision
    redaction_findings: list[RedactionFinding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ReviewStatus = ReviewStatus.pending
    reviewer_id: str | None = None
    reviewer_justification: str | None = None
    final_arguments: dict[str, Any] | None = None
    reviewer_response: str | None = None


class ReviewDecisionRequest(BaseModel):
    decision: ReviewDecision
    justification: str = Field(min_length=12, max_length=1000)
    edit_args: dict[str, Any] | None = None
    response: str | None = None


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
