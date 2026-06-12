from pydantic import BaseModel, Field
from enum import Enum
from typing import Any


class AgentRequest(BaseModel):
    """
    Model for incoming agent requests.
    """
    message: str = Field(min_length=5, max_length=100, description="message from the user to the agent")
    tenant_id: str = "tenant-a"


class AgentResponse(BaseModel):
    """
    Model for outgoing agent responses.
    """
    request_id: str = Field(description="unique identifier for the request")
    status: str = Field(description="status of the agent's response, e.g., 'success' or 'error'")
    message: str = Field(description="the agent's response message")


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
