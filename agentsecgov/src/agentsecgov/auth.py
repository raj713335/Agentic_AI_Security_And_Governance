from __future__ import annotations

from fastapi import Header, HTTPException, status

from .models import Principal


API_KEYS: dict[str, Principal] = {
    "learner-key": Principal(
        user_id="learner-001",
        tenant_id="tenant-a",
        role="learner",
        scopes={"docs:search", "ticket:create"},
        department="support",
        environment="local",
    ),
    "admin-key": Principal(
        user_id="admin-001",
        tenant_id="tenant-a",
        role="admin",
        scopes={
            "docs:search",
            "ticket:create",
            "record:delete:request",
            "customer_email:request",
        },
        department="support",
        environment="local",
    ),
    "reviewer-key": Principal(
        user_id="reviewer-001",
        tenant_id="tenant-a",
        role="reviewer",
        scopes={"review:decide", "docs:search"},
        department="risk",
        environment="local",
    ),
    "breakglass-key": Principal(
        user_id="security-admin-001",
        tenant_id="tenant-a",
        role="security_admin",
        scopes={"breakglass:critical", "review:decide", "docs:search"},
        department="security",
        environment="local",
    ),
}


def get_current_principal(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> Principal:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    principal = API_KEYS.get(x_api_key)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return principal


def require_scope(principal: Principal, scope: str) -> None:
    if not principal.has_scope(scope):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Required scope missing: {scope}",
        )
