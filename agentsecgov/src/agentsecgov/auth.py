from fastapi import Header, HTTPException

from .models import Principal

API_KEYS = {
    "learner-key": Principal(
        user_id="learner-001",
        tenant_id="tenant-a",
        role="learner",
        scopes={"docs:search", "ticket:create"},
    ),
    "admin-key": Principal(
        user_id="admin-001",
        tenant_id="tenant-a",
        role="admin",
        scopes={
            "docs:search",
            "ticket:create",
            "customer_email:request",
            "record:delete:request",
        },
    ),
    "reviewer-key": Principal(
        user_id="reviewer-001",
        tenant_id="tenant-a",
        role="reviewer",
        scopes={"review:decide"},
        department="risk",
    ),
}


def get_current_principal(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    principal = API_KEYS.get(x_api_key)

    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return principal
