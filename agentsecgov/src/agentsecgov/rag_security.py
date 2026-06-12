def validate_retrieved_document(document: dict, tenant_id: str) -> tuple[bool, str]:
    if document.get("tenant_id") != tenant_id:
        return False, "cross-tenant retrieved document blocked"

    if document.get("approved") is not True:
        return False, "document is not approved for retrieval"

    return True, "document allowed"