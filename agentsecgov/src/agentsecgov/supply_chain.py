APPROVED_COMPONENTS = {
    "support-mcp": "1.0.0",
}


def is_component_approved(name: str, version: str) -> bool:
    return APPROVED_COMPONENTS.get(name) == version
