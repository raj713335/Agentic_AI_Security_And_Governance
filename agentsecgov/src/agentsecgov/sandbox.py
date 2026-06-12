class SecurityError(Exception):
    pass


BLOCKED_TOOL_NAMES = {
    "run_shell",
    "execute_python",
    "raw_sql",
    "generic_http_request",
    "unrestricted_browser",
}


MAX_ARGUMENT_SIZE = 5000


def sandbox_precheck(tool_name: str, arguments: dict) -> None:
    if tool_name in BLOCKED_TOOL_NAMES:
        raise SecurityError("Broad execution tools are not allowed")

    if len(str(arguments)) > MAX_ARGUMENT_SIZE:
        raise SecurityError("Tool arguments exceed allowed size")