package agentsecgov

default decision := {
  "decision": "deny",
  "reason": "no allow rule matched"
}

has_scope(scope) if {
  input.principal.scopes[_] == scope
}

decision := {
  "decision": "deny",
  "reason": "goal mismatch"
} if {
  input.context.goal_match == false
}

decision := {
  "decision": "deny",
  "reason": "missing required scope"
} if {
  input.tool.required_scope != null
  not has_scope(input.tool.required_scope)
}

decision := {
  "decision": "review",
  "reason": "high-risk tool requires human review"
} if {
  input.tool.risk == "high"
  has_scope(input.tool.required_scope)
}

decision := {
  "decision": "deny",
  "reason": "critical tool denied by default"
} if {
  input.tool.risk == "critical"
}

decision := {
  "decision": "allow",
  "reason": "low or medium risk scoped action allowed"
} if {
  input.tool.risk == "low"
  has_scope(input.tool.required_scope)
}

decision := {
  "decision": "allow",
  "reason": "low or medium risk scoped action allowed"
} if {
  input.tool.risk == "medium"
  has_scope(input.tool.required_scope)
}