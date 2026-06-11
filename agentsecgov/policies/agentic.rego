package agentsecgov

# Teaching policy for agentic tool calls.
# Input shape:
# {
#   "principal": {"role":"admin", "scopes":["ticket:create"], "tenant_id":"tenant-a", "environment":"local"},
#   "tool": {"name":"delete_record", "risk":"high", "required_scope":"record:delete:request", "requires_review":true},
#   "context": {"has_pii": false, "tenant_id":"tenant-a", "possible_prompt_injection": false}
# }

default decision := {
  "decision": "deny",
  "reason": "no allow rule matched",
  "requires_review": false
}

has_scope(scope) if {
  input.principal.scopes[_] == scope
}

same_tenant if {
  input.principal.tenant_id == input.context.tenant_id
}

critical_without_breakglass if {
  input.tool.risk == "critical"
  not has_scope("breakglass:critical")
}

high_risk if {
  input.tool.risk == "high"
}

required_scope_missing if {
  input.tool.required_scope != null
  not has_scope(input.tool.required_scope)
}

decision := {
  "decision": "deny",
  "reason": "cross-tenant action denied",
  "requires_review": false
} if {
  not same_tenant
}

decision := {
  "decision": "deny",
  "reason": sprintf("missing required scope: %s", [input.tool.required_scope]),
  "requires_review": false
} if {
  required_scope_missing
}

decision := {
  "decision": "deny",
  "reason": "possible prompt injection targeting high-risk action",
  "requires_review": false
} if {
  input.context.possible_prompt_injection
  input.tool.risk == "high"
}

decision := {
  "decision": "deny",
  "reason": "critical action requires break-glass scope",
  "requires_review": false
} if {
  critical_without_breakglass
}

decision := {
  "decision": "review",
  "reason": "critical action requires human review even with break-glass scope",
  "requires_review": true
} if {
  input.tool.risk == "critical"
  has_scope("breakglass:critical")
}

decision := {
  "decision": "review",
  "reason": "high-risk tool requires human review",
  "requires_review": true
} if {
  high_risk
  has_scope(input.tool.required_scope)
}

decision := {
  "decision": "allow",
  "reason": "principal has required scope and tool risk is within autonomy budget",
  "requires_review": false
} if {
  input.tool.risk == "low"
  has_scope(input.tool.required_scope)
  same_tenant
}

decision := {
  "decision": "allow",
  "reason": "principal has required scope and tool risk is within autonomy budget",
  "requires_review": false
} if {
  input.tool.risk == "medium"
  has_scope(input.tool.required_scope)
  same_tenant
  not input.tool.requires_review
}
