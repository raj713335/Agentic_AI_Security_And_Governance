The system contains these components:

```text
FastAPI API
Authentication layer
Principal model
PII redactor
Deterministic planner or LangChain-style planner
Goal integrity checker
Policy engine
Tool registry
Sandboxed executor
Approval queue
Output validator
Audit logger
Anomaly detector
Kill switch registry
Governance artifacts
```

The most important boundary is between:

```text
Agent proposes tool call
```

and

```text
Tool actually executes
```

Everything in this course protects that boundary.

### Exercise

Label each component in the architecture as one of these:

```text
Input control
Planning control
Policy control
Execution control
Output control
Monitoring control
Governance evidence
```
