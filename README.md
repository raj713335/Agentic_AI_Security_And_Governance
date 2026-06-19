# Agentic AI Security and Governance

This project is the companion codebase for the **Agentic AI Security and Governance** course. It demonstrates how to securely architect, govern, and monitor autonomous AI agents using a robust defense-in-depth approach.

## The Core Security Boundary

The most critical architectural principle taught in this course is establishing a firm boundary between an AI's intent and actual system execution:

1. **Agent proposes a tool call.**
2. **[ SECURITY & GOVERNANCE GATE ]**
3. **Tool actually executes.**

Everything in this project is designed to protect this boundary, ensuring that generative AI models (which are inherently non-deterministic) cannot directly execute high-risk actions without explicit authorization, policy checks, and potentially human review.

## Security Controls Implemented

The framework categorizes security measures into distinct control layers. This repository includes working implementations of each:

### 1. Input Controls
*   **Authentication & Least Privilege (`auth.py`)**: Assigns API keys to `Principal` identities, granting them specific scopes and roles (e.g., `learner`, `admin`, `reviewer`).
*   **PII Redaction (`pii.py`)**: Intercepts user inputs to detect and redact Personally Identifiable Information (Emails, Phone Numbers, Account IDs) *before* they are sent to the LLM or stored in audit logs.
*   **Context Security (`context_security.py`)**: Wraps retrieved document context in clear delimiters to prevent untrusted data from masquerading as system instructions.

### 2. Planning Controls
*   **Live LangChain Integration (`agent.py`)**: Uses a LangChain planner powered by `gpt-4o` that proposes actions, seamlessly dropping into the security gates for evaluation. Falls back to a deterministic planner if no API key is provided.
*   **Goal Integrity (`goal.py`)**: Classifies the user's overarching intent and ensures the tools proposed by the agent align with that approved goal (preventing goal hijacking).
*   **Security Signals (`security_signals.py`)**: Detects known prompt injection and jailbreak phrases.
*   **Autonomy Budgets (`autonomy.py`)**: Hardcodes limits on how many sequential actions an agent can take without requiring a pause or re-authorization.

### 3. Policy Controls
*   **Policy Engine (`policy.py` & `agentic.rego`)**: Evaluates every proposed tool call against organizational rules. Decisions result in `allow`, `deny`, or `review`. It evaluates risk levels, tenant isolation, and required scopes.
*   **Multi-Agent Delegation (`multi_agent.py`)**: Enforces cryptographic signing and strict policies on which agents (e.g., `support-agent`) can delegate tasks to other agents (e.g., `billing-agent`).

### 4. Execution Controls
*   **Approval Queue / Human-in-the-Loop (`approvals.py`)**: When the policy engine returns `review`, execution is paused, and the request is queued. Human reviewers can approve, edit, reject, or safely respond without executing the tool.
*   **Sandboxed Execution (`sandbox.py`)**: Validates argument sizes and hard-blocks overly broad execution tools (like `run_shell` or `raw_sql`).
*   **MCP Tool Review (`mcp_review.py`)**: Evaluates dynamically loaded Model Context Protocol (MCP) tools against an approved registry before allowing their use.

### 5. Output Controls
*   **Output Validation (`output_validation.py`)**: Inspects the drafted outputs of tools (such as external customer emails) for sensitive requests (e.g., asking for passwords or API keys) before they are sent.

### 6. Monitoring & Operations
*   **Audit Logging (`audit.py`)**: Maintains a tamper-evident JSONL audit trail of all requests, proposed tools, policy decisions, redaction counts, and reviewer actions.
*   **Anomaly Detection (`monitoring.py`)**: Scans the audit trail for spikes in high-risk tool usage or repeated denied actions, generating alerts.
*   **Circuit Breakers (`circuit_breaker.py`)**: Detects cascading failures or high-risk activity across multiple agents and trips a breaker to halt execution.
*   **Kill Switch (`kill_switch.py`)**: Allows administrators to immediately disable specific tools globally without redeploying the application.

### 7. Governance Evidence
Located in the `templates/` directory, these markdown artifacts are essential for demonstrating compliance to auditors:
*   **System Cards (`ai_system_card.md`)**
*   **Deployment Readiness Checklists (`deployment_readiness_checklist.md`)**
*   **Data Classification Guidelines (`data_classification.md`)**
*   **Third-Party Component Inventory (`third_party_component_inventory.md`)**
*   **RAG Ingestion Checklists (`rag_ingestion_checklist.md`)**
*   **MCP Server Reviews (`mcp_server_review.md`)**

## Setup and Usage

Install the required dependencies (including LangChain support):
```bash
pip install -r requirements.txt
```

Run the tests to see the security controls in action:
```bash
python -m unittest discover -s agentsecgov/tests
```

To enable the live LangChain planner, export your OpenAI API key before running the application:
```bash
export OPENAI_API_KEY="your-api-key"
```
