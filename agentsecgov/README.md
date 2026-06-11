# Agentic Security and Governance - Udemy Course Pack

This course pack contains a practical instructor-ready course for "Agentic Security and Governance" using open-source tools and patterns including FastAPI, LangChain/LangGraph-style agent workflows, Open Policy Agent/Rego, Presidio-style PII controls, OpenTelemetry, and Promptfoo-style red-team/evaluation workflows.

## What is included

- `course/COURSE_TIMELINE.md` - 6-week course timeline, modules, lectures, outcomes, assignments.
- `course/LECTURE_SCRIPTS.md` - lecture-by-lecture instructor script with exact words and timeboxes.
- `course/EXERCISES_AND_ASSESSMENTS.md` - coding exercises, quizzes, labs, rubrics, capstone.
- `course/RESOURCES.md` - primary resources and tool references.
- `labs/agentsecgov/` - runnable FastAPI reference app with governed agent workflow, policy checks, PII redaction, approval queue, audit log, tests, OPA Rego policy, and promptfoo starter config.
- `templates/` - governance templates for risk register, AI system card, approval matrix, incident runbook, and policy mapping.

## Recommended use

Use the course as an 8 to 10 hour Udemy course with exercises after each section. The code labs are designed to run locally without a paid LLM key, while still teaching the production control patterns that apply to LangChain/LangGraph agent apps.

## Local lab quick start

```bash
cd labs/agentsecgov
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
uvicorn agentsecgov.main:app --reload
```

Try the API:

```bash
curl -s -X POST http://127.0.0.1:8000/agent/run \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: learner-key' \
  -d '{"message":"Create a support ticket for user alice@example.com about login failure"}'
```

For an action requiring approval:

```bash
curl -s -X POST http://127.0.0.1:8000/agent/run \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: admin-key' \
  -d '{"message":"Delete record CUST-1001 because it is duplicated"}'
```

Then inspect pending reviews:

```bash
curl -s http://127.0.0.1:8000/reviews/pending -H 'X-API-Key: reviewer-key'
```
