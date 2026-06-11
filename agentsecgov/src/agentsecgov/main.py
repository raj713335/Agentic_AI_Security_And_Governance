from fastapi import FastAPI

from .models import AgentRequest, AgentResponse
from .agent import DeterministicAgent

app = FastAPI(
    title="AgentSecGov API",
    description="API for AgentSecGov, a framework for secure and compliant AI agents.",
    version="0.1.0",
)

AGENT = DeterministicAgent()


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/agent/run", response_model=AgentResponse)
async def run_agent(request: AgentRequest) -> AgentResponse:
    # In a real implementation, you would have logic here to process the request
    # and generate a response based on the agent's capabilities and the input message.

    return AGENT.run(request)
