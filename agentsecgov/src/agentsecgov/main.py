from fastapi import FastAPI, Depends

from .models import AgentRequest, AgentResponse, Principal
from .agent import DeterministicAgent, GovernedAgent
from .auth import get_current_principal

app = FastAPI(
    title="AgentSecGov API",
    description="API for AgentSecGov, a framework for secure and compliant AI agents.",
    version="0.1.0",
)

AGENT = GovernedAgent()


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/agent/run", response_model=AgentResponse)
async def run_agent(request: AgentRequest, principal: Principal = Depends(get_current_principal)) -> AgentResponse:
    # In a real implementation, you would have logic here to process the request
    # and generate a response based on the agent's capabilities and the input message.

    return AGENT.run(request, principal)
