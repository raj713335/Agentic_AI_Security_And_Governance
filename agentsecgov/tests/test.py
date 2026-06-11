from fastapi.testclient import TestClient

from ..src.agentsecgov.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_run_agent():
    payload = {
        "message": "Hello, AgentSecGov!",
        "tenant_id": "tenant-a"
    }
    response = client.post("/agent/run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "Agent received your message" in data["message"]


def test_run_agent_with_ticket():
    payload = {
        "message": "I have a login issue.",
        "tenant_id": "tenant-a"
    }
    response = client.post("/agent/run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "planned"
    assert "Agent plans to create a support ticket" in data["message"]
