from fastapi.testclient import TestClient

from ..src.agentsecgov.main import app
from ..src.agentsecgov.goal import goal_integrity_check

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# def test_run_agent():
#     payload = {
#         "message": "Hello, AgentSecGov!",
#         "tenant_id": "tenant-a"
#     }
#     response = client.post("/agent/run", json=payload)
#     assert response.status_code == 200
#     data = response.json()
#     assert data["status"] == "success"
#     assert "Agent received your message" in data["message"]
#
#
# def test_run_agent_with_ticket():
#     payload = {
#         "message": "I have a login issue.",
#         "tenant_id": "tenant-a"
#     }
#     response = client.post("/agent/run", json=payload)
#     assert response.status_code == 200
#     data = response.json()
#     assert data["status"] == "planned"
#     assert "Agent plans to create a support ticket" in data["message"]


def test_agent_requires_api_key() -> None:
    response = client.post(
        "/agent/run",
        json={"message": "Create a ticket"},
    )

    assert response.status_code == 401


def test_valid_api_key_allows_request() -> None:
    response = client.post(
        "/agent/run",
        json={"message": "Create a ticket"},
        headers={"X-API-Key": "learner-key"},
    )

    assert response.status_code == 200


def test_goal_integrity_blocks_login_to_delete() -> None:
    allowed, reason = goal_integrity_check(
        "Help me with a login issue",
        "delete_record",
    )

    assert allowed is False
    assert "does not match" in reason


