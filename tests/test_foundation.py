from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from repoguard.api import create_app
from repoguard.config import Settings


def test_health_does_not_require_services() -> None:
    with TestClient(create_app(Settings(environment="test"))) as client:
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["mode"] == "test"


def test_production_fails_closed_without_configuration() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_harness_exists_and_has_every_goal() -> None:
    for name in [
        "AGENTS.md",
        "GOALS.md",
        "STATE.md",
        "WORKLOG.md",
        "ARCHITECTURE.md",
        "DECISIONS.md",
        "docs/DEMO.md",
        "docs/EVALUATION.md",
    ]:
        assert Path(name).is_file()
    goals = Path("GOALS.md").read_text()
    assert all(f"## G{number:02d}" in goals for number in range(14))
