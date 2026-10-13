import hashlib
import hmac
import json
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from repoguard.models import Installation, Job, WebhookDelivery


def test_invalid_push_rolls_back_delivery_and_pr_event_is_ignored(client: TestClient) -> None:
    client.app.state.settings.webhook_secret = SecretStr("s" * 32)
    with client.app.state.sessions() as db:
        db.add(Installation(id=42, tenant_id="alpha"))
        db.commit()
    payload = {
        "installation": {"id": 42},
        "repository": {"id": 7},
        "ref": "refs/heads/main",
        "after": "main",
    }
    body = json.dumps(payload).encode()
    delivery = str(uuid4())
    headers = {
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": "sha256=" + hmac.new(b"s" * 32, body, hashlib.sha256).hexdigest(),
    }
    assert client.post("/webhooks/github", content=body, headers=headers).status_code == 422
    with client.app.state.sessions() as db:
        assert db.get(WebhookDelivery, delivery) is None
        assert list(db.scalars(select(Job))) == []
    headers["X-GitHub-Event"] = "pull_request"
    assert (
        client.post("/webhooks/github", content=body, headers=headers).json()["status"] == "ignored"
    )
