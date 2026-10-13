import copy

import httpx
import pytest
from fastapi.testclient import TestClient

from repoguard.config import Settings
from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.remediation import HTTPProposalProvider, PolicyError, apply, propose
from repoguard.scanner import scan
from repoguard.worker import run_once


def test_exact_ci_patches_resolve_target_and_preserve_other_content() -> None:
    snapshot = Snapshot(fixture_sha("vulnerable"), files("vulnerable"))
    result = scan(snapshot, semgrep_enabled=False)
    for rule in ["RG-CI-TIMEOUT", "RG-CI-PERMISSIONS"]:
        finding = next(f for f in result["findings"] if f["rule_id"] == rule)
        patch = propose(snapshot, finding)
        assert patch == propose(snapshot, finding)
        updated = apply(snapshot, patch["artifact"], patch["digest"])
        assert rule not in {f["rule_id"] for f in scan(updated, semgrep_enabled=False)["findings"]}
        assert updated.files["app.py"] == snapshot.files["app.py"]
        assert (
            "echo no tests" not in patch["artifact"]["diff"]
        )  # zero context avoids unrelated source
        tampered = copy.deepcopy(patch["artifact"])
        tampered["replacement"] = "run: malicious-command\n"
        with pytest.raises(PolicyError, match="mismatch"):
            apply(snapshot, tampered, patch["digest"])
        with pytest.raises(PolicyError):
            apply(Snapshot("b" * 40, snapshot.files), patch["artifact"], patch["digest"])


def test_model_injection_tools_and_wrong_recipe_rejected() -> None:
    snapshot = Snapshot(fixture_sha("vulnerable"), files("vulnerable"))
    finding = next(
        f
        for f in scan(snapshot, semgrep_enabled=False)["findings"]
        if f["rule_id"] == "RG-CI-TIMEOUT"
    )
    for output in [
        {"rule_id": "RG-CI-TIMEOUT", "path": "../../host", "operation": "timeout_15"},
        {
            "rule_id": "RG-CI-TIMEOUT",
            "path": finding["path"],
            "operation": "timeout_15",
            "tools": ["shell"],
        },
        {"rule_id": "RG-CI-TIMEOUT", "path": finding["path"], "operation": "minimum_permissions"},
    ]:
        provider = HTTPProposalProvider(
            Settings(llm_enabled=True, llm_endpoint="https://provider.example/recipe"),
            httpx.Client(
                transport=httpx.MockTransport(lambda _, row=output: httpx.Response(200, json=row))
            ),
        )
        with pytest.raises((PolicyError, ValueError)):
            propose(snapshot, finding, provider)
    with pytest.raises(PolicyError, match="disabled"):
        HTTPProposalProvider(Settings()).choose({})


def test_api_proposal_provenance_idempotency_and_tenancy(
    client: TestClient, repository: str
) -> None:
    queued = client.post(
        f"/v1/repositories/{repository}/scans",
        json={"sha": fixture_sha("vulnerable"), "idempotency_key": "proposal"},
    ).json()
    run_once(client.app.state.sessions, client.app.state.settings, client.app.state.github)
    result = client.get(f"/v1/scans/{queued['id']}").json()
    target = next(f for f in result["findings"] if f["rule_id"] == "RG-CI-TIMEOUT")
    url = f"/v1/scans/{queued['id']}/proposals"
    response = client.post(url, json={"finding_id": target["id"]})
    assert response.status_code == 201
    proposal = response.json()
    assert proposal["validation"] == "pending" and proposal["approved_by"] is None
    assert proposal["artifact"]["base_sha"] == fixture_sha("vulnerable")
    assert "timeout-minutes: 15" in proposal["artifact"]["diff"]
    assert client.post(url, json={"finding_id": target["id"]}).json()["id"] == proposal["id"]
    unsupported = next(f for f in result["findings"] if f["rule_id"] == "RG-DOCKER-ROOT")
    assert client.post(url, json={"finding_id": unsupported["id"]}).status_code == 422
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.get(f"/v1/proposals/{proposal['id']}").status_code == 404
    assert client.post(url, json={"finding_id": target["id"]}).status_code == 404


def test_provider_receives_only_metadata_and_valid_recipe_is_accepted() -> None:
    snapshot = Snapshot(fixture_sha("vulnerable"), files("vulnerable"))
    target = next(
        f
        for f in scan(snapshot, semgrep_enabled=False)["findings"]
        if f["rule_id"] == "RG-CI-TIMEOUT"
    )
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content.decode())
        return httpx.Response(
            200,
            json={"rule_id": target["rule_id"], "path": target["path"], "operation": "timeout_15"},
        )

    provider = HTTPProposalProvider(
        Settings(llm_enabled=True, llm_endpoint="https://provider.example/recipe"),
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert propose(snapshot, target, provider) == propose(snapshot, target)
    assert "subprocess" not in captured[0] and "echo no tests" not in captured[0]


def test_existing_invalid_timeout_and_duplicate_yaml_are_not_rewritten() -> None:
    path = ".github/workflows/ci.yml"
    for content in [
        b"jobs:\n  checks:\n    timeout-minutes: 0\n    steps: []\n",
        b"jobs: {}\njobs: {}\n",
    ]:
        snapshot = Snapshot("a" * 40, {path: content})
        if b"timeout" in content:
            target = next(f for f in scan(snapshot)["findings"] if f["rule_id"] == "RG-CI-TIMEOUT")
            with pytest.raises(PolicyError, match="existing_timeout"):
                propose(snapshot, target)
        else:
            assert scan(snapshot)["coverage"]["RG-CI-TIMEOUT"]["status"] == "unknown"
