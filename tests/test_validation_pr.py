import asyncio
import json
import shutil
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from repoguard.config import Settings
from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.models import Repository
from repoguard.pull_requests import create_pull_request, git_blob_sha
from repoguard.remediation import PolicyError, apply, propose
from repoguard.sandbox import container_argv, run_container
from repoguard.scanner import canonical, scan
from repoguard.validation import ValidatorClient, signature
from repoguard.worker import run_once


def patch() -> tuple[Snapshot, dict]:
    snapshot = Snapshot(fixture_sha("vulnerable"), files("vulnerable"))
    target = next(
        f
        for f in scan(snapshot, semgrep_enabled=False)["findings"]
        if f["rule_id"] == "RG-CI-TIMEOUT"
    )
    proposal = propose(snapshot, target)
    return apply(snapshot, proposal["artifact"], proposal["digest"]), proposal


def signed_client(settings: Settings, tamper: bool = False) -> ValidatorClient:
    def handler(request: httpx.Request) -> httpx.Response:
        assert signature("s" * 32, request.content) == request.headers["X-RepoGuard-Signature"]
        payload = json.loads(request.content)
        result = {
            "status": "passed",
            "profile": "isolated-static-and-tests/1",
            "digest": payload["digest"],
            "sha": payload["sha"],
            "nonce": payload["nonce"],
            "tests": "not_present",
        }
        data = canonical(result)
        return httpx.Response(
            200,
            content=data,
            headers={"X-RepoGuard-Signature": "wrong" if tamper else signature("s" * 32, data)},
        )

    return ValidatorClient(settings, httpx.Client(transport=httpx.MockTransport(handler)))


def test_signed_attestation_and_missing_isolation_fail_closed() -> None:
    snapshot, proposal = patch()
    with pytest.raises(PolicyError, match="unavailable"):
        ValidatorClient(Settings()).validate(snapshot, proposal["digest"])
    settings = Settings(
        validator_url="https://validator.example", validator_secret=SecretStr("s" * 32)
    )
    assert signed_client(settings).validate(snapshot, proposal["digest"])["status"] == "passed"
    with pytest.raises(PolicyError, match="signature"):
        signed_client(settings, tamper=True).validate(snapshot, proposal["digest"])


def test_container_command_has_no_host_mount_or_user_command() -> None:
    args = container_argv("rg-validation-" + str(uuid4()), "validator@sha256:" + "a" * 64)
    assert args[args.index("--network") + 1] == "none"
    assert "--read-only" in args and "--cap-drop" in args and "--pids-limit" in args
    assert args[args.index("--user") + 1] == "10001:10001"
    assert not {"-v", "--volume", "--mount", "--privileged", "--pid=host"} & set(args)
    assert args[-3:] == ["python", "-I", "/runner/validate.py"]
    local_id = "sha256:" + "b" * 64
    assert container_argv("rg-validation-" + str(uuid4()), local_id)[-4] == local_id
    with pytest.raises(PolicyError):
        container_argv("malicious;command", "python:latest")


def test_approval_requires_validated_exact_digest_and_tenant(
    client: TestClient, repository: str
) -> None:
    queued = client.post(
        f"/v1/repositories/{repository}/scans",
        json={"sha": fixture_sha("vulnerable"), "idempotency_key": "approval"},
    ).json()
    run_once(client.app.state.sessions, client.app.state.settings, client.app.state.github)
    target = next(
        f
        for f in client.get(f"/v1/scans/{queued['id']}").json()["findings"]
        if f["rule_id"] == "RG-CI-TIMEOUT"
    )
    proposal = client.post(
        f"/v1/scans/{queued['id']}/proposals", json={"finding_id": target["id"]}
    ).json()
    url = f"/v1/proposals/{proposal['id']}"
    body = {"digest": proposal["digest"]}
    assert client.post(url + "/approve", json=body).status_code == 409
    assert client.post(url + "/pull-request", json=body).status_code == 409
    assert client.post(url + "/validate", json={}).status_code == 503
    assert client.get(url).json()["validation"] == "unavailable"
    # Mock attestation verifies local policy only; never claims actual Docker success.
    settings = Settings(
        validator_url="https://validator.example", validator_secret=SecretStr("s" * 32)
    )
    client.app.state.validator = signed_client(settings)
    assert client.post(url + "/validate", json={}).json()["validation"] == "passed"
    assert client.post(url + "/approve", json={"digest": "b" * 64}).status_code == 409
    assert client.post(url + "/approve", json=body).json()["approved_by"] == "alpha"
    assert client.post(url + "/validate", json={}).status_code == 409
    assert client.post(url + "/pull-request", json=body).status_code == 409  # fixture has no remote
    client.headers["Authorization"] = "Bearer beta-token"
    assert client.post(url + "/approve", json=body).status_code == 404


class MockGitHub:
    def __init__(self) -> None:
        self.calls = []
        self.branch = False
        self.pr = False
        self.base = fixture_sha("vulnerable")

    def token(self, installation: int, repository_id: int, write: bool = False) -> str:
        return "mock-write" if write else "mock-read"

    def request(self, method: str, path: str, token: str, body: dict | None = None) -> dict | list:
        from repoguard.github import GitHubError

        self.calls.append((method, path, body))
        if path.endswith("/repo"):
            return {"default_branch": "main"}
        if "/commits/main" in path:
            return {"sha": self.base, "commit": {"tree": {"sha": "tree-base"}}}
        if path.endswith("/git/blobs"):
            import base64

            return {"sha": git_blob_sha(base64.b64decode(body["content"]))}
        if path.endswith("/git/trees"):
            return {"sha": "tree-fixed"}
        if path.endswith("/git/commits"):
            return {"sha": "fixed-commit"}
        if "/git/ref/heads/" in path:
            if not self.branch:
                raise GitHubError("github_http_404")
            return {"object": {"sha": "fixed-commit"}}
        if path.endswith("/git/refs"):
            self.branch = True
            return {}
        if "/pulls?" in path:
            return [self.pr_record()] if self.pr else []
        if path.endswith("/pulls"):
            self.pr = True
            return self.pr_record()
        raise AssertionError((method, path))

    def pr_record(self) -> dict:
        branch = next(
            body["ref"].removeprefix("refs/heads/")
            for method, path, body in self.calls
            if path.endswith("/git/refs")
        )
        return {
            "html_url": "https://github.com/owner/repo/pull/1",
            "number": 1,
            "base": {"sha": self.base},
            "head": {"sha": "fixed-commit", "ref": branch},
        }


def test_dedicated_branch_pr_retry_and_stale_base() -> None:
    snapshot, proposal = patch()
    github = MockGitHub()
    repository = Repository(owner="owner", name="repo", installation_id=42, provider_id=7)
    args = (
        github,
        repository,
        snapshot,
        proposal["artifact"],
        proposal["digest"],
        "human",
        "2026-10-12T00:00:00+00:00",
    )
    assert create_pull_request(*args) == "https://github.com/owner/repo/pull/1"
    assert create_pull_request(*args) == "https://github.com/owner/repo/pull/1"
    assert (
        sum(method == "POST" and path.endswith("/pulls") for method, path, _ in github.calls) == 1
    )
    assert (
        sum(method == "POST" and path.endswith("/git/refs") for method, path, _ in github.calls)
        == 1
    )
    assert all("/merge" not in path and "/deploy" not in path for _, path, _ in github.calls)
    github.base = "b" * 40
    before = len(github.calls)
    with pytest.raises(PolicyError, match="base_branch_changed"):
        create_pull_request(*args)
    assert not any(method == "POST" for method, _, _ in github.calls[before:])


@pytest.mark.sandbox
def test_real_container_checks() -> None:
    import os

    image = os.getenv("REPOGUARD_TEST_VALIDATOR_IMAGE")
    if not shutil.which("docker") or not image:
        pytest.skip("BLOCKED: Docker and digest-pinned validator image unavailable")
    snapshot, _ = patch()
    result = asyncio.run(run_container(snapshot, image))
    assert result["status"] == "passed"
