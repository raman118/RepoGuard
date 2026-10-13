from fastapi.testclient import TestClient

from repoguard.fixtures import files, fixture_sha
from repoguard.ingestion import Snapshot
from repoguard.scanner import scan
from repoguard.worker import run_once


def test_labeled_config_findings_clean_and_coverage() -> None:
    vulnerable = scan(
        Snapshot(fixture_sha("vulnerable"), files("vulnerable")), semgrep_enabled=False
    )
    assert {f["rule_id"] for f in vulnerable["findings"]} == {
        "RG-CI-PERMISSIONS",
        "RG-CI-TIMEOUT",
        "RG-CI-TEST",
        "RG-DOCKER-ROOT",
        "RG-DOCKER-TAG",
        "RG-DEPENDENCY-PIN",
    }
    for finding in vulnerable["findings"]:
        assert finding["line"] > 0 and finding["path"] in files("vulnerable")
        assert finding["evidence"] and finding["explanation"] and finding["remediation"]
    assert vulnerable["coverage"]["RG-PY-SHELL"]["reason"] == "engine_disabled"
    clean = scan(Snapshot(fixture_sha("clean"), files("clean")), semgrep_enabled=False)
    assert clean["findings"] == []
    assert scan(Snapshot("a" * 40, {}))["coverage"]["RG-CI-TIMEOUT"]["status"] == "unknown"


def test_yaml_injection_and_parse_failure_are_unknown() -> None:
    for text in [
        b"x: &a [*a]",
        b"!!python/object/apply:os.system ['echo attack']",
        b"jobs: [invalid]",
        b"\xff",
    ]:
        result = scan(Snapshot("a" * 40, {".github/workflows/ci.yml": text}))
        assert result["coverage"]["RG-CI-TIMEOUT"]["status"] == "unknown"
        assert result["errors"]


def test_fixture_scan_worker_persists_actual_findings(client: TestClient, repository: str) -> None:
    queued = client.post(
        f"/v1/repositories/{repository}/scans",
        json={
            "sha": fixture_sha("vulnerable"),
            "idempotency_key": "actual-scan",
        },
    ).json()
    assert queued["state"] == "queued"
    assert run_once(client.app.state.sessions, client.app.state.settings, client.app.state.github)
    response = client.get(f"/v1/scans/{queued['id']}").json()
    assert response["state"] == "succeeded"
    assert len(response["findings"]) >= 6
    assert response["result"]["sha"] == fixture_sha("vulnerable")
    python_scanned = response["result"]["coverage"]["RG-PY-SHELL"]["status"] == "scanned"
    assert response["result"]["score"]["value"] == (41 if python_scanned else 37)
    assert response["result"]["score"]["policy_version"] == "readiness/1"
    assert not run_once(
        client.app.state.sessions, client.app.state.settings, client.app.state.github
    )
