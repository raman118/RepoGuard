"""Release gates must catch missing execution and insecure packaging regressions."""

import json
import re
import subprocess
import sys
from pathlib import Path
from runpy import run_path

import pytest
import yaml

reject_skipped = run_path("scripts/verify.py")["reject_skipped"]


@pytest.mark.parametrize(
    "body",
    [
        '<testsuite tests="0"/>',
        '<testsuite><testcase name="required"><skipped/></testcase></testsuite>',
    ],
)
def test_required_gate_rejects_no_execution(tmp_path: Path, body: str) -> None:
    report = tmp_path / "gate.xml"
    report.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError, match="skipped_or_no_tests"):
        reject_skipped(report)


def test_required_gate_accepts_executed_tests(tmp_path: Path) -> None:
    report = tmp_path / "gate.xml"
    report.write_text('<testsuites><testsuite><testcase name="real"/></testsuite></testsuites>')
    reject_skipped(report)


def test_container_contracts_keep_database_and_validator_boundaries() -> None:
    pins = json.loads(Path("artifacts/hosting-pins.json").read_text())["images"]
    for filename in ["compose.yml", "compose.verify.yml"]:
        compose = yaml.safe_load(Path(filename).read_text())
        for name, service in compose["services"].items():
            if "image" in service:
                assert service["image"] == pins[name]
                assert re.search(r"@sha256:[0-9a-f]{64}$", service["image"])
            assert service["read_only"] is True
            assert service["cap_drop"] == ["ALL"]
            assert service["pids_limit"] > 0 and service["cpus"] > 0
            assert "no-new-privileges:true" in service["security_opt"]
            assert not service.get("privileged")
            assert not any("docker.sock" in value for value in service.get("volumes", []))
            if filename == "compose.verify.yml":
                assert not service.get("ports") and not service.get("volumes")
            else:
                assert all(port.startswith("127.0.0.1:") for port in service.get("ports", []))
    verify = yaml.safe_load(Path("compose.verify.yml").read_text())
    assert verify["networks"]["test-data"]["internal"] is True
    assert all(service["networks"] == ["test-data"] for service in verify["services"].values())
    assert verify["services"]["checks"]["build"]["target"] == "verification"
    compose = yaml.safe_load(Path("compose.yml").read_text())
    assert compose["services"]["api"]["depends_on"]["migrate"] == {
        "condition": "service_completed_successfully"
    }
    assert compose["networks"]["data"]["internal"] is True
    for filename in ["Dockerfile", "frontend/Dockerfile", "sandbox/Dockerfile"]:
        content = Path(filename).read_text()
        images = re.findall(r"^FROM (\S+)", content, flags=re.MULTILINE)
        assert all(image in pins.values() or image == "base" for image in images)
        assert "USER " in content


@pytest.mark.parametrize("status", ["DONE", "IN_PROGRESS"])
def test_checkpoint_cannot_hide_unmet_acceptance_or_two_active_goals(
    tmp_path: Path, status: str
) -> None:
    goals = (
        "## G00 — foundation\nStatus: IN_PROGRESS\n- [x] existing task\n"
        "## G01 — next\nStatus: TODO\n- [ ] unmet task\n"
    )
    target = tmp_path / "GOALS.md"
    target.write_text(goals, encoding="utf-8")
    script = Path("scripts/checkpoint.py").resolve()
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "G01",
            status,
            "--evidence",
            "local test",
            "--next",
            "inspect pending acceptance",
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert target.read_text(encoding="utf-8") == goals
    assert not (tmp_path / "STATE.md").exists()
