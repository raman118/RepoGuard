"""Run trusted local gates without Git/GitHub; require external gates explicitly."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def reject_skipped(report: Path) -> None:
    """A required integration gate must execute tests, with no skipped acceptance."""
    cases = list(ET.parse(report).getroot().iter("testcase"))
    if not cases or any(case.find("skipped") is not None for case in cases):
        raise ValueError("required_gate_has_skipped_or_no_tests")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope",
        choices=["local", "backend", "frontend", "services", "sandbox", "semgrep"],
        default="local",
    )
    args = parser.parse_args()
    uv = shutil.which("uv")
    if uv is None:
        raise SystemExit("uv is required")
    environment = dict(os.environ)
    # Operator tests use allowlisted fixtures/mocked remotes, never live credentials.
    output = environment.get("REPOGUARD_VERIFY_OUTPUT", str(ROOT / ".runtime"))
    for name in list(environment):
        if name.startswith("REPOGUARD_") and not name.startswith("REPOGUARD_TEST_"):
            del environment[name]
    environment.update(
        REPOGUARD_ENVIRONMENT="test",
        REPOGUARD_FIXTURE_MODE="true",
        REPOGUARD_LLM_ENABLED="false",
        NEXT_TELEMETRY_DISABLED="1",
    )
    commands: list[tuple[list[str], Path]] = []
    report: Path | None = None
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    if args.scope in {"local", "backend"}:
        commands.extend(
            ([uv, "run", *command], ROOT)
            for command in [
                ["ruff", "check", "."],
                ["ruff", "format", "--check", "."],
                ["mypy", "backend"],
                ["pytest"],
            ]
        )
    if args.scope in {"local", "frontend"}:
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if npm is None:
            raise SystemExit("npm is required for frontend gates")
        commands.extend(
            ([npm, "run", script], ROOT / "frontend")
            for script in [
                "format:check",
                "lint",
                "typecheck",
                "test",
                "build",
                "test:e2e",
            ]
        )
    if args.scope in {"services", "sandbox", "semgrep"}:
        commands.append(([sys.executable, "scripts/require_gates.py", args.scope], ROOT))
        report = directory / f"{args.scope}.xml"
        selection = {
            "services": ["-m", "postgres or services"],
            "sandbox": ["-m", "sandbox"],
            "semgrep": ["tests/test_semgrep.py"],
        }[args.scope]
        commands.append(([uv, "run", "pytest", *selection, f"--junitxml={report}"], ROOT))
    evidence: dict = {
        "started_at": datetime.now(UTC).isoformat(),
        "scope": args.scope,
        "commands": [],
        "status": "running",
        "limitations": (
            "Local backend tests explicitly skip unavailable service/sandbox gates. "
            "Run services, sandbox and semgrep scopes separately; no live GitHub/CI/deploy proof."
        ),
    }
    code = 0
    try:
        for command, cwd in commands:
            print(f"[{cwd.name}] {' '.join(command)}", flush=True)
            started = time.monotonic()
            result = subprocess.run(command, cwd=cwd, env=environment, check=False)
            evidence["commands"].append(
                {
                    "argv": command,
                    "cwd": cwd.relative_to(ROOT).as_posix(),
                    "exit_code": result.returncode,
                    "seconds": round(time.monotonic() - started, 3),
                }
            )
            if result.returncode:
                code = result.returncode
                break
        if code == 0 and report is not None:
            reject_skipped(report)
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"Verification failed: {type(error).__name__}", file=sys.stderr)
        code = 1
    finally:
        evidence["status"] = "passed" if code == 0 else "failed"
        evidence["finished_at"] = datetime.now(UTC).isoformat()
        target = directory / f"verification-{args.scope}.json"
        target.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(f"Verification evidence: {target}", flush=True)
    raise SystemExit(code)


if __name__ == "__main__":
    main()
