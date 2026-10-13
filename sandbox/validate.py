"""This trusted entrypoint must ONLY run inside the restricted validator image."""

import ast
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml


def main() -> None:
    if os.getuid() != 10001 or not Path("/runner/pytest.ini").is_file():
        raise RuntimeError("container-only entrypoint")
    raw = sys.stdin.buffer.read(60_000_001)
    if len(raw) > 60_000_000:
        raise ValueError("input limit")
    payload = json.loads(raw)
    root = Path("/work/repo")
    root.mkdir()
    syntax_files = 0
    for path, encoded in payload["files"].items():
        target = root / path
        if root not in target.resolve().parents:
            raise ValueError("invalid path")
        content = base64.b64decode(encoded, validate=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        if path.endswith(".py"):
            ast.parse(content, filename=path)
            syntax_files += 1
        elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            yaml.safe_load(content)
            syntax_files += 1
    tests = "not_present"
    if (root / "tests").is_dir():
        response = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "pytest",
                "-q",
                "-c",
                "/runner/pytest.ini",
                "-p",
                "no:cacheprovider",
                "--basetemp=/work/pytest-temp",
                str(root / "tests"),
            ],
            cwd=root,
            capture_output=True,
            timeout=25,
            check=False,
        )
        if response.returncode != 0:
            raise ValueError("repository tests failed")
        tests = "passed"
    print(
        json.dumps(
            {
                "status": "passed",
                "profile": "isolated-static-and-tests/1",
                "syntax_files": syntax_files,
                "tests": tests,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never return raw untrusted test output/source/tracebacks to the API.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "profile": "isolated-static-and-tests/1",
                    "code": "isolated_checks_failed",
                }
            )
        )
        sys.exit(1)
