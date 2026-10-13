import asyncio
import sys
from pathlib import Path

import psutil
import pytest

from repoguard.processes import ProcessLimitError, bounded_command


def test_analysis_output_and_deadline_limits() -> None:
    with pytest.raises(ProcessLimitError, match="output_limit"):
        asyncio.run(bounded_command([sys.executable, "-c", "print('x' * 10000)"], maximum=1024))
    with pytest.raises(ProcessLimitError, match="timeout"):
        asyncio.run(
            bounded_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)
        )


def test_credentials_are_not_inherited_by_analysis_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOGUARD_GITHUB_PRIVATE_KEY", "fake-secret-for-env-leak-test")
    code, out, _ = asyncio.run(
        bounded_command(
            [
                sys.executable,
                "-c",
                "import os; print(os.getenv('REPOGUARD_GITHUB_PRIVATE_KEY', 'absent'))",
            ]
        )
    )
    assert code == 0 and out.strip() == b"absent"


def test_analysis_timeout_cleans_descendant_processes(tmp_path: Path) -> None:
    marker = tmp_path / "child.pid"
    program = (
        "import subprocess, sys, time; from pathlib import Path; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        f"Path({str(marker)!r}).write_text(str(child.pid)); time.sleep(30)"
    )
    with pytest.raises(ProcessLimitError, match="timeout"):
        asyncio.run(bounded_command([sys.executable, "-c", program], timeout=1))
    child_pid = int(marker.read_text())
    assert (
        not psutil.pid_exists(child_pid)
        or psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE
    )
