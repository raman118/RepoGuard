"""Dedicated trusted controller: no host mounts, user commands or repository execution."""

import asyncio
import base64
import json
import re
import shutil
from typing import Any
from uuid import uuid4

from repoguard.ingestion import Snapshot
from repoguard.remediation import PolicyError
from repoguard.scanner import canonical


def container_argv(name: str, image: str) -> list[str]:
    if (
        re.fullmatch(r"rg-validation-[0-9a-f-]{36}", name) is None
        or re.fullmatch(r"(?:[A-Za-z0-9./:_-]+@)?sha256:[0-9a-f]{64}", image) is None
    ):
        raise PolicyError("sandbox_identity_invalid")
    return [
        "docker",
        "create",
        "--pull=never",
        "--name",
        name,
        "-i",
        "--network",
        "none",
        "--read-only",
        "--user",
        "10001:10001",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "1",
        "--pids-limit",
        "64",
        "--ulimit",
        "nofile=128:128",
        "--ulimit",
        "fsize=8388608:8388608",
        "--log-driver",
        "none",
        "--tmpfs",
        "/work:rw,noexec,nosuid,size=67108864,uid=10001,gid=10001",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16777216,uid=10001,gid=10001",
        "--env",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        image,
        "python",
        "-I",
        "/runner/validate.py",
    ]


async def command(
    argv: list[str], data: bytes | None = None, timeout: int = 40
) -> tuple[int, bytes]:
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert process.stdout is not None and process.stdin is not None
    stdin = process.stdin
    stdout = process.stdout

    async def send() -> None:
        try:
            if data:
                stdin.write(data)
                await stdin.drain()
            stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

    async def receive() -> bytes:
        output = bytearray()
        while True:
            chunk = await stdout.read(4096)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 32_768:
                raise PolicyError("sandbox_output_limit")
        return bytes(output)

    try:
        async with asyncio.timeout(timeout):
            _, output = await asyncio.gather(send(), receive())
            code = await process.wait()
            return code, output
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def run_container(snapshot: Snapshot, image: str) -> dict[str, Any]:
    if not shutil.which("docker"):
        raise PolicyError("isolation_unavailable")
    name = "rg-validation-" + str(uuid4())
    argv = container_argv(name, image)
    created = False
    attempted = False
    try:
        code, info = await command(["docker", "info", "--format", "{{json .}}"], timeout=5)
        runtime = json.loads(info) if code == 0 else {}
        if runtime.get("OSType") != "linux" or not all(
            runtime.get(key) is True
            for key in ["MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"]
        ):
            raise PolicyError("linux_isolation_required")
        attempted = True
        code, _ = await command(argv, timeout=10)
        if code:
            raise PolicyError("sandbox_create_failed")
        created = True
        code, raw = await command(["docker", "inspect", name], timeout=5)
        if code:
            raise PolicyError("sandbox_inspection_failed")
        config = json.loads(raw)[0]
        host = config["HostConfig"]
        if (
            host.get("NetworkMode") != "none"
            or not host.get("ReadonlyRootfs")
            or host.get("Privileged")
            or host.get("Binds")
            or config.get("Mounts")
            or host.get("Memory") != 268435456
            or host.get("MemorySwap") != 268435456
            or host.get("NanoCpus") != 1_000_000_000
            or host.get("PidsLimit") != 64
            or config["Config"].get("User") != "10001:10001"
            or "ALL" not in host.get("CapDrop", [])
            or "no-new-privileges=true" not in host.get("SecurityOpt", [])
        ):
            raise PolicyError("sandbox_policy_not_enforced")
        payload = canonical(
            {
                "sha": snapshot.sha,
                "files": {
                    path: base64.b64encode(content).decode()
                    for path, content in snapshot.files.items()
                },
            }
        )
        code, raw = await command(
            ["docker", "start", "--attach", "--interactive", name], payload, timeout=40
        )
        if code:
            return {"status": "failed", "code": "isolated_checks_failed"}
        result: dict[str, Any] = json.loads(raw)
        if (
            result.get("status") not in {"passed", "failed"}
            or result.get("profile") != "isolated-static-and-tests/1"
        ):
            raise PolicyError("sandbox_result_invalid")
        return result
    except (OSError, ValueError, KeyError, TimeoutError):
        raise PolicyError("isolation_unavailable") from None
    finally:
        if attempted:
            code, _ = await command(["docker", "rm", "--force", name], timeout=10)
            if code and created:
                raise PolicyError("sandbox_cleanup_failed")
