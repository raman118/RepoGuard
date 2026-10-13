"""Run trusted fixed argv with bounded streams; never accept argv from an API/model."""

import asyncio
import os

import psutil


class ProcessLimitError(Exception):
    pass


async def bounded_command(
    argv: list[str],
    data: bytes | None = None,
    timeout: int = 40,
    maximum: int = 5_000_000,
    extra_environment: dict[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "LANG", "LC_ALL"}
    }
    if extra_environment:
        allowed = {
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "SEMGREP_SETTINGS_FILE",
            "SEMGREP_ENABLE_VERSION_CHECK",
            "SEMGREP_SEND_METRICS",
        }
        if set(extra_environment) - allowed:
            raise ValueError("process_environment_denied")
        environment.update(extra_environment)
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stdin, stdout, stderr = process.stdin, process.stdout, process.stderr
    size = 0

    async def send() -> None:
        try:
            if data:
                for offset in range(0, len(data), 65536):
                    stdin.write(data[offset : offset + 65536])
                    await stdin.drain()
            stdin.close()
        except (BrokenPipeError, ConnectionResetError):
            pass

    async def read(stream: asyncio.StreamReader) -> bytes:
        nonlocal size
        output = bytearray()
        while chunk := await stream.read(4096):
            size += len(chunk)
            if size > maximum:
                raise ProcessLimitError("process_output_limit")
            output.extend(chunk)
        return bytes(output)

    send_task = asyncio.create_task(send())
    out_task = asyncio.create_task(read(stdout))
    err_task = asyncio.create_task(read(stderr))
    tasks = [send_task, out_task, err_task]
    try:
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks)
            return await process.wait(), out_task.result(), err_task.result()
    except TimeoutError:
        raise ProcessLimitError("process_timeout") from None
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if process.returncode is None:
            try:
                descendants = psutil.Process(process.pid).children(recursive=True)
            except psutil.NoSuchProcess:
                descendants = []
            for child in descendants:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            process.kill()
            await process.wait()
