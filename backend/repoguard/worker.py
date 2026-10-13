"""Separate job process; API enqueue never blocks on scanning."""

import argparse
import asyncio
import base64
import json
import subprocess
import sys
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from repoguard.config import Settings
from repoguard.database import make_engine, sessions
from repoguard.github import GitHub, GitHubError
from repoguard.ingestion import IngestionError, ingest
from repoguard.jobs import claim, finish
from repoguard.models import Repository, Scan
from repoguard.notifications import Wakeups
from repoguard.observability import configure_logging
from repoguard.processes import ProcessLimitError, bounded_command


def run_once(factory: sessionmaker[Session], settings: Settings, github: GitHub) -> bool:
    lease = claim(factory, settings.job_timeout_seconds + 60)
    if lease is None:
        return False
    try:
        with factory() as db:
            scan = db.get(Scan, lease.scan_id)
            if scan is None:
                raise IngestionError("scan_missing")
            repository = db.get(Repository, scan.repository_id)
            if repository is None:
                raise IngestionError("repository_missing")
            snapshot = ingest(repository, scan.sha, settings, github)
        payload = {
            "sha": snapshot.sha,
            "files": {
                path: base64.b64encode(content).decode() for path, content in snapshot.files.items()
            },
        }
        code, output, _ = asyncio.run(
            bounded_command(
                [sys.executable, "-m", "repoguard.analysis_runtime"],
                json.dumps(payload).encode(),
                timeout=settings.job_timeout_seconds,
            )
        )
        if code != 0:
            raise IngestionError("analysis_failed")
        result: dict[str, Any] = json.loads(output)
        finish(factory, lease, result)
    except GitHubError as error:
        finish(factory, lease, error_code=error.code, retryable=error.retryable)
    except (
        IngestionError,
        ValueError,
        OSError,
        subprocess.SubprocessError,
        ProcessLimitError,
    ) as error:
        error_code = str(error) if isinstance(error, IngestionError) else "analysis_failed"
        finish(factory, lease, error_code=error_code)
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    configure_logging()
    factory = sessions(make_engine(settings.database_url))
    github = GitHub(settings)
    wakeups = Wakeups(settings.redis_url)
    try:
        while True:
            processed = run_once(factory, settings, github)
            if args.once:
                return
            if not processed:
                wakeups.wait()
    finally:
        wakeups.close()


if __name__ == "__main__":
    main()
