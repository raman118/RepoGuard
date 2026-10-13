"""Owned loopback-only E2E service with disposable DB and real scan worker."""

import os
import threading
from pathlib import Path

import uvicorn

from repoguard.api import create_app
from repoguard.auth import token_digest
from repoguard.config import Settings
from repoguard.models import Base, Credential, Tenant
from repoguard.worker import run_once


def main() -> None:
    directory = Path(".runtime").resolve()
    directory.mkdir(exist_ok=True)
    database = directory / f"e2e-{os.getpid()}.db"
    settings = Settings(environment="test", database_url=f"sqlite:///{database.as_posix()}")
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    with app.state.sessions() as db:
        db.add(Tenant(id="e2e", name="local browser fixture"))
        db.flush()
        db.add(
            Credential(digest=token_digest("e2e-local-only-token"), tenant_id="e2e", actor="e2e")
        )
        db.commit()
    stopped = threading.Event()

    def worker() -> None:
        while not stopped.is_set():
            run_once(app.state.sessions, settings, app.state.github)
            stopped.wait(0.2)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning", access_log=False)
    finally:
        stopped.set()
        thread.join(timeout=10)
        app.state.engine.dispose()


if __name__ == "__main__":
    main()
