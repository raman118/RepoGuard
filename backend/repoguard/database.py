from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str) -> Engine:
    sqlite = url.startswith("sqlite")
    engine = create_engine(
        url, pool_pre_ping=True, connect_args={"check_same_thread": False} if sqlite else {}
    )
    if sqlite:

        @event.listens_for(engine, "connect")
        def sqlite_constraints(connection: Any, _: Any) -> None:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")

    return engine


def sessions(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
