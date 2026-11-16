from collections.abc import Iterator
from pathlib import Path

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    connect_args = {}
    if url.get_backend_name() == "sqlite":
        # FastAPI runs sync endpoints in a thread pool.
        connect_args["check_same_thread"] = False
        if url.database and url.database != ":memory:":
            Path(url.database).parent.mkdir(parents=True, exist_ok=True)
    return create_engine(url, connect_args=connect_args)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request."""
    with request.app.state.sessionmaker() as session:
        yield session
