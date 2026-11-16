"""App factory. Run with: uvicorn app.main:create_app --factory"""

import logging

from fastapi import FastAPI
from sqlalchemy.orm import sessionmaker

from app import __version__, api, models, ui  # noqa: F401  (models registers tables)
from app.config import Settings, get_settings
from app.db import Base, make_engine


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=settings.log_level.upper())

    engine = make_engine(settings.database_url)
    # v0.1 keeps it simple: create tables on startup. Alembic comes with the
    # first schema change that needs a migration.
    Base.metadata.create_all(engine)

    app = FastAPI(title="Scanboard", version=__version__)
    app.state.settings = settings
    app.state.sessionmaker = sessionmaker(engine, expire_on_commit=False)

    app.include_router(api.health)
    app.include_router(api.router)
    app.include_router(ui.router)
    return app
