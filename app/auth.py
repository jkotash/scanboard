"""Auth: an admin token for management/read, per-project API keys for ingest.

API keys are long random strings, so a plain SHA-256 hash is enough to store
them safely (slow hashes like bcrypt matter for low-entropy human passwords).
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, settings_dep
from app.db import get_db
from app.models import ApiKey, Project

UI_COOKIE = "scanboard_session"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_api_key() -> str:
    return "sb_" + secrets.token_urlsafe(32)


def _bearer(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"}
    )


def token_matches(given: str, settings: Settings) -> bool:
    return hmac.compare_digest(given.encode(), settings.admin_token.encode())


def require_admin(request: Request, settings: Annotated[Settings, Depends(settings_dep)]) -> None:
    token = _bearer(request)
    if token is None or not token_matches(token, settings):
        raise _unauthorized("admin token required")


def require_project_key(request: Request, db: Annotated[Session, Depends(get_db)]) -> Project:
    token = _bearer(request)
    if token is None:
        raise _unauthorized("project API key required")
    api_key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(token)))
    if api_key is None:
        raise _unauthorized("invalid API key")
    api_key.last_used_at = datetime.now(UTC)
    return api_key.project


# --- UI session: a cookie holding an HMAC derived from the admin token ---------


def ui_session_value(settings: Settings) -> str:
    return hmac.new(settings.admin_token.encode(), b"scanboard-ui", hashlib.sha256).hexdigest()


def ui_logged_in(request: Request, settings: Settings) -> bool:
    cookie = request.cookies.get(UI_COOKIE)
    return cookie is not None and hmac.compare_digest(cookie, ui_session_value(settings))
