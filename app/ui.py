from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import UI_COOKIE, token_matches, ui_logged_in, ui_session_value
from app.config import Settings, settings_dep
from app.db import get_db
from app.models import Project
from app.parsers import SEVERITIES
from app.queries import findings_query

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
router = APIRouter(include_in_schema=False)

DB = Annotated[Session, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(settings_dep)]


def _to_login() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)


@router.get("/login")
def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login(request: Request, settings: SettingsDep, token: Annotated[str, Form()]) -> Response:
    if not token_matches(token, settings):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid token"}, status_code=401
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        UI_COOKIE,
        ui_session_value(settings),
        httponly=True,
        samesite="lax",
        secure=settings.base_url.startswith("https"),
        max_age=12 * 60 * 60,
    )
    return response


@router.post("/logout")
def logout() -> Response:
    response = _to_login()
    response.delete_cookie(UI_COOKIE)
    return response


@router.get("/")
def index(request: Request, db: DB, settings: SettingsDep) -> Response:
    if not ui_logged_in(request, settings):
        return _to_login()
    projects = db.scalars(select(Project).order_by(Project.name)).all()
    return templates.TemplateResponse(
        request, "index.html", {"projects": projects, "logged_in": True}
    )


@router.get("/projects/{name}")
def project_page(
    request: Request,
    name: str,
    db: DB,
    settings: SettingsDep,
    severity: str = "",
    fixable: bool = False,
) -> Response:
    if not ui_logged_in(request, settings):
        return _to_login()
    project = db.scalar(select(Project).where(Project.name == name))
    if project is None:
        raise HTTPException(404, "project not found")

    latest = project.latest_build
    findings = (
        db.scalars(findings_query(latest.id, severity or None, fixable)).all() if latest else []
    )
    return templates.TemplateResponse(
        request,
        "project.html",
        {
            "project": project,
            "latest": latest,
            "findings": findings,
            "builds": project.builds[:30],
            "severities": SEVERITIES,
            "severity": severity.upper(),
            "fixable": fixable,
            "logged_in": True,
        },
    )
