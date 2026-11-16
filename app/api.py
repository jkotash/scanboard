import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth import hash_key, new_api_key, require_admin, require_project_key
from app.config import Settings, settings_dep
from app.db import get_db
from app.models import ApiKey, Build, Component, Finding, Project
from app.parsers import ParseError, parse_cyclonedx, parse_trivy, severity_counts
from app.queries import findings_query

MAX_UPLOAD_BYTES = 50 * 1024 * 1024

router = APIRouter(prefix="/api/v1", tags=["api"])
health = APIRouter(tags=["health"])

DB = Annotated[Session, Depends(get_db)]
admin_only = [Depends(require_admin)]


# --- helpers -------------------------------------------------------------------


def _read_json(upload: UploadFile, field: str) -> Any:
    raw = upload.file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"{field} exceeds 50 MB")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(422, f"{field} is not valid JSON") from exc


def _get_project(db: Session, name: str) -> Project:
    project = db.scalar(select(Project).where(Project.name == name))
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


def _get_build(db: Session, build_id: int) -> Build:
    build = db.get(Build, build_id)
    if build is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "build not found")
    return build


def build_out(build: Build | None) -> dict[str, Any] | None:
    if build is None:
        return None
    return {
        "id": build.id,
        "commit_sha": build.commit_sha,
        "branch": build.branch,
        "image_ref": build.image_ref,
        "image_digest": build.image_digest,
        "pipeline_url": build.pipeline_url,
        "created_at": build.created_at.isoformat(),
        "counts": build.counts,
    }


# --- ingest (project API key) ---------------------------------------------------


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
def ingest(
    project: Annotated[Project, Depends(require_project_key)],
    db: DB,
    settings: Annotated[Settings, Depends(settings_dep)],
    vuln_report: Annotated[UploadFile, File(description="Trivy JSON report")],
    sbom: Annotated[UploadFile | None, File(description="CycloneDX JSON SBOM")] = None,
    commit_sha: Annotated[str, Form()] = "",
    branch: Annotated[str, Form()] = "",
    image_ref: Annotated[str, Form()] = "",
    image_digest: Annotated[str, Form()] = "",
    pipeline_url: Annotated[str, Form()] = "",
) -> dict[str, Any]:
    try:
        findings = parse_trivy(_read_json(vuln_report, "vuln_report"))
        components = parse_cyclonedx(_read_json(sbom, "sbom")) if sbom else []
    except ParseError as exc:
        raise HTTPException(422, str(exc)) from exc

    counts = severity_counts(findings)
    build = Build(
        project_id=project.id,
        commit_sha=commit_sha[:64],
        branch=branch[:255],
        image_ref=image_ref[:500],
        image_digest=image_digest[:100],
        pipeline_url=pipeline_url[:500],
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        unknown=counts["UNKNOWN"],
        findings=[Finding(**f) for f in findings],
        components=[Component(**c) for c in components],
    )
    db.add(build)
    db.commit()

    return {
        "build_id": build.id,
        "project": project.name,
        "counts": build.counts,
        "findings": len(findings),
        "components": len(components),
        "url": f"{settings.base_url.rstrip('/')}/projects/{project.name}",
    }


# --- read (admin token) -----------------------------------------------------------


@router.get("/projects", dependencies=admin_only)
def list_projects(db: DB) -> list[dict[str, Any]]:
    projects = db.scalars(select(Project).order_by(Project.name)).all()
    return [{"name": p.name, "latest_build": build_out(p.latest_build)} for p in projects]


@router.get("/projects/{name}", dependencies=admin_only)
def get_project(name: str, db: DB) -> dict[str, Any]:
    project = _get_project(db, name)
    return {
        "name": project.name,
        "created_at": project.created_at.isoformat(),
        "builds": [build_out(b) for b in project.builds],
    }


@router.get("/builds/{build_id}/findings", dependencies=admin_only)
def build_findings(
    build_id: int, db: DB, severity: str | None = None, fixable: bool = False
) -> list[dict[str, Any]]:
    _get_build(db, build_id)
    return [
        {
            "vuln_id": f.vuln_id,
            "package_name": f.package_name,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "severity": f.severity,
            "title": f.title,
            "target": f.target,
        }
        for f in db.scalars(findings_query(build_id, severity, fixable))
    ]


@router.get("/builds/{build_id}/components", dependencies=admin_only)
def build_components(build_id: int, db: DB) -> list[dict[str, Any]]:
    build = _get_build(db, build_id)
    return [
        {"name": c.name, "version": c.version, "purl": c.purl, "type": c.type}
        for c in sorted(build.components, key=lambda c: (c.name, c.version))
    ]


# --- admin -------------------------------------------------------------------------


class ProjectIn(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,99}$")


class KeyIn(BaseModel):
    label: str = Field(default="", max_length=100)


@router.post("/admin/projects", status_code=201, dependencies=admin_only)
def create_project(body: ProjectIn, db: DB) -> dict[str, str]:
    if db.scalar(select(Project).where(Project.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "project already exists")
    db.add(Project(name=body.name))
    db.commit()
    return {"name": body.name}


@router.post("/admin/projects/{name}/keys", status_code=201, dependencies=admin_only)
def create_key(name: str, db: DB, body: KeyIn | None = None) -> dict[str, str]:
    project = _get_project(db, name)
    key = new_api_key()
    label = body.label if body else ""
    db.add(ApiKey(project_id=project.id, key_hash=hash_key(key), label=label))
    db.commit()
    return {
        "project": name,
        "label": label,
        "api_key": key,
        "note": "Store this key now. Only its hash is kept, so it can't be shown again.",
    }


# --- health -------------------------------------------------------------------------


@health.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@health.get("/readyz")
def readyz(db: DB) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from exc
    return {"status": "ready"}
