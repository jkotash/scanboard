from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"
ADMIN_TOKEN = "test-admin-token"


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(
        admin_token=ADMIN_TOKEN,
        database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
    )
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def project_key(client, admin_headers) -> str:
    """Create project 'demo' and return a fresh ingest key for it."""
    client.post("/api/v1/admin/projects", json={"name": "demo"}, headers=admin_headers)
    r = client.post("/api/v1/admin/projects/demo/keys", json={"label": "ci"}, headers=admin_headers)
    return r.json()["api_key"]


def ingest(client, key: str, *, sbom: bool = True, report: bytes | None = None):
    files = {
        "vuln_report": (
            "trivy.json",
            report if report is not None else (FIXTURES / "trivy.json").read_bytes(),
            "application/json",
        )
    }
    if sbom:
        files["sbom"] = (
            "sbom.cdx.json",
            (FIXTURES / "sbom.cdx.json").read_bytes(),
            "application/json",
        )
    return client.post(
        "/api/v1/ingest",
        headers={"Authorization": f"Bearer {key}"},
        data={
            "commit_sha": "abc1234def",
            "branch": "main",
            "image_ref": "ghcr.io/example/demo:sha-abc1234",
            "image_digest": "sha256:deadbeef",
            "pipeline_url": "https://github.com/example/demo/actions/runs/1",
        },
        files=files,
    )
