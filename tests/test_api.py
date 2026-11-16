from tests.conftest import ADMIN_TOKEN, ingest


def test_health_endpoints(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_read_endpoints_require_admin(client):
    assert client.get("/api/v1/projects").status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert client.get("/api/v1/projects", headers=bad).status_code == 401


def test_project_names_are_validated(client, admin_headers):
    r = client.post("/api/v1/admin/projects", json={"name": "Bad Name!"}, headers=admin_headers)
    assert r.status_code == 422


def test_duplicate_project_conflicts(client, admin_headers):
    client.post("/api/v1/admin/projects", json={"name": "demo"}, headers=admin_headers)
    r = client.post("/api/v1/admin/projects", json={"name": "demo"}, headers=admin_headers)
    assert r.status_code == 409


def test_ingest_requires_valid_project_key(client, project_key):
    assert ingest(client, "sb_not-a-real-key").status_code == 401
    # The admin token is not an ingest key.
    assert ingest(client, ADMIN_TOKEN).status_code == 401


def test_ingest_stores_build_findings_and_sbom(client, project_key, admin_headers):
    r = ingest(client, project_key)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["counts"] == {"critical": 2, "high": 2, "medium": 1, "low": 1, "unknown": 0}
    assert body["components"] == 3

    build_id = body["build_id"]
    projects = client.get("/api/v1/projects", headers=admin_headers).json()
    assert projects[0]["name"] == "demo"
    assert projects[0]["latest_build"]["id"] == build_id

    findings = client.get(f"/api/v1/builds/{build_id}/findings", headers=admin_headers).json()
    assert [f["severity"] for f in findings][:2] == ["CRITICAL", "HIGH"]  # worst first

    fixable = client.get(
        f"/api/v1/builds/{build_id}/findings?fixable=true", headers=admin_headers
    ).json()
    assert len(fixable) == 3
    assert all(f["fixed_version"] for f in fixable)

    comps = client.get(f"/api/v1/builds/{build_id}/components", headers=admin_headers).json()
    assert {c["name"] for c in comps} == {"openssl", "fastapi", "starlette"}


def test_ingest_without_sbom(client, project_key):
    r = ingest(client, project_key, sbom=False)
    assert r.status_code == 201
    assert r.json()["components"] == 0


def test_ingest_rejects_garbage(client, project_key):
    assert ingest(client, project_key, report=b"not json").status_code == 422
    assert ingest(client, project_key, report=b'{"foo": 1}').status_code == 422


def test_project_history_newest_first(client, project_key, admin_headers):
    first = ingest(client, project_key).json()["build_id"]
    second = ingest(client, project_key).json()["build_id"]
    builds = client.get("/api/v1/projects/demo", headers=admin_headers).json()["builds"]
    assert [b["id"] for b in builds] == [second, first]
