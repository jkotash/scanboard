from tests.conftest import ADMIN_TOKEN, ingest


def test_dashboard_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_wrong_token_is_rejected(client):
    r = client.post("/login", data={"token": "wrong"}, follow_redirects=False)
    assert r.status_code == 401


def test_login_then_see_project(client, project_key):
    ingest(client, project_key)
    r = client.post("/login", data={"token": ADMIN_TOKEN}, follow_redirects=False)
    assert r.status_code == 303

    page = client.get("/")
    assert page.status_code == 200
    assert "demo" in page.text

    detail = client.get("/projects/demo?severity=critical")
    assert "CVE-2024-0001" in detail.text
    assert "CVE-2024-0004" not in detail.text  # filtered out (medium)
