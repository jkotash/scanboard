# Scanboard

**A lightweight, pipeline-native dashboard for container vulnerability scans and SBOMs.**
One container, running in five minutes, and one step to add to any pipeline.

Every pipeline runs the same scan step (Trivy for vulnerabilities, a CycloneDX SBOM)
and posts the results to Scanboard. You get one view of the security posture of
everything you build.

```
any pipeline: build image → trivy (JSON) + SBOM (CycloneDX) → POST /api/v1/ingest
                                                                │
                                              Scanboard (FastAPI + SQLite) → dashboard
```

> Status: v0.1, early. Heavier alternatives: OWASP Dependency-Track, DefectDojo.

## Quickstart

1. Run it:
   ```bash
   docker run -d -p 8000:8000 -v scanboard:/data -e ADMIN_TOKEN=$(openssl rand -hex 32) ghcr.io/johnkotash/scanboard:latest
   ```
   Or, from a clone: `ADMIN_TOKEN=... docker compose up -d`
2. Create a project and an ingest key:
   ```bash
   curl -X POST localhost:8000/api/v1/admin/projects -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"name":"myapp"}'
   curl -X POST localhost:8000/api/v1/admin/projects/myapp/keys -H "Authorization: Bearer $ADMIN_TOKEN"
   ```
3. Send a scan from your pipeline:
   ```bash
   trivy image --format json -o trivy.json myapp:latest
   trivy image --format cyclonedx -o sbom.cdx.json myapp:latest
   curl -fsS -X POST "$SCANBOARD_URL/api/v1/ingest" \
     -H "Authorization: Bearer $SCANBOARD_API_KEY" \
     -F commit_sha="$GITHUB_SHA" -F branch="$GITHUB_REF_NAME" \
     -F image_ref="myapp:latest" \
     -F vuln_report=@trivy.json -F sbom=@sbom.cdx.json
   ```

Then open http://localhost:8000 and log in with the admin token.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMIN_TOKEN` | *(required)* | Admin API access and UI login |
| `DATABASE_URL` | `sqlite:////data/scanboard.db` | Any SQLAlchemy URL |
| `BASE_URL` | `http://localhost:8000` | Used in links; `https://` also marks the UI cookie Secure |
| `LOG_LEVEL` | `INFO` | Logging |

## API

| Method | Path | Auth |
| --- | --- | --- |
| POST | `/api/v1/ingest` (multipart: `vuln_report`, optional `sbom`, metadata fields) | project API key |
| GET | `/api/v1/projects`, `/api/v1/projects/{name}` | admin token |
| GET | `/api/v1/builds/{id}/findings?severity=&fixable=true` | admin token |
| GET | `/api/v1/builds/{id}/components` | admin token |
| POST | `/api/v1/admin/projects`, `/api/v1/admin/projects/{name}/keys` | admin token |
| GET | `/healthz`, `/readyz` | none |

Interactive docs at `/docs`.

## Security notes

Scan data is a map of your weaknesses, so nothing is readable without auth.
Ingest keys are per project and stored only as hashes. For anything exposed to the
internet, also put the UI behind an identity-aware proxy (e.g. Cloudflare Access).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
ADMIN_TOKEN=dev DATABASE_URL=sqlite:///./dev.db uvicorn app.main:create_app --factory --reload
```

## License

Apache-2.0
