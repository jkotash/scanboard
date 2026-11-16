import json

import pytest

from app.parsers import ParseError, parse_cyclonedx, parse_trivy, severity_counts
from tests.conftest import FIXTURES


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


def test_parse_trivy_reads_every_result():
    findings = parse_trivy(load("trivy.json"))
    assert len(findings) == 5
    assert {f["target"] for f in findings} >= {"Python"}


def test_parse_trivy_normalizes_severity_and_missing_fix():
    findings = {f["vuln_id"]: f for f in parse_trivy(load("trivy.json"))}
    assert findings["GHSA-xxxx-yyyy-zzzz"]["severity"] == "LOW"  # was lowercase
    assert findings["CVE-2024-0003"]["fixed_version"] is None


def test_severity_counts():
    counts = severity_counts(parse_trivy(load("trivy.json")))
    assert counts == {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}


def test_parse_trivy_clean_image_has_no_findings():
    assert parse_trivy({"SchemaVersion": 2, "ArtifactName": "x"}) == []


def test_parse_trivy_rejects_other_json():
    with pytest.raises(ParseError):
        parse_trivy({"hello": "world"})


def test_parse_cyclonedx_flattens_nested_components():
    names = [c["name"] for c in parse_cyclonedx(load("sbom.cdx.json"))]
    assert names == ["openssl", "fastapi", "starlette"]


def test_parse_cyclonedx_rejects_spdx():
    with pytest.raises(ParseError):
        parse_cyclonedx({"spdxVersion": "SPDX-2.3"})
