"""Turn scanner output into plain dicts. No database code here, so it's easy to test."""

from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ParseError(ValueError):
    pass


def parse_trivy(report: Any) -> list[dict[str, Any]]:
    """Findings from a Trivy JSON report (`trivy image --format json`)."""
    if not isinstance(report, dict) or not ({"SchemaVersion", "Results"} & report.keys()):
        raise ParseError("vuln_report is not a Trivy JSON report")

    findings = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity", "UNKNOWN")).upper()
            findings.append(
                {
                    "vuln_id": vuln.get("VulnerabilityID", ""),
                    "package_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion") or None,
                    "severity": severity if severity in SEVERITIES else "UNKNOWN",
                    "title": vuln.get("Title") or "",
                    "target": target,
                }
            )
    return findings


def parse_cyclonedx(sbom: Any) -> list[dict[str, Any]]:
    """Components from a CycloneDX JSON SBOM, flattening nested components."""
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ParseError("sbom is not a CycloneDX JSON document")

    components: list[dict[str, Any]] = []

    def walk(items: list[dict[str, Any]]) -> None:
        for c in items:
            components.append(
                {
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "purl": c.get("purl", ""),
                    "type": c.get("type", ""),
                }
            )
            walk(c.get("components") or [])

    walk(sbom.get("components") or [])
    return components


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[f["severity"]] += 1
    return counts
