"""Queries shared by the API and the UI."""

from sqlalchemy import Select, case, select

from app.models import Finding
from app.parsers import SEVERITIES

_severity_rank = case(
    {s: i for i, s in enumerate(SEVERITIES)}, value=Finding.severity, else_=len(SEVERITIES)
)


def findings_query(build_id: int, severity: str | None, fixable: bool) -> Select[tuple[Finding]]:
    query = select(Finding).where(Finding.build_id == build_id)
    if severity:
        query = query.where(Finding.severity == severity.upper())
    if fixable:
        query = query.where(Finding.fixed_version.is_not(None))
    return query.order_by(_severity_rank, Finding.vuln_id, Finding.package_name)
