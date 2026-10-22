import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional

from ..config import settings

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    severity: str
    passed: bool
    description: str = ""
    recommendation: str = ""
    evidence: Optional[str] = None
    reference: Optional[str] = None


class TargetNotAllowed(Exception):
    """Raised when a target resolves to a private/internal address (SSRF guard)."""


def assert_public_host(host: Optional[str]) -> None:
    if not host:
        raise TargetNotAllowed("Missing hostname")
    if settings.ALLOW_PRIVATE_TARGETS:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"Cannot resolve host '{host}': {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise TargetNotAllowed(
                f"'{host}' resolves to non-public address {ip}. "
                "Set ALLOW_PRIVATE_TARGETS=true only for local development."
            )


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """Weighted pass ratio: each check counts by its severity weight.
    A failed critical caps the grade at D regardless of the ratio."""
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    failed = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings if not f.passed)
    score = 100 if total == 0 else round(100 * (1 - failed / total))
    has_critical = any(f.severity == "critical" and not f.passed for f in findings)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    if has_critical and grade in {"A+", "A", "B", "C"}:
        grade = "D"  # any critical issue caps the grade
    return score, grade


def summarize(findings: list[Finding]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if not f.passed:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    categories: dict[str, dict[str, int]] = {}
    for f in findings:
        c = categories.setdefault(f.category, {"passed": 0, "failed": 0})
        c["passed" if f.passed else "failed"] += 1
    return {
        "severity_counts": counts,
        "total_checks": len(findings),
        "passed": sum(1 for f in findings if f.passed),
        "failed": sum(1 for f in findings if not f.passed),
        "categories": categories,
    }
