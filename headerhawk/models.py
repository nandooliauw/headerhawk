"""Data models shared by every module in headerhawk."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Severity ranking used for sorting findings in reports.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Score credit per check status. A warning still earns partial credit so that
# "almost right" configurations are not punished like missing ones.
STATUS_CREDIT = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "skip": 0.0, "info": 1.0}


@dataclass
class Check:
    """A single audit assertion.

    ``weight`` is the number of points the check is worth in the 0-100 score.
    ``severity`` describes how bad it is when the check *fails*.
    """

    id: str
    title: str
    category: str
    severity: str
    weight: int
    status: str = "pass"  # pass | warn | fail | skip | info
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "weight": self.weight,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class Hop:
    """One request/response in the redirect chain."""

    url: str
    status: int = 0
    location: str = ""
    tls: dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    """The result of fetching a target, including TLS metadata per hop."""

    requested_url: str
    final_url: str = ""
    status: int = 0
    hops: list[Hop] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    body_snippet: str = ""
    tls: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def header(self, name: str, default: str = "") -> str:
        values = self.headers.get(name.lower())
        return values[0] if values else default

    def header_all(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


@dataclass
class Report:
    target: str
    final_url: str
    generated_at: str
    score: int
    grade: str
    checks: list[Check]
    response: Response
    probed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0, "info": 0}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1
        return counts

    def findings(self) -> list[Check]:
        """Failing and warning checks, worst first."""
        items = [c for c in self.checks if c.status in ("fail", "warn")]
        return sorted(items, key=lambda c: (SEVERITY_ORDER.get(c.severity, 9), c.id))

    def category_scores(self) -> list[dict[str, Any]]:
        buckets: dict[str, list[Check]] = {}
        for check in self.checks:
            if check.status == "skip" or check.weight == 0:
                continue
            buckets.setdefault(check.category, []).append(check)
        out = []
        for category, checks in buckets.items():
            total = sum(c.weight for c in checks)
            earned = sum(c.weight * STATUS_CREDIT[c.status] for c in checks)
            out.append(
                {
                    "category": category,
                    "score": round(100 * earned / total) if total else 0,
                    "points": f"{earned:g}/{total}",
                }
            )
        return sorted(out, key=lambda item: item["category"])

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "headerhawk",
            "version": __import__("headerhawk").__version__,
            "target": self.target,
            "final_url": self.final_url,
            "generated_at": self.generated_at,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts,
            "categories": self.category_scores(),
            "checks": [c.as_dict() for c in self.checks],
            "probes": self.probed,
            "response": {
                "status": self.response.status,
                "redirects": [
                    {"url": h.url, "status": h.status, "location": h.location}
                    for h in self.response.hops
                ],
                "headers": {k: v for k, v in sorted(self.response.headers.items())},
                "tls": self.response.tls,
                "error": self.response.error,
            },
        }
