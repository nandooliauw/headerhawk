"""Scoring: turn a list of checks into a 0-100 score and a letter grade."""

from __future__ import annotations

from .models import STATUS_CREDIT, Check

GRADE_BANDS = [
    (90, "A", "Hardened"),
    (80, "B", "Good"),
    (70, "C", "Needs work"),
    (60, "D", "Weak"),
    (0, "F", "Failing"),
]


def score(checks: list[Check]) -> tuple[int, str, str]:
    """Return ``(score, grade, label)``.

    Checks with status ``skip`` (not applicable, e.g. TLS on a plain HTTP host)
    are removed from both numerator and denominator so a target is never
    punished for something it cannot have.
    """

    applicable = [c for c in checks if c.status != "skip" and c.weight > 0]
    total = sum(c.weight for c in applicable)
    if total == 0:
        return 0, "F", "Not scored"
    earned = sum(c.weight * STATUS_CREDIT[c.status] for c in applicable)
    value = int(round(100 * earned / total))
    for threshold, grade, label in GRADE_BANDS:
        if value >= threshold:
            return value, grade, label
    return 0, "F", "Failing"
