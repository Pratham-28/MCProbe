"""Turn findings into a score and grade."""
from app.models import Finding, Grade, Report

WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for fi in findings:
        key = (fi.category, fi.location, fi.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(fi)
    return out


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for fi in findings:
        counts[fi.severity] += 1
    return counts


def score(findings: list[Finding]) -> int:
    total = sum(WEIGHTS[fi.severity] for fi in findings)
    return max(0, 100 - total)


def grade(value: int) -> Grade:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 40:
        return "D"
    return "F"


def apply_scoring(report: Report) -> None:
    report.findings = dedupe(report.findings)
    report.severity_counts = severity_counts(report.findings)
    report.score = score(report.findings)
    report.grade = grade(report.score)
