"""Turn findings into a score and grade."""
from app.models import Finding, Grade, Report

WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


# Categories that describe the same underlying problem (text aimed at the agent) from
# different vantage points. Static, judge and model all name it differently.
FAMILY = {"prompt_injection": "injection", "tool_poisoning": "injection", "response_injection": "injection"}
RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower is more severe


def finding_key(fi: Finding) -> tuple[str, str, str]:
    """(problem family, where it was seen: tool definition vs response, which tool)."""
    loc = fi.location
    if loc.startswith("response:"):
        kind, subject = "response", loc[len("response:"):]
    elif loc.startswith("tool:"):
        kind, subject = "tool", loc[len("tool:"):]
    else:
        kind, subject = "tool", loc
    subject = subject.split(".", 1)[0]  # strip .description / .input_schema
    return (FAMILY.get(fi.category, fi.category), kind, subject)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (family, kind, tool); the most severe wins, the earliest on a tie."""
    best: dict[tuple[str, str, str], Finding] = {}
    order: list[tuple[str, str, str]] = []
    for fi in findings:
        key = finding_key(fi)
        if key not in best:
            best[key] = fi
            order.append(key)
        elif RANK[fi.severity] < RANK[best[key].severity]:
            best[key] = fi
    return [best[k] for k in order]


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
