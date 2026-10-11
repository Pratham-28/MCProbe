"""Turn findings into a score, a grade, a verdict, and per-finding impact / fix text."""
from __future__ import annotations

import re

from app.frameworks import attach_references
from app.models import Finding, Grade, Report

WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower is more severe

# Categories that describe the same underlying problem (text aimed at the agent) from
# different vantage points. Static, judge and model all name it differently.
FAMILY = {"prompt_injection": "injection", "tool_poisoning": "injection", "response_injection": "injection"}


def split_location(loc: str) -> tuple[str, str]:
    """('tool'|'response'|'server', subject). 'tool:x.description' -> ('tool','x')."""
    if loc.startswith("response:"):
        return "response", loc[len("response:"):].split(".", 1)[0]
    if loc.startswith("tool:"):
        return "tool", loc[len("tool:"):].split(".", 1)[0]
    return "server", loc


def finding_key(fi: Finding) -> tuple[str, str, str]:
    """(problem family, where it was seen: tool definition vs response, which tool)."""
    kind, subject = split_location(fi.location)
    kind = "tool" if kind == "server" else kind
    return (FAMILY.get(fi.category, fi.category), kind, subject)


def recategorise(fi: Finding) -> None:
    """Model- and judge-written findings use loose categories; pin them to where they were seen.

    - prompt_injection reported on a tool definition is tool poisoning; on a response it is
      response injection. 'prompt_injection' is reserved for the server-level instructions.
    - a schema_quality finding that is really about a truncated / malformed description gets
      its own category so it is not labelled 'sloppy input validation'.
    """
    kind, _ = split_location(fi.location)
    if fi.category == "prompt_injection" and kind == "tool":
        fi.category = "tool_poisoning"
    elif fi.category == "prompt_injection" and kind == "response":
        fi.category = "response_injection"
    if fi.category == "schema_quality" and re.search(
            r"truncat|malformed|cut off|incomplete|ends with|no continuation|unfinished", fi.title + " " + fi.detail, re.I):
        fi.category = "malformed_description"
    if fi.category == "malformed_description" and fi.severity in ("critical", "high", "medium"):
        fi.severity = "low"  # cosmetic on its own, whatever the model thought


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (family, kind, tool); the most severe wins, the earliest on a tie."""
    best: dict[tuple[str, str, str], Finding] = {}
    order: list[tuple[str, str, str]] = []
    for fi in findings:
        key = finding_key(fi)
        if key not in best:
            best[key] = fi
            order.append(key)
            continue
        cur = best[key]
        winner, loser = (fi, cur) if RANK[fi.severity] < RANK[cur.severity] else (cur, fi)
        # The pattern-match finding carries the exact matched phrases and the raw evidence;
        # keep them even when the model's more severe wording wins the row.
        if not winner.matches and loser.matches:
            winner.matches = list(loser.matches)
            if loser.evidence and not any(m in winner.evidence for m in loser.matches):
                winner.evidence = loser.evidence
        if not winner.diff and loser.diff:
            winner.diff = loser.diff
        best[key] = winner
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


# ---------------------------------------------------------------------------
# Human text: impact (what it means), fix (what to do), verdict fragment.
# ---------------------------------------------------------------------------

def _num(text: str) -> str | None:
    m = re.search(r"(\d[\d,]*)\s*tokens", text)
    return m.group(1) if m else None


def _fmt(n: str | int) -> str:
    try:
        return f"{int(str(n).replace(',', '')):,}"
    except ValueError:
        return str(n)


def describe(fi: Finding, all_findings: list[Finding] | None = None) -> tuple[str, str, str]:
    """Return (impact, fix, verdict_fragment) specific to this finding."""
    kind, subject = split_location(fi.location)
    tool = subject if kind in ("tool", "response") else None
    cat = fi.category
    phrase = fi.matches[0] if fi.matches else None
    quoted = f' ("{phrase[:60]}")' if phrase else ""

    if cat == "tool_poisoning" and "rug pull" in fi.title.lower():
        changed = ", ".join(sorted((fi.diff or {}).keys())) or fi.evidence
        return (f"The server changed the definition of {changed} after it was used. A server that behaves "
                f"like this can turn malicious after you have approved it.",
                "Don't connect. Report it to the maintainer, and pin tool definitions if you must use it.",
                "changed its tools after being used")
    if cat == "tool_poisoning":
        return (f"The description of '{tool}' contains an instruction aimed at your AI{quoted}. "
                f"An agent that reads it may follow it silently.",
                f"Don't connect. Report '{tool}' to the maintainer.",
                "hides instructions aimed at your AI")
    if cat == "prompt_injection":
        return (f"The server's own instructions try to steer your AI{quoted} instead of describing the server.",
                "Don't connect until the instructions only describe the server.",
                "tries to steer your AI through its instructions")
    if cat == "response_injection":
        return (f"A call to '{tool}' returned text that gives your AI new orders{quoted}. "
                f"This is how agents get tricked into leaking data.",
                f"Treat '{tool}' output as untrusted; don't connect this server to an agent with other tools.",
                "returns output that tries to hijack your AI")
    if cat == "secret_leak":
        return (f"A call to '{tool}' returned a credential-shaped value{quoted}. Anything that reads the "
                f"response, including your AI's logs, now has it.",
                "Rotate this key now and ask the maintainer to stop returning it.",
                "leaks a credential")
    if cat == "excessive_permissions":
        safe = sorted({split_location(f.location)[1] for f in (all_findings or []) if False})  # placeholder, filled in verdict stage
        if fi.title.startswith("Possibly dangerous"):
            return (f"'{tool}' mentions {', '.join(repr(m) for m in fi.matches) or 'a sensitive word'} in its "
                    f"description but its name does not suggest a destructive action.",
                    f"Read the description of '{tool}' before allowing it; it is probably fine.",
                    "mentions sensitive capabilities")
        return (f"'{tool}' can do far more than a typical tool should ({', '.join(fi.matches) or 'see description'})"
                + ("." if "annotations" not in fi.detail else " and it is not marked read-only or destructive."),
                f"Only allow the read-only tools of this server in your client and leave '{tool}' out.",
                "exposes dangerous capabilities")
    if cat == "context_bloat":
        n = _num(fi.title) or _num(fi.detail)
        if kind == "response":
            return (f"One call to '{tool}' returned ~{_fmt(n) if n else 'many'} tokens, which can push other "
                    f"context out of your AI's window.",
                    f"Ask '{tool}' for less (filters, pagination) or wrap it so results are summarised first.",
                    f"returns oversized responses from '{tool}'")
        if kind == "tool":
            share = re.search(r"\((\d+)%", fi.detail)
            return (f"'{tool}' alone costs {_fmt(n) if n else 'hundreds of'} tokens"
                    + (f" ({share.group(1)}% of this server's total)" if share else "") + " on every agent turn.",
                    f"Turn on only the tools you need, or ask the maintainer to shorten '{tool}'.",
                    f"has a tool ('{tool}') that alone costs {_fmt(n) if n else 'hundreds of'} tokens")
        return (f"Connecting this server adds {_fmt(n) if n else 'thousands of'} tokens to every agent turn, "
                f"diluting attention and raising cost.",
                "Turn on only the tools you need (e.g. a ?tools= filter) or split the server.",
                "eats a large share of your AI's context")
    if cat == "data_exfiltration":
        return (f"'{tool or 'this server'}' pushes your data toward a third party.",
                "Don't connect. Report to the maintainer.", "tries to send your data elsewhere")
    if cat == "schema_quality":
        return (f"'{tool}' accepts arbitrary input, so your AI cannot validate arguments and the server cannot reject bad calls.",
                f"Ask the maintainer to declare properties for '{tool}'. Low risk on its own.",
                "accepts poorly validated input")
    if cat == "malformed_description":
        return (f"The description of '{tool}' looks truncated or malformed, so your AI may misunderstand what it does.",
                f"Ask the maintainer to fix the description of '{tool}'. Cosmetic unless combined with other issues.",
                "has a malformed tool description")
    if cat == "tool_shadowing":
        return (f"'{tool}' mimics a well-known tool name and can be picked by mistake.",
                f"Rename or disable '{tool}' in your client.", "impersonates another tool")
    if cat == "insecure_transport":
        return ("Tool calls and any token you supply travel in plain text.",
                "Use the https:// address of this server if one exists.", "talks over an unencrypted connection")
    if cat == "connectivity":
        return (fi.detail[:200], fi.recommendation or "Check the URL and try again.", "could not be reached")
    return (fi.detail[:200], fi.recommendation, "has issues")


def verdict_sentence(g: str, findings: list[Finding]) -> str:
    if g == "?":
        return "MCProbe could not read this server, so it has no grade."
    if not findings:
        return "We connected, read every tool, and tried the safe ones. Nothing suspicious turned up."
    ranked = sorted(findings, key=lambda f: RANK[f.severity])
    frags: list[str] = []
    for f in ranked:
        frag = describe(f)[2]
        if frag not in frags:
            frags.append(frag)
        if len(frags) == 2:
            break
    return "This server " + " and ".join(frags) + "."


VERDICT_HEAD = {"A": "Looks safe to connect.", "B": "Mostly fine. Read the notes below.",
                "C": "Connect with caution.", "D": "Do not connect.", "F": "Do not connect.",
                "?": "Couldn't scan."}


def apply_scoring(report: Report) -> None:
    for fi in report.findings:
        recategorise(fi)
    report.findings = dedupe(report.findings)
    attach_references(report.findings)
    for fi in report.findings:
        fi.references = fi.references or []
        impact, fix, _ = describe(fi, report.findings)
        if not fi.impact:
            fi.impact = impact
        if not fi.fix:
            fi.fix = fix
    report.severity_counts = severity_counts(report.findings)
    report.score = score(report.findings)
    report.grade = grade(report.score)
    report.verdict = VERDICT_HEAD[report.grade] + " " + verdict_sentence(report.grade, report.findings)
