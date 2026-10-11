"""Deterministic checks over an MCP inventory. No network, no LLM."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Finding, Inventory, ToolInfo

STRONG_INJECTION = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions",
    r"do\s+not\s+(tell|inform|mention|reveal)\s+(this\s+to\s+)?the\s+user",
    r"<\s*important\s*>",
    r"<\s*system\s*>",
    r"before\s+(using|calling|running)\s+this\s+tool",
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
]
WEAK_INJECTION = [
    r"\bsystem\s*:",
    r"you\s+must\s+always",
    r"include\s+the\s+contents\s+of",
    r"\bsend\s+.{0,40}\s+to\s+https?://",
    r"\b(hidden|secret)\s+instruction",
    r"without\s+(telling|informing)\s+the\s+user",
    r"read\s+(the\s+file\s+)?~/\.ssh\S*",
    r"\bapi[_ ]?keys?\b.{0,30}\b(include|send|attach)",
]
_STRONG = [re.compile(p, re.I | re.S) for p in STRONG_INJECTION]
_WEAK = [re.compile(p, re.I | re.S) for p in WEAK_INJECTION]

# Exec-class words: dangerous wherever they appear.
CRITICAL_WORDS = ["exec", "shell", "eval", "command", "sudo", "kill", "drop"]
ACTION_WORDS = ["delete", "remove", "rm", "write_file", "upload"]
SENSITIVE_NOUNS = ["credential", "password", "token", "secret"]
# Static check: anything powerful or sensitive gets an excessive_permissions finding.
DANGEROUS_WORDS = CRITICAL_WORDS + ACTION_WORDS + SENSITIVE_NOUNS
# Prober gate: never *call* tools that act on the world. Sensitive nouns are intentionally
# absent: reading get_token_count or get_config is how the prober observes secret leaks.
DESTRUCTIVE_WORDS = CRITICAL_WORDS + ACTION_WORDS + [
    "send", "email", "pay", "transfer", "write", "create", "update", "post", "purge",
]
# A keyword next to one of these is the description saying what the tool does NOT do.
NEGATIONS = re.compile(
    r"(read[- ]only|never\s+(returns?|exposes?|reveals?|sends?)|does\s+not|doesn't|cannot|can't|"
    r"no\s+(write|delete|exec)|without\s+(modifying|changing|executing))", re.I)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("OpenAI-style key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
]

PER_TOOL_TOKEN_LIMIT = 400
TOTAL_TOKEN_LIMIT = 6000
TOOL_COUNT_LIMIT = 30


def find_injection(text: str) -> tuple[list[str], list[str]]:
    if not text:
        return [], []
    strong = [m.group(0) for rx in _STRONG for m in [rx.search(text)] if m]
    weak = [m.group(0) for rx in _WEAK for m in [rx.search(text)] if m]
    return strong, weak


def _word_hits(text: str, words: list[str]) -> list[str]:
    low = text.lower()
    return [w for w in words if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low)]


def _negated(description: str, word: str) -> bool:
    """True when every sentence mentioning `word` is negated, either in that sentence or the one
    right after it ("...credential access details. Read-only and never returns credential values.")."""
    sentences = re.split(r"(?<=[.!?])\s+", description)
    idx = [i for i, s in enumerate(sentences) if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", s, re.I)]
    return bool(idx) and all(NEGATIONS.search(" ".join(sentences[i:i + 2])) for i in idx)


def _injection_finding(text: str, location: str, category: str, phase="analyze") -> Finding | None:
    strong, weak = find_injection(text)
    if not strong and not weak:
        return None
    matched = strong + weak
    return Finding(
        category=category,  # type: ignore[arg-type]
        severity="high" if strong else "medium",
        title="Instructions aimed at the AI agent" if category == "prompt_injection"
        else "Tool description contains agent-directed instructions",
        detail="Text that should only describe functionality contains phrases that try to "
               "steer the agent's behaviour. Matched: " + "; ".join(repr(m[:60]) for m in matched),
        location=location,
        evidence=text,
        matches=matched,
        recommendation="Remove any instructions addressed to the agent. Descriptions should "
                       "state what the tool does and nothing else.",
        phase=phase,
        source="static",
    )


def dangerous_capability(t: ToolInfo) -> Finding | None:
    """Keyword rule with three tiers: name or exec-class word keeps full severity; a keyword
    only in the description is low; a negated keyword ("read-only", "never returns") is skipped."""
    desc = t.description or ""
    name_hits = _word_hits(t.name.replace("_", " ").replace("-", " "), DANGEROUS_WORDS)
    desc_hits = [w for w in _word_hits(desc, DANGEROUS_WORDS) if not _negated(desc, w)]
    exec_hits = [w for w in name_hits + desc_hits if w in CRITICAL_WORDS]
    if not name_hits and not desc_hits:
        return None
    ann = t.annotations or {}
    read_only = ann.get("read_only_hint") is True
    annotated = ann.get("destructive_hint") is not None or ann.get("read_only_hint") is not None
    hits = sorted(set(name_hits + desc_hits))
    if name_hits or exec_hits:
        sev = "high" if exec_hits else "medium"
        # An honest annotation (read-only, or declared destructive) steps the severity down once:
        # the server told the truth, so the agent can be configured around it.
        if read_only or ann.get("destructive_hint") is True:
            sev = {"high": "medium", "medium": "low"}[sev]
        title = f"Tool '{t.name}' exposes sensitive capability"
        detail = ("Name or description suggests a powerful capability (" + ", ".join(hits) + ")"
                  + ("" if annotated else " and the tool carries no readOnly/destructive annotations"))
    else:
        sev = "low"
        title = f"Possibly dangerous (keyword match): '{t.name}'"
        detail = ("The description mentions " + ", ".join(repr(w) for w in hits) + " but the tool name does not "
                  "suggest a destructive action. Treat as a hint to read the description, not as a verdict.")
    return Finding(
        category="excessive_permissions", severity=sev, title=title, detail=detail,
        location=f"tool:{t.name}", evidence=desc[:300], matches=hits,
        recommendation="Add ToolAnnotations, narrow the capability, and require confirmation "
                       "for destructive operations.",
        phase="analyze", source="static")


def run_static_checks(inv: Inventory, url: str) -> list[Finding]:
    findings: list[Finding] = []

    if inv.instructions:
        fi = _injection_finding(inv.instructions, "server.instructions", "prompt_injection")
        if fi:
            findings.append(fi)

    total = inv.total_tokens or sum(t.tokens for t in inv.tools) or 1
    for t in inv.tools:
        fi = _injection_finding(t.description or "", f"tool:{t.name}.description", "tool_poisoning")
        if fi:
            findings.append(fi)

        if t.tokens > PER_TOOL_TOKEN_LIMIT:
            share = round(100 * t.tokens / total)
            findings.append(Finding(
                category="context_bloat", severity="medium",
                title=f"Tool '{t.name}' costs {t.tokens} tokens",
                detail=f"'{t.name}' alone is {t.tokens} tokens ({share}% of this server's total), paid on "
                       f"every request (limit {PER_TOOL_TOKEN_LIMIT} per tool).",
                location=f"tool:{t.name}", evidence=(t.description or "")[:300],
                recommendation="Shorten the description; move detail into the tool's result or docs.",
                phase="analyze", source="static"))

        fi = dangerous_capability(t)
        if fi:
            findings.append(fi)

        schema = t.input_schema or {}
        if not schema or (schema.get("additionalProperties") is True and not schema.get("properties")):
            findings.append(Finding(
                category="schema_quality", severity="low",
                title=f"Tool '{t.name}' has an unconstrained input schema",
                detail="No input schema, or a free-form object. The agent cannot validate arguments "
                       "and the server accepts arbitrary input.",
                location=f"tool:{t.name}.input_schema", evidence=str(schema)[:300],
                recommendation="Declare explicit properties and mark required ones.",
                phase="analyze", source="static"))

    if inv.total_tokens > TOTAL_TOKEN_LIMIT:
        findings.append(Finding(
            category="context_bloat", severity="high",
            title=f"Tool list costs {inv.total_tokens} tokens of context",
            detail=f"Connecting to this server adds {inv.total_tokens} tokens to every agent turn "
                   f"(limit {TOTAL_TOKEN_LIMIT}).",
            location="server.tools", evidence=f"{len(inv.tools)} tools, {inv.total_tokens} tokens",
            recommendation="Trim descriptions, split the server, or expose fewer tools.",
            phase="analyze", source="static"))
    elif len(inv.tools) > TOOL_COUNT_LIMIT:
        findings.append(Finding(
            category="context_bloat", severity="medium",
            title=f"Server exposes {len(inv.tools)} tools",
            detail="Large tool lists dilute the agent's attention and raise the chance of wrong tool choice.",
            location="server.tools", evidence=", ".join(t.name for t in inv.tools[:20]),
            recommendation="Group related tools or split into focused servers.",
            phase="analyze", source="static"))

    parsed = urlparse(url)
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        findings.append(Finding(
            category="insecure_transport", severity="medium",
            title="Server is reachable over plain HTTP",
            detail="Tool arguments and results, and any bearer token, travel unencrypted.",
            location="server.url", evidence=url,
            recommendation="Serve over HTTPS.",
            phase="analyze", source="static"))

    return findings
