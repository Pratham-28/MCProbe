"""Deterministic checks over an MCP inventory. No network, no LLM."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Finding, Inventory

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
    r"read\s+~/\.ssh",
    r"\bapi[_ ]?keys?\b.{0,30}\b(include|send|attach)",
]
_STRONG = [re.compile(p, re.I | re.S) for p in STRONG_INJECTION]
_WEAK = [re.compile(p, re.I | re.S) for p in WEAK_INJECTION]

CRITICAL_WORDS = ["exec", "shell", "eval", "command", "sudo"]
ACTION_WORDS = ["delete", "remove", "rm", "write_file", "upload", "drop", "kill"]
SENSITIVE_NOUNS = ["credential", "password", "token", "secret"]
# Static check: anything powerful or sensitive gets an excessive_permissions finding.
DANGEROUS_WORDS = CRITICAL_WORDS + ACTION_WORDS + SENSITIVE_NOUNS
# Prober gate: never *call* tools that act on the world. Sensitive nouns are intentionally
# absent: reading get_token_count or get_config is how the prober observes secret leaks.
DESTRUCTIVE_WORDS = CRITICAL_WORDS + ACTION_WORDS + [
    "send", "email", "pay", "transfer", "write", "create", "update", "post", "purge",
]

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
        recommendation="Remove any instructions addressed to the agent. Descriptions should "
                       "state what the tool does and nothing else.",
        phase=phase,
        source="static",
    )


def run_static_checks(inv: Inventory, url: str) -> list[Finding]:
    findings: list[Finding] = []

    if inv.instructions:
        fi = _injection_finding(inv.instructions, "server.instructions", "prompt_injection")
        if fi:
            findings.append(fi)

    for t in inv.tools:
        fi = _injection_finding(t.description or "", f"tool:{t.name}.description", "tool_poisoning")
        if fi:
            findings.append(fi)

        if t.tokens > PER_TOOL_TOKEN_LIMIT:
            findings.append(Finding(
                category="context_bloat", severity="medium",
                title=f"Tool '{t.name}' costs {t.tokens} tokens",
                detail=f"This single tool definition uses {t.tokens} tokens of context on every "
                       f"request (limit {PER_TOOL_TOKEN_LIMIT}).",
                location=f"tool:{t.name}", evidence=(t.description or "")[:300],
                recommendation="Shorten the description; move detail into the tool's result or docs.",
                phase="analyze", source="static"))

        hits = _word_hits(t.name + " " + (t.description or ""), DANGEROUS_WORDS)
        if hits:
            ann = t.annotations or {}
            annotated = ann.get("destructive_hint") is not None or ann.get("read_only_hint") is not None
            critical = bool(_word_hits(t.name + " " + (t.description or ""), CRITICAL_WORDS))
            sev = "high" if (critical and not annotated) else "medium"
            findings.append(Finding(
                category="excessive_permissions", severity=sev,
                title=f"Tool '{t.name}' exposes sensitive capability",
                detail="Name or description suggests a powerful capability (" + ", ".join(hits) + ")"
                       + ("" if annotated else " and the tool carries no readOnly/destructive annotations"),
                location=f"tool:{t.name}", evidence=(t.description or "")[:300],
                recommendation="Add ToolAnnotations, narrow the capability, and require confirmation "
                               "for destructive operations.",
                phase="analyze", source="static"))

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
