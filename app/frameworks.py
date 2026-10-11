"""Map Airlock finding categories onto MITRE ATLAS, OWASP LLM Top 10 and MITRE ATT&CK.

IDs verified against dist/ATLAS.yaml (mitre-atlas/atlas-data), genai.owasp.org/llm-top-10
and attack.mitre.org on 2026-10-11.
"""
from __future__ import annotations

import re

from app.models import Finding

ATLAS = "MITRE ATLAS"
OWASP = "OWASP LLM Top 10"
ATTACK = "MITRE ATT&CK"


def _atlas(tid: str, name: str) -> dict[str, str]:
    return {"framework": ATLAS, "id": tid, "name": name, "url": f"https://atlas.mitre.org/techniques/{tid}"}


def _attack(tid: str, name: str) -> dict[str, str]:
    path = tid.replace(".", "/")
    return {"framework": ATTACK, "id": tid, "name": name, "url": f"https://attack.mitre.org/techniques/{path}/"}


def _owasp(num: str, name: str, slug: str) -> dict[str, str]:
    return {"framework": OWASP, "id": f"LLM{num}:2025", "name": name, "url": f"https://genai.owasp.org/llmrisk/{slug}/"}


# Verified reference objects
T0051 = _atlas("AML.T0051", "LLM Prompt Injection")
T0080 = _atlas("AML.T0080", "AI Agent Context Poisoning")
T0110 = _atlas("AML.T0110", "AI Agent Tool Poisoning")
T0109 = _atlas("AML.T0109", "AI Supply Chain Rug Pull")
T0057 = _atlas("AML.T0057", "LLM Data Leakage")
T0098 = _atlas("AML.T0098", "AI Agent Tool Credential Harvesting")
T0053 = _atlas("AML.T0053", "AI Agent Tool Invocation")
T0101 = _atlas("AML.T0101", "Data Destruction via AI Agent Tool Invocation")
T0086 = _atlas("AML.T0086", "Exfiltration via AI Agent Tool Invocation")
T0034_002 = _atlas("AML.T0034.002", "Agentic Resource Consumption")

LLM01 = _owasp("01", "Prompt Injection", "llm01-prompt-injection")
LLM02 = _owasp("02", "Sensitive Information Disclosure", "llm022025-sensitive-information-disclosure")
LLM03 = _owasp("03", "Supply Chain", "llm032025-supply-chain")
LLM06 = _owasp("06", "Excessive Agency", "llm062025-excessive-agency")
LLM10 = _owasp("10", "Unbounded Consumption", "llm102025-unbounded-consumption")

T1195 = _attack("T1195", "Supply Chain Compromise")
T1552 = _attack("T1552", "Unsecured Credentials")
T1059 = _attack("T1059", "Command and Scripting Interpreter")
T1041 = _attack("T1041", "Exfiltration Over C2 Channel")
T1036 = _attack("T1036", "Masquerading")
T1557 = _attack("T1557", "Adversary-in-the-Middle")

_EXEC_WORDS = re.compile(r"(?<![a-z])(exec|shell|command|eval|sudo)(?![a-z])", re.I)
_DESTROY_WORDS = re.compile(r"(?<![a-z])(delete|remove|drop|purge|kill|destroy|truncate)(?![a-z])", re.I)


def references_for(fi: Finding) -> list[dict[str, str]]:
    text = f"{fi.title} {fi.detail} {fi.location}"
    cat = fi.category
    if cat == "tool_poisoning":
        if "rug pull" in fi.title.lower():
            return [T0109, LLM03, T1195]
        return [T0110, LLM01, T1195]
    if cat == "prompt_injection":
        return [T0051, T0080, LLM01]
    if cat == "response_injection":
        return [T0051, T0080, LLM01]
    if cat == "secret_leak":
        return [T0057, T0098, LLM02, T1552]
    if cat == "excessive_permissions":
        refs = [T0053, LLM06]
        if _EXEC_WORDS.search(text):
            refs.append(T1059)
        if _DESTROY_WORDS.search(text):
            refs.append(T0101)
        return refs
    if cat == "data_exfiltration":
        return [T0086, LLM02, T1041]
    if cat == "context_bloat":
        return [T0034_002, LLM10]
    if cat == "schema_quality":
        return [T0053, LLM06]
    if cat == "tool_shadowing":
        return [T0110, T1036, LLM01]
    if cat == "insecure_transport":
        return [T1557, LLM03]
    return []


def attach_references(findings: list[Finding]) -> None:
    for fi in findings:
        if not fi.references:
            fi.references = references_for(fi)
