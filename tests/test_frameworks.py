from app.frameworks import references_for
from app.models import Finding, Report
from app.scoring import apply_scoring


def f(category, title="t", detail="d"):
    return Finding(category=category, severity="high", title=title, detail=detail, location="tool:x", phase="analyze", source="static")


def ids(fi):
    return {(r["framework"], r["id"]) for r in references_for(fi)}


def test_every_reference_is_complete():
    for cat in ["tool_poisoning", "prompt_injection", "response_injection", "secret_leak", "excessive_permissions",
                "context_bloat", "data_exfiltration", "schema_quality", "tool_shadowing", "insecure_transport"]:
        refs = references_for(f(cat))
        assert refs, cat
        for r in refs:
            assert set(r) == {"framework", "id", "name", "url"} and r["url"].startswith("https://"), (cat, r)


def test_key_mappings():
    assert ("MITRE ATLAS", "AML.T0110") in ids(f("tool_poisoning"))
    assert ("MITRE ATLAS", "AML.T0109") in ids(f("tool_poisoning", title="Tool definitions changed after use (rug pull)"))
    assert ("MITRE ATLAS", "AML.T0051") in ids(f("response_injection"))
    assert ("OWASP LLM Top 10", "LLM01:2025") in ids(f("prompt_injection"))
    assert {("MITRE ATLAS", "AML.T0057"), ("MITRE ATT&CK", "T1552"), ("OWASP LLM Top 10", "LLM02:2025")} <= ids(f("secret_leak"))
    assert ("OWASP LLM Top 10", "LLM06:2025") in ids(f("excessive_permissions"))
    assert ("MITRE ATT&CK", "T1059") in ids(f("excessive_permissions", title="Tool 'exec_shell' exposes sensitive capability"))
    assert ("MITRE ATT&CK", "T1059") not in ids(f("excessive_permissions", title="Tool 'delete_file' exposes sensitive capability"))
    assert ("MITRE ATLAS", "AML.T0034.002") in ids(f("context_bloat"))
    assert ("MITRE ATT&CK", "T1557") in ids(f("insecure_transport"))
    assert references_for(f("connectivity")) == []


def test_apply_scoring_fills_references_without_overwriting():
    r = Report(url="u")
    pre = f("secret_leak"); pre.references = [{"framework": "Custom", "id": "X", "name": "n", "url": "https://x"}]
    r.findings = [pre, f("context_bloat")]
    apply_scoring(r)
    assert r.findings[0].references == pre.references
    assert any(x["id"] == "AML.T0034.002" for x in r.findings[1].references)
