from app.models import Finding, Report
from app.scoring import apply_scoring, dedupe, grade, score, severity_counts


def f(sev, title="t", location="l", category="context_bloat"):
    return Finding(category=category, severity=sev, title=title, detail="d",
                   location=location, phase="analyze", source="static")


def test_score_weights():
    assert score([]) == 100
    assert score([f("critical")]) == 70
    assert score([f("high")]) == 85
    assert score([f("medium")]) == 93
    assert score([f("low")]) == 98
    assert score([f("info")]) == 100
    assert score([f("critical")] * 4) == 0  # floored


def test_grade_thresholds():
    assert grade(100) == "A" and grade(90) == "A"
    assert grade(89) == "B" and grade(75) == "B"
    assert grade(74) == "C" and grade(60) == "C"
    assert grade(59) == "D" and grade(40) == "D"
    assert grade(39) == "F" and grade(0) == "F"


def test_dedupe_collapses_same_category_location_title():
    a, b = f("high", "x", "tool:a"), f("high", "x", "tool:a")
    c = f("high", "x", "tool:b")
    assert len(dedupe([a, b, c])) == 2


def test_apply_scoring_fills_report():
    r = Report(url="u")
    r.findings = [f("high"), f("high"), f("low", "other", "tool:b")]
    apply_scoring(r)
    assert len(r.findings) == 2
    assert r.severity_counts == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert r.score == 83 and r.grade == "B"


def test_dedupe_collapses_injection_family_on_same_tool_keeping_highest_severity():
    static = f("high", "Tool description contains agent-directed instructions", "tool:search_docs.description", "tool_poisoning")
    judge = f("high", "Tool 'search_docs' contains agent-directed instructions", "tool:search_docs.description", "tool_poisoning")
    model = f("critical", "Hidden SSH exfil", "tool:search_docs", "prompt_injection")
    out = dedupe([static, judge, model])
    assert len(out) == 1 and out[0].severity == "critical" and out[0].title == "Hidden SSH exfil"


def test_dedupe_keeps_description_and_response_findings_apart():
    desc = f("medium", "big description", "tool:summarize", "context_bloat")
    resp = f("medium", "big response", "response:summarize", "context_bloat")
    assert len(dedupe([desc, resp])) == 2


def test_dedupe_keeps_first_on_equal_severity():
    a = f("high", "static one", "tool:exec_shell", "excessive_permissions")
    b = f("high", "judge one", "tool:exec_shell.description", "excessive_permissions")
    out = dedupe([a, b])
    assert len(out) == 1 and out[0].title == "static one"
