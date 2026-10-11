from app.models import Finding, Report, PHASES
from app.tokens import count_tokens


def test_report_defaults_have_all_phases_pending():
    r = Report(url="http://x")
    assert [p.phase for p in r.phases] == PHASES
    assert all(p.status == "pending" for p in r.phases)
    assert r.grade == "F" and r.score == 0


def test_report_round_trips_through_json():
    r = Report(url="http://x")
    r.findings.append(Finding(category="context_bloat", severity="medium", title="t",
                              detail="d", location="tool:x", phase="analyze", source="static"))
    again = Report.model_validate_json(r.model_dump_json())
    assert again.findings[0].title == "t"


def test_evidence_is_truncated_to_limit():
    from app.models import EVIDENCE_LIMIT
    f = Finding(category="prompt_injection", severity="high", title="t", detail="d",
                location="l", evidence="x" * (EVIDENCE_LIMIT + 400), phase="analyze", source="static")
    assert len(f.evidence) == EVIDENCE_LIMIT


def test_count_tokens():
    assert count_tokens("") == 0
    assert count_tokens("hello world") == 2


def test_finding_has_empty_references_by_default():
    f = Finding(category="secret_leak", severity="high", title="t", detail="d", location="l", phase="probe", source="prober")
    assert f.references == []
