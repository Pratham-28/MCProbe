import asyncio
import json
from pathlib import Path

from app.mcp_client import make_inproc_connector
from app.models import Report
from app.orchestrator import AuditRun, run_audit
from app.store import Store
from fixtures.clean_server import server as clean
from fixtures.evil_server import server as evil
from tests.fakes import FakeLLM, FakeReply, tc

CLEAN_URL, EVIL_URL = "http://localhost:8101/mcp", "http://localhost:8102/mcp"
CONNECTOR = make_inproc_connector({CLEAN_URL: clean, EVIL_URL: evil})


def judge_ok(names):
    return FakeReply(content=json.dumps({"tools": [{"name": n, "risk": "none", "injection": False, "reasons": []} for n in names],
                                         "instructions": {"risk": "none", "reasons": []}}))


async def test_evil_server_grades_f(tmp_path: Path):
    llm = FakeLLM([
        judge_ok(["search_docs", "read_notes", "summarize", "exec_shell", "get_config"]),
        FakeReply(tool_calls=[tc("call_tool", {"name": "read_notes", "arguments": {"note_id": "1"}})]),
        FakeReply(tool_calls=[tc("call_tool", {"name": "get_config", "arguments": {}})]),
        FakeReply(tool_calls=[tc("finish", {"summary": "done"})]),
    ])
    run = AuditRun(Report(url=EVIL_URL, target_label="evil"))
    report = await run_audit(run, bearer_token=None, llm=llm, connector=CONNECTOR, store=Store(tmp_path))
    assert report.grade == "F"
    cats = {f.category for f in report.findings}
    assert {"tool_poisoning", "response_injection", "context_bloat", "secret_leak", "excessive_permissions"} <= cats
    assert all(p.status == "completed" for p in report.phases)
    assert report.inventory and len(report.inventory.tools) == 5
    assert len(report.probe_calls) == 2
    assert report.llm_usage["calls"] == 4
    assert (tmp_path / f"{report.audit_id}.json").exists()
    names = [e["event"] for e in run.events]
    assert names[0] == "phase" and names[-1] == "done" and "probe_call" in names and "finding" in names
    assert run.done


async def test_clean_server_grades_a(tmp_path: Path):
    llm = FakeLLM([judge_ok(["add", "get_time"]), FakeReply(tool_calls=[tc("finish", {"summary": "clean"})])])
    run = AuditRun(Report(url=CLEAN_URL))
    report = await run_audit(run, bearer_token=None, llm=llm, connector=CONNECTOR, store=Store(tmp_path))
    assert report.grade == "A" and report.score == 100 and report.findings == []


async def test_unreachable_server_reports_connectivity(tmp_path: Path):
    run = AuditRun(Report(url="http://localhost:9/mcp"))
    report = await run_audit(run, bearer_token=None, llm=FakeLLM(), connector=CONNECTOR, store=Store(tmp_path))
    assert report.grade == "F"
    assert report.findings[0].category == "connectivity" and report.findings[0].severity == "critical"
    assert report.phase("connect").status == "failed"
    assert {p.status for p in report.phases[1:4]} == {"skipped"}
    assert report.phase("report").status == "completed"
    assert run.events[-1]["event"] == "done"


async def test_judge_failure_does_not_stop_run(tmp_path: Path):
    llm = FakeLLM([FakeReply(content="nope"), FakeReply(content="nope"),
                   FakeReply(tool_calls=[tc("finish", {"summary": "x"})])])
    run = AuditRun(Report(url=CLEAN_URL))
    report = await run_audit(run, bearer_token=None, llm=llm, connector=CONNECTOR, store=Store(tmp_path))
    assert report.phase("analyze").status == "completed"
    assert "judge" in report.phase("analyze").detail.lower()
    assert report.phase("probe").status == "completed"


async def test_subscribe_replays_then_streams(tmp_path: Path):
    run = AuditRun(Report(url=CLEAN_URL))
    run.emit("log", {"phase": "connect", "message": "hello"})
    got = []

    async def consume():
        async for ev in run.subscribe():
            got.append(ev["event"])

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)
    run.emit("done", {})
    run.done = True
    run.close()
    await asyncio.wait_for(task, 2)
    assert got == ["log", "done"]


def test_store_roundtrip_and_listing(tmp_path: Path):
    s = Store(tmp_path)
    r1 = Report(url="u1", grade="A", score=100); r2 = Report(url="u2", grade="F", score=0)
    s.save(r1); s.save(r2)
    assert s.load(r1.audit_id).url == "u1" and s.load("missing") is None
    assert [x["url"] for x in s.list_summaries()] == ["u2", "u1"]


# --- fixes from final review ---
from contextlib import asynccontextmanager

from app.mcp_client import open_inproc


def failing_inventory_connector():
    @asynccontextmanager
    async def connector(url, token):
        async with open_inproc(clean) as conn:
            async def boom():
                raise RuntimeError("schema exploded")
            conn.inventory = boom
            yield conn
    return connector


async def test_discover_failure_marks_phase_failed_and_grades_f(tmp_path: Path):
    run = AuditRun(Report(url=CLEAN_URL))
    report = await run_audit(run, bearer_token=None, llm=FakeLLM(), connector=failing_inventory_connector(), store=Store(tmp_path))
    assert report.phase("discover").status == "failed" and "schema exploded" in report.phase("discover").detail
    assert {report.phase("analyze").status, report.phase("probe").status} == {"skipped"}
    assert report.grade == "F" and report.score == 0
    assert any(f.category == "connectivity" and f.severity == "critical" for f in report.findings)
    assert run.done and run.events[-1]["event"] == "done"


async def test_llm_usage_is_per_audit_not_cumulative(tmp_path: Path):
    llm = FakeLLM([judge_ok(["add", "get_time"]), FakeReply(tool_calls=[tc("finish", {"summary": "a"})]),
                   judge_ok(["add", "get_time"]), FakeReply(tool_calls=[tc("finish", {"summary": "b"})])])
    r1 = await run_audit(AuditRun(Report(url=CLEAN_URL)), bearer_token=None, llm=llm, connector=CONNECTOR, store=Store(tmp_path))
    r2 = await run_audit(AuditRun(Report(url=CLEAN_URL)), bearer_token=None, llm=llm, connector=CONNECTOR, store=Store(tmp_path))
    assert r1.llm_usage["calls"] == 2 and r2.llm_usage["calls"] == 2


class BrokenStore(Store):
    def save(self, report):
        raise OSError("disk full")


async def test_store_failure_still_finishes_run_and_closes_subscribers(tmp_path: Path):
    llm = FakeLLM([judge_ok(["add", "get_time"]), FakeReply(tool_calls=[tc("finish", {"summary": "a"})])])
    run = AuditRun(Report(url=CLEAN_URL))
    got = []

    async def consume():
        async for ev in run.subscribe():
            got.append(ev["event"])

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)
    report = await run_audit(run, bearer_token=None, llm=llm, connector=CONNECTOR, store=BrokenStore(tmp_path))
    await asyncio.wait_for(task, 2)
    assert run.done and got[-1] == "done" and "error" in got
    assert report.grade == "A"


# --- replay and LLM-off mode ---
def test_store_latest_for_url_returns_newest_completed(tmp_path: Path):
    from datetime import datetime, timezone, timedelta
    s = Store(tmp_path)
    old = Report(url="u", grade="A", score=100, finished_at=datetime.now(timezone.utc) - timedelta(hours=2))
    new = Report(url="u", grade="F", score=0, finished_at=datetime.now(timezone.utc))
    unfinished = Report(url="u")  # no finished_at
    other = Report(url="v", grade="B", score=80, finished_at=datetime.now(timezone.utc))
    for r in (old, new, unfinished, other):
        s.save(r)
    assert s.latest_for_url("u").audit_id == new.audit_id
    assert s.latest_for_url("missing") is None


async def test_llm_off_mode_runs_static_and_deterministic_probe(tmp_path: Path):
    run = AuditRun(Report(url=EVIL_URL))
    report = await run_audit(run, bearer_token=None, llm=None, connector=CONNECTOR, store=Store(tmp_path))
    assert report.grade == "F"
    assert report.model == "none (LLM disabled)"
    assert "LLM disabled" in report.phase("analyze").detail
    assert report.phase("probe").status == "completed"
    called = [c.tool for c in report.probe_calls]
    assert "exec_shell" not in called  # gate still applies
    assert {"read_notes", "get_config"} <= set(called)
    cats = {f.category for f in report.findings}
    assert {"response_injection", "secret_leak", "tool_poisoning"} <= cats  # rug pull still detected
    assert report.llm_usage == {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}


def test_store_attaches_references_to_old_reports_on_read(tmp_path: Path):
    from app.models import Finding
    s = Store(tmp_path)
    r = Report(url="u", finished_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    r.findings = [Finding(category="secret_leak", severity="high", title="t", detail="d", location="response:x", phase="probe", source="prober")]
    s.save(r)  # saved without references, like reports from before the mapping existed
    assert s.load(r.audit_id).findings[0].references
    assert s.latest_for_url("u").findings[0].references


async def test_persisted_report_has_report_phase_completed(tmp_path: Path):
    llm = FakeLLM([judge_ok(["add", "get_time"]), FakeReply(tool_calls=[tc("finish", {"summary": "a"})])])
    store = Store(tmp_path)
    report = await run_audit(AuditRun(Report(url=CLEAN_URL)), bearer_token=None, llm=llm, connector=CONNECTOR, store=store)
    saved = store.load(report.audit_id)
    assert saved.phase("report").status == "completed"
    assert saved.phase("report").detail.startswith("Grade A")


def test_store_marks_report_phase_completed_for_finished_legacy_reports(tmp_path: Path):
    import datetime as dt
    s = Store(tmp_path)
    r = Report(url="u", finished_at=dt.datetime.now(dt.timezone.utc))
    r.phase("report").status = "running"  # how reports were saved before the ordering fix
    s.save(r)
    assert s.load(r.audit_id).phase("report").status == "completed"
