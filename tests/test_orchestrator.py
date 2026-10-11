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
