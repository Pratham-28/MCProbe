import asyncio
import json

import httpx
import pytest

from app.main import create_app
from app.mcp_client import make_inproc_connector
from app.store import Store
from fixtures.clean_server import server as clean
from tests.fakes import FakeLLM, FakeReply, tc

CLEAN_URL = "http://127.0.0.1:8101/mcp"


def judge_ok():
    return FakeReply(content=json.dumps({"tools": [], "instructions": {"risk": "none", "reasons": []}}))


@pytest.fixture
def client(tmp_path):
    llm = FakeLLM([judge_ok(), FakeReply(tool_calls=[tc("finish", {"summary": "ok"})])])
    app = create_app(llm=llm, connector=make_inproc_connector({CLEAN_URL: clean}), store=Store(tmp_path))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test"), app


async def wait_done(app, audit_id):
    for _ in range(200):
        if app.state.runs[audit_id].done:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("audit did not finish")


async def test_index_and_targets(client):
    c, _ = client
    r = await c.get("/"); assert r.status_code == 200 and "Airlock" in r.text
    r = await c.get("/targets"); assert r.status_code == 200 and r.json()[0]["id"] == "fixture-clean"


async def test_create_audit_and_fetch_report(client):
    c, app = client
    r = await c.post("/audits", json={"url": CLEAN_URL, "label": "clean"})
    assert r.status_code == 202
    audit_id = r.json()["audit_id"]
    await wait_done(app, audit_id)
    r = await c.get(f"/audits/{audit_id}")
    body = r.json()
    assert body["grade"] == "A" and body["target_label"] == "clean"
    r = await c.get("/audits")
    assert r.json()[0]["audit_id"] == audit_id
    assert (await c.get("/audits/nope")).status_code == 404


async def test_events_stream_ends_with_done(client):
    c, app = client
    audit_id = (await c.post("/audits", json={"url": CLEAN_URL})).json()["audit_id"]
    events = []
    async with c.stream("GET", f"/audits/{audit_id}/events") as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        async for line in resp.aiter_lines():
            if line.startswith("event:"):
                events.append(line.split(":", 1)[1].strip())
            if events and events[-1] == "done":
                break
    assert events[0] == "phase" and events[-1] == "done"


async def test_bearer_token_never_appears_in_report_or_events(client):
    c, app = client
    audit_id = (await c.post("/audits", json={"url": CLEAN_URL, "bearer_token": "SECRET-TOKEN-123"})).json()["audit_id"]
    await wait_done(app, audit_id)
    blob = json.dumps(app.state.runs[audit_id].events) + (await c.get(f"/audits/{audit_id}")).text
    assert "SECRET-TOKEN-123" not in blob
    assert (await c.get(f"/audits/{audit_id}")).json()["inventory"]["authenticated"] is True


async def test_bad_url_is_rejected(client):
    c, _ = client
    assert (await c.post("/audits", json={"url": "not a url"})).status_code == 422
