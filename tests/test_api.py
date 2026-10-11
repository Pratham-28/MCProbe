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
    r = await c.get("/"); assert r.status_code == 200 and "MCProbe" in r.text
    assert 'id="url-input"' in r.text and "EventSource" in r.text and "Technical details" in r.text
    assert 'id="findings-table"' in r.text and "dl-csv" in r.text and 'id="llm-toggle"' in r.text
    assert "What to do" in r.text and "Group by tool" in r.text and "/compare" in r.text and "/badge/" in r.text
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


async def test_replay_returns_existing_report_for_same_url(client):
    c, app = client
    first = (await c.post("/audits", json={"url": CLEAN_URL})).json()["audit_id"]
    await wait_done(app, first)
    r = await c.post("/audits", json={"url": CLEAN_URL})
    assert r.status_code == 200 and r.json() == {"audit_id": first, "replayed": True}
    r = await c.post("/audits", json={"url": CLEAN_URL, "force": True})
    assert r.status_code == 202 and r.json()["audit_id"] != first
    await wait_done(app, r.json()["audit_id"])


async def test_llm_off_env_runs_without_key(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPROBE_LLM", "off")
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    app = create_app(connector=make_inproc_connector({CLEAN_URL: clean}), store=Store(tmp_path))
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    r = await c.post("/audits", json={"url": CLEAN_URL})
    assert r.status_code == 202
    await wait_done(app, r.json()["audit_id"])
    body = (await c.get(f"/audits/{r.json()['audit_id']}")).json()
    assert body["grade"] == "A" and body["model"] == "none (LLM disabled)"


async def test_whitepaper_page(client):
    c, _ = client
    r = await c.get("/whitepaper")
    assert r.status_code == 200 and "Whitepaper" in r.text and "Implemented" in r.text
    home = (await c.get("/")).text
    assert 'href="/whitepaper"' in home and 'href="#proof"' not in home and ">GitHub</a>" not in home


async def test_settings_is_read_only_and_env_sets_default(tmp_path, monkeypatch):
    monkeypatch.setenv("MCPROBE_LLM", "off")
    app = create_app(connector=make_inproc_connector({CLEAN_URL: clean}), store=Store(tmp_path))
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    assert (await c.get("/settings")).json() == {"llm_enabled": False, "source": "env"}
    assert (await c.post("/settings", json={"llm_enabled": True})).status_code == 405
    assert (await c.get("/settings")).json()["llm_enabled"] is False


async def test_github_variable_flag_drives_llm_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("MCPROBE_LLM", raising=False)
    values = ["off", "off", "on"]

    def handler(req):
        return httpx.Response(200, json={"value": values.pop(0) if values else "on"})

    from app.flags import GitHubVariableFlag
    flag = GitHubVariableFlag(repo="me/mcprobe", token="t", interval=0.05,
                              client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    llm = FakeLLM([judge_ok(), FakeReply(tool_calls=[tc("finish", {"summary": "ok"})])])
    app = create_app(llm=llm, connector=make_inproc_connector({CLEAN_URL: clean}), store=Store(tmp_path), flag=flag)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    async with app.router.lifespan_context(app):
        await asyncio.sleep(0.02)
        assert (await c.get("/settings")).json() == {"llm_enabled": False, "source": "github:me/mcprobe"}
        audit_id = (await c.post("/audits", json={"url": CLEAN_URL, "force": True})).json()["audit_id"]
        await wait_done(app, audit_id)
        assert (await c.get(f"/audits/{audit_id}")).json()["model"] == "none (LLM disabled)"
        assert llm.usage["calls"] == 0
        for _ in range(40):
            if (await c.get("/settings")).json()["llm_enabled"]:
                break
            await asyncio.sleep(0.05)
        assert (await c.get("/settings")).json()["llm_enabled"] is True
        audit_id = (await c.post("/audits", json={"url": CLEAN_URL, "force": True})).json()["audit_id"]
        await wait_done(app, audit_id)
        assert (await c.get(f"/audits/{audit_id}")).json()["model"] == "fake-model"
