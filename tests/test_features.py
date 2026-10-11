"""Badge endpoint and compare-with-previous."""
import datetime as dt
import json

import httpx

from app.compare import compare_reports
from app.main import create_app
from app.mcp_client import make_inproc_connector
from app.models import Inventory, Report, ToolInfo, now
from app.store import Store
from fixtures.clean_server import server as clean

CLEAN_URL = "http://127.0.0.1:8101/mcp"


def report(url, grade, score, tools, minutes_ago, audit_id=None):
    r = Report(url=url, grade=grade, score=score, finished_at=now() - dt.timedelta(minutes=minutes_ago))
    if audit_id:
        r.audit_id = audit_id
    r.inventory = Inventory(server_name="s", tools=[ToolInfo(name=n, description=d) for n, d in tools])
    return r


def test_compare_reports_diffs_tools_and_grade():
    prev = report("u", "A", 100, [("a", "one"), ("b", "two")], 60)
    cur = report("u", "C", 70, [("a", "one changed"), ("c", "three")], 1)
    out = compare_reports(prev, cur)
    assert out["grade_change"] == {"from": "A", "to": "C", "score_delta": -30}
    assert out["tools"]["added"] == ["c"] and out["tools"]["removed"] == ["b"]
    assert [c["name"] for c in out["tools"]["changed"]] == ["a"]
    assert out["tools"]["changed"][0]["fields"]["description"] == {"before": "one", "after": "one changed"}


def test_store_previous_for_url_skips_itself_and_newer(tmp_path):
    s = Store(tmp_path)
    old = report("u", "A", 100, [], 120, "old000000001")
    mid = report("u", "B", 80, [], 60, "mid000000001")
    cur = report("u", "C", 70, [], 1, "cur000000001")
    other = report("v", "A", 100, [], 30)
    for r in (old, mid, cur, other):
        s.save(r)
    assert s.previous_for(cur).audit_id == "mid000000001"
    assert s.previous_for(mid).audit_id == "old000000001"
    assert s.previous_for(old) is None


async def test_badge_and_compare_endpoints(tmp_path):
    s = Store(tmp_path)
    prev = report(CLEAN_URL, "A", 100, [("add", "x")], 60, "prev00000001")
    cur = report(CLEAN_URL, "B", 83, [("add", "y"), ("get_time", "t")], 1, "cur000000001")
    s.save(prev); s.save(cur)
    app = create_app(connector=make_inproc_connector({CLEAN_URL: clean}), store=s)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    r = await c.get("/badge/cur000000001.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
    assert "MCProbe" in r.text and "B 83" in r.text
    assert (await c.get("/badge/nope.svg")).status_code == 404
    unk = report(CLEAN_URL, "?", 0, [], 1, "unk000000001"); unk.status = "unscannable"; s.save(unk)
    assert "?" in (await c.get("/badge/unk000000001.svg")).text
    r = await c.get("/audits/cur000000001/compare")
    body = r.json()
    assert body["previous"]["audit_id"] == "prev00000001"
    assert body["grade_change"]["from"] == "A" and body["tools"]["added"] == ["get_time"]
    assert (await c.get("/audits/prev00000001/compare")).json()["previous"] is None
