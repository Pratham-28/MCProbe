import pytest

from app.mcp_client import ConnectionFailed, make_inproc_connector, open_connection, open_inproc
from fixtures.clean_server import server as clean
from fixtures.evil_server import server as evil


async def test_inventory_from_inproc_server():
    async with open_inproc(clean) as conn:
        inv = await conn.inventory()
        assert inv.server_name == "clean-demo"
        assert inv.transport == "inproc"
        assert sorted(t.name for t in inv.tools) == ["add", "get_time"]
        add = next(t for t in inv.tools if t.name == "add")
        assert add.annotations == {"title": None, "read_only_hint": True, "destructive_hint": False,
                                   "idempotent_hint": None, "open_world_hint": False}
        assert add.tokens > 0 and inv.total_tokens >= sum(t.tokens for t in inv.tools)
        assert inv.prompts == [] and inv.resources == []


async def test_call_tool_ok_and_error():
    async with open_inproc(clean) as conn:
        ok, text = await conn.call_tool("add", {"a": 1, "b": 2})
        assert ok and text == "3"
        ok, text = await conn.call_tool("add", {"a": "zz"})
        assert not ok and "validation" in text.lower()
        ok, text = await conn.call_tool("nope", {})
        assert not ok and "unknown tool" in text.lower()


async def test_tool_fingerprints_change_after_rug_pull():
    async with open_inproc(evil) as conn:
        before = await conn.tool_fingerprints()
        await conn.call_tool("get_config", {})
        after = await conn.tool_fingerprints()
        assert before["search_docs"] != after["search_docs"]
        assert before["read_notes"] == after["read_notes"]


async def test_inproc_connector_routes_by_url():
    connector = make_inproc_connector({"http://localhost:8101/mcp": clean})
    async with connector("http://localhost:8101/mcp", None) as conn:
        assert (await conn.inventory()).server_name == "clean-demo"
    with pytest.raises(ConnectionFailed):
        async with connector("http://localhost:9/mcp", None):
            pass


async def test_open_connection_bad_url_raises_connection_failed():
    with pytest.raises(ConnectionFailed) as e:
        async with open_connection("http://127.0.0.1:1/mcp"):
            pass
    assert "127.0.0.1" in str(e.value) or "connect" in str(e.value).lower()
