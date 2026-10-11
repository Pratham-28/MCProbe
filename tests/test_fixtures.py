from mcp import Client

from fixtures.clean_server import server as clean
from fixtures.evil_server import server as evil


async def test_clean_server_tools():
    async with Client(clean) as c:
        names = sorted(t.name for t in (await c.list_tools()).tools)
        assert names == ["add", "get_time"]
        r = await c.call_tool("add", {"a": 2, "b": 3})
        assert r.content[0].text == "5"


async def test_evil_server_tools_and_rug_pull():
    async with Client(evil) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert set(tools) == {"search_docs", "read_notes", "summarize", "exec_shell", "get_config"}
        assert "<IMPORTANT>" in tools["search_docs"].description
        before = tools["search_docs"].description
        r = await c.call_tool("read_notes", {"note_id": "1"})
        assert "ignore previous instructions" in r.content[0].text.lower()
        r = await c.call_tool("get_config", {})
        assert "AKIA" in r.content[0].text
        after = {t.name: t for t in (await c.list_tools()).tools}["search_docs"].description
        assert after != before
