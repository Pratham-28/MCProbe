import asyncio

import httpx

from app.flags import GitHubVariableFlag, parse_on_off


def test_parse_on_off():
    assert parse_on_off("on") is True and parse_on_off("ON ") is True and parse_on_off("true") is True and parse_on_off("1") is True
    assert parse_on_off("off") is False and parse_on_off("false") is False and parse_on_off("0") is False
    assert parse_on_off("maybe") is None and parse_on_off("") is None and parse_on_off(None) is None


def make_flag(handler, **kw):
    transport = httpx.MockTransport(handler)
    return GitHubVariableFlag(repo="me/mcprobe", token="t", name="MCPROBE_LLM",
                              client=httpx.AsyncClient(transport=transport), **kw)


async def test_fetch_reads_repository_variable():
    seen = {}

    def handler(req):
        seen["url"] = str(req.url); seen["auth"] = req.headers.get("authorization")
        return httpx.Response(200, json={"name": "MCPROBE_LLM", "value": "off"})

    flag = make_flag(handler)
    assert await flag.fetch() is False
    assert seen["url"] == "https://api.github.com/repos/me/mcprobe/actions/variables/MCPROBE_LLM"
    assert seen["auth"] == "Bearer t"


async def test_fetch_returns_none_on_error_or_bad_value():
    assert await make_flag(lambda r: httpx.Response(404)).fetch() is None
    assert await make_flag(lambda r: httpx.Response(200, json={"value": "banana"})).fetch() is None

    def boom(r):
        raise httpx.ConnectError("down")
    assert await make_flag(boom).fetch() is None


async def test_poll_loop_applies_value_and_keeps_last_known_on_failure():
    values = iter(["off", "on", None])
    def handler(r):
        v = next(values)
        return httpx.Response(200, json={"value": v}) if v else httpx.Response(500)

    applied = []
    flag = make_flag(handler, interval=0.01)
    task = asyncio.create_task(flag.run(applied.append))
    await asyncio.sleep(0.2)
    task.cancel()
    assert applied[:2] == [False, True] and all(x in (True, False) for x in applied)
    assert flag.last_value is True and flag.last_error is not None
