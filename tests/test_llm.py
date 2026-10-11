import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.llm import LLM, build_llm
from tests.fakes import FakeLLM, FakeReply, tc


async def test_llm_chat_accumulates_usage_and_returns_message():
    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock())))
    fake_client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="hi", tool_calls=None))],
        usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3),
    )
    llm = LLM(model="m", client=fake_client)
    msg = await llm.chat([{"role": "user", "content": "x"}], json_mode=True)
    assert msg.content == "hi"
    assert llm.usage == {"prompt_tokens": 7, "completion_tokens": 3, "calls": 1}
    kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert kwargs["model"] == "m" and kwargs["response_format"] == {"type": "json_object"}
    assert "tools" not in kwargs


async def test_llm_passes_tools_and_omits_response_format():
    fake_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=AsyncMock())))
    fake_client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[]))], usage=None)
    llm = LLM(model="m", client=fake_client)
    await llm.chat([], tools=[{"type": "function", "function": {"name": "f", "parameters": {}}}], tool_choice="auto")
    kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert kwargs["tools"][0]["function"]["name"] == "f" and kwargs["tool_choice"] == "auto"
    assert "response_format" not in kwargs
    assert llm.usage["calls"] == 1 and llm.usage["prompt_tokens"] == 0


def test_build_llm_requires_key(monkeypatch):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_llm()


def test_build_llm_without_neatlogs(monkeypatch):
    monkeypatch.setenv("LITELLM_API_KEY", "k")
    monkeypatch.delenv("NEATLOGS_API_KEY", raising=False)
    monkeypatch.setenv("AIRLOCK_MODEL", "claude-haiku")
    llm = build_llm()
    assert llm.model == "claude-haiku"


async def test_fake_llm_script():
    fake = FakeLLM([FakeReply(tool_calls=[tc("finish", {"summary": "s"})])])
    r = await fake.chat([])
    assert r.tool_calls[0].function.name == "finish"
    r = await fake.chat([])
    assert r.content == "{}" and fake.usage["calls"] == 2
