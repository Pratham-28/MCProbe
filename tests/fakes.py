"""Scripted stand-in for app.llm.LLM used by judge, prober, and e2e tests."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace


def tc(name: str, arguments: dict, id: str | None = None):
    return SimpleNamespace(
        id=id or f"call_{name}_{abs(hash(json.dumps(arguments, sort_keys=True))) % 10000}",
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


@dataclass
class FakeReply:
    content: str | None = None
    tool_calls: list | None = None


@dataclass
class FakeLLM:
    script: list[FakeReply] = field(default_factory=list)
    model: str = "fake-model"
    usage: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0})
    calls: list[list[dict]] = field(default_factory=list)

    async def chat(self, messages, *, tools=None, tool_choice=None, json_mode=False, max_tokens=2000):
        self.calls.append(messages)
        self.usage["calls"] += 1
        self.usage["prompt_tokens"] += 10
        self.usage["completion_tokens"] += 5
        if self.script:
            return self.script.pop(0)
        return FakeReply(content="{}")
