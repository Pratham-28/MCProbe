"""OpenAI-compatible chat client against the hackathon LiteLLM endpoint, traced by neatlogs."""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Any

from dotenv import load_dotenv
from openai import AsyncOpenAI

load_dotenv()
log = logging.getLogger("airlock.llm")

DEFAULT_BASE_URL = "https://litellm.vision.aivar.app/v1"
DEFAULT_MODEL = "claude-sonnet-4.6"

_neatlogs_on = False


class LLM:
    def __init__(self, model: str, client: Any):
        self.model = model
        self.client = client
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}

    async def chat(self, messages: list[dict], *, tools: list[dict] | None = None,
                   tool_choice: str | dict | None = None, json_mode: bool = False,
                   max_tokens: int = 2000):
        kwargs: dict[str, Any] = {"model": self.model, "messages": messages, "max_tokens": max_tokens}
        if tools:
            kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = await self.client.chat.completions.create(**kwargs)
        self.usage["calls"] += 1
        usage = getattr(resp, "usage", None)
        if usage is not None:
            self.usage["prompt_tokens"] += getattr(usage, "prompt_tokens", 0) or 0
            self.usage["completion_tokens"] += getattr(usage, "completion_tokens", 0) or 0
        return resp.choices[0].message


def build_llm() -> LLM:
    global _neatlogs_on
    key = os.environ.get("LITELLM_API_KEY")
    if not key:
        raise RuntimeError("LITELLM_API_KEY is not set; copy .env.example to .env and fill it in")
    base_url = os.environ.get("LITELLM_BASE_URL", DEFAULT_BASE_URL)
    model = os.environ.get("AIRLOCK_MODEL", DEFAULT_MODEL)
    client: Any = AsyncOpenAI(api_key=key, base_url=base_url)

    nl_key = os.environ.get("NEATLOGS_API_KEY")
    if nl_key:
        import neatlogs
        neatlogs.init(api_key=nl_key, workflow_name="airlock")
        client = neatlogs.wrap(client, app="airlock", model=model)
        _neatlogs_on = True
        log.info("neatlogs tracing enabled")
    else:
        log.warning("NEATLOGS_API_KEY not set; running untraced")
    return LLM(model=model, client=client)


@contextlib.contextmanager
def audit_context(audit_id: str):
    """Bind the audit id as the neatlogs session so every LLM call in a run is grouped."""
    if not _neatlogs_on:
        yield
        return
    import neatlogs
    with neatlogs.identify(session_id=audit_id):
        yield


def flush_traces() -> None:
    if _neatlogs_on:
        import neatlogs
        neatlogs.flush()
