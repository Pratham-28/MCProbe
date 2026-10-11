"""Connect to an MCP server, read its inventory, call tools."""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass

from mcp import Client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.shared._httpx_utils import create_mcp_http_client

from app.models import Inventory, ToolInfo
from app.tokens import count_tokens

CONNECT_TIMEOUT = 15.0


class ConnectionFailed(Exception):
    """Raised when neither transport could establish an MCP session."""


def flatten_error(exc: BaseException) -> str:
    """ExceptionGroups from anyio hide the real cause; dig it out."""
    subs = getattr(exc, "exceptions", None)
    if subs:
        return "; ".join(flatten_error(e) for e in subs)
    msg = str(exc).strip() or exc.__class__.__name__
    return f"{exc.__class__.__name__}: {msg}"


def _text_of(result) -> str:
    parts: list[str] = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else json.dumps(block.model_dump(mode="json"))[:500])
    if not parts and getattr(result, "structured_content", None) is not None:
        parts.append(json.dumps(result.structured_content))
    return "\n".join(parts)


@dataclass
class McpConnection:
    client: Client
    transport: str
    authenticated: bool = False

    async def inventory(self) -> Inventory:
        c = self.client
        tools: list[ToolInfo] = []
        for t in (await c.list_tools()).tools:
            ann = t.annotations.model_dump() if t.annotations is not None else None
            desc = t.description or ""
            ti = ToolInfo(name=t.name, description=desc, input_schema=t.input_schema or {}, annotations=ann)
            ti.tokens = count_tokens(t.name + "\n" + desc + "\n" + json.dumps(ti.input_schema))
            tools.append(ti)

        async def safe_list(fn, attr):
            try:
                return [x.model_dump(mode="json") for x in getattr(await fn(), attr)]
            except Exception:
                return []

        prompts = await safe_list(c.list_prompts, "prompts")
        resources = await safe_list(c.list_resources, "resources")
        info = c.server_info
        inv = Inventory(
            server_name=getattr(info, "name", None),
            server_version=getattr(info, "version", None) or None,
            protocol_version=c.protocol_version,
            instructions=c.instructions,
            transport=self.transport,  # type: ignore[arg-type]
            authenticated=self.authenticated,
            tools=tools, prompts=prompts, resources=resources,
        )
        inv.total_tokens = count_tokens(inv.instructions or "") + sum(t.tokens for t in tools)
        return inv

    async def call_tool(self, name: str, arguments: dict, timeout: float = 20.0) -> tuple[bool, str]:
        try:
            result = await asyncio.wait_for(self.client.call_tool(name, arguments), timeout)
        except asyncio.TimeoutError:
            return False, f"timeout after {timeout:.0f}s"
        except Exception as exc:  # protocol-level failure
            return False, flatten_error(exc)
        text = _text_of(result)
        return (not bool(getattr(result, "is_error", False))), text

    async def tool_fingerprints(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for t in (await self.client.list_tools()).tools:
            blob = json.dumps({"d": t.description, "s": t.input_schema}, sort_keys=True)
            out[t.name] = hashlib.sha256(blob.encode()).hexdigest()[:16]
        return out


@asynccontextmanager
async def open_inproc(server: MCPServer) -> AsyncIterator[McpConnection]:
    async with Client(server) as client:
        yield McpConnection(client=client, transport="inproc")


async def _close(cm) -> None:
    try:
        await cm.__aexit__(None, None, None)
    except Exception:
        pass


@asynccontextmanager
async def open_connection(url: str, bearer_token: str | None = None) -> AsyncIterator[McpConnection]:
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else None
    errors: list[str] = []

    try:
        http = create_mcp_http_client(headers=headers)
        async with asyncio.timeout(CONNECT_TIMEOUT):
            cm = Client(streamable_http_client(url, http_client=http))
            client = await cm.__aenter__()
    except BaseException as exc:
        errors.append(f"streamable_http: {flatten_error(exc)}")
    else:
        try:
            yield McpConnection(client=client, transport="streamable_http", authenticated=bool(bearer_token))
        finally:
            await _close(cm)
        return

    try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            cm = Client(sse_client(url, headers=headers, timeout=CONNECT_TIMEOUT))
            client = await cm.__aenter__()
    except BaseException as exc:
        errors.append(f"sse: {flatten_error(exc)}")
        raise ConnectionFailed("Could not establish an MCP session. " + " | ".join(errors)) from None
    try:
        yield McpConnection(client=client, transport="sse", authenticated=bool(bearer_token))
    finally:
        await _close(cm)


Connector = Callable[[str, str | None], AbstractAsyncContextManager[McpConnection]]


def make_inproc_connector(mapping: dict[str, MCPServer]) -> Connector:
    @asynccontextmanager
    async def connector(url: str, bearer_token: str | None) -> AsyncIterator[McpConnection]:
        if url not in mapping:
            raise ConnectionFailed(f"No in-process server registered for {url}")
        async with open_inproc(mapping[url]) as conn:
            conn.authenticated = bool(bearer_token)
            yield conn
    return connector
