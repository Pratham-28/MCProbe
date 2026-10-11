"""A well-behaved MCP server. Expected MCProbe grade: A."""
from datetime import datetime, timezone

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer(
    "clean-demo",
    version="1.0.0",
    instructions="Small utility server offering the current time and integer addition.",
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)


@server.tool(annotations=READ_ONLY)
def get_time() -> str:
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


@server.tool(annotations=READ_ONLY)
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


if __name__ == "__main__":
    server.run("streamable-http", host="127.0.0.1", port=8101)
