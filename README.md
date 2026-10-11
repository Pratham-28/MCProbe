# Airlock — MCP Security Assessment

Paste an MCP server URL; Airlock connects, inventories tools/prompts/resources,
runs static and LLM checks, safely probes tools, and grades the server.

## Run
    cp .env.example .env   # fill LITELLM_API_KEY and NEATLOGS_API_KEY
    uv sync --group dev
    uv run uvicorn app.main:app --reload --port 8000
    # in another terminal
    ./scripts/run_fixtures.sh
Open http://localhost:8000

## Test
    uv run pytest -q
