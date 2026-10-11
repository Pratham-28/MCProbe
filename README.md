# Airlock — MCP Security Assessment

Paste an MCP server URL; Airlock connects, inventories tools/prompts/resources,
runs static and LLM checks, safely probes tools behind a code gate, detects rug
pulls, and grades the server A–F. Built for neatHack 2026 (team SRP).

![Evil fixture report](docs/evil-report-fake-llm.png)

## Run
    cp .env.example .env   # fill LITELLM_API_KEY and NEATLOGS_API_KEY
    uv sync --group dev
    ./scripts/run_fixtures.sh &          # clean (8101) and evil (8102) demo servers
    uv run uvicorn app.main:app --reload --port 8000
Open http://localhost:8000, pick a target, Start Assessment.

## Verify tracing
    uv run python -m neatlogs doctor --probe   # expect TRACE_VISIBLE and TRACE_FINALIZED PASS

## Test
    uv run pytest -q

## Layout
- `app/` — FastAPI app, MCP client, static checks, LLM judge, prober agent loop, scoring, orchestrator
- `fixtures/` — clean and evil demo MCP servers
- `static/index.html` — the UI
- `docs/superpowers/` — design spec and implementation plan
- `hackathon.md` — build log and evidence
