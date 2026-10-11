# Airlock — MCP Security Assessment

Paste an MCP server URL; Airlock connects, inventories tools/prompts/resources,
runs static and LLM checks, safely probes tools behind a code gate, detects rug
pulls, and grades the server A–F. Built for neatHack 2026 (team SRP).

![Airlock landing](docs/ui-landing.png)

![Airlock verdict for the evil fixture](docs/ui-verdict.png)

## What you get
- A grade (A–F), a one-sentence verdict, and a findings table: Issue · Severity · Impact · Framework · Evidence.
- Every finding mapped to **MITRE ATLAS**, **OWASP LLM Top 10 (2025)** and **MITRE ATT&CK** where applicable.
- Download as JSON or CSV, copy a share link, print to PDF.
- Replays: scanning a URL that already has a report shows it instantly; "Re-scan live" forces a fresh run.
- `AIRLOCK_LLM=off` runs with no LLM at all: static checks plus a deterministic probe of gate-approved tools.

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
