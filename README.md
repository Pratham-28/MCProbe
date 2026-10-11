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

## Deploy (AWS EC2, hackathon allowance)
One `t3.small` in `us-east-1` inside `Hackathon_VPC`, Ubuntu 24.04, security group open on
TCP 80 (and 22 for you). Then on the instance:

    curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/deploy/setup_ec2.sh \
      | REPO_URL=https://github.com/<owner>/<repo>.git bash
    nano /opt/airlock/.env          # LITELLM_API_KEY, NEATLOGS_API_KEY, AIRLOCK_MODEL
    sudo systemctl restart airlock

Open `http://<public-ip>/`. Logs: `journalctl -u airlock -f`. The fixture servers run as a
second unit, `airlock-fixtures`.

### Switching AI analysis on and off while live (GitHub feature flag)
Deterministic checks always run. The LLM judge and the probing agent are controlled from
GitHub, not from the UI:

1. In the repo: Settings → Secrets and variables → Actions → Variables → **New repository
   variable**: name `AIRLOCK_LLM`, value `on` or `off`.
2. Create a fine-grained personal access token for that repo with **Variables: Read-only**
   (classic tokens: `repo` scope).
3. On the server, in `.env`:

       GITHUB_REPO=<owner>/<repo>
       GITHUB_FLAG_TOKEN=<token>
       # optional: GITHUB_FLAG_NAME=AIRLOCK_LLM  GITHUB_FLAG_INTERVAL=60

   then `sudo systemctl restart airlock` once.

The server polls the variable every 60 s; changing it in GitHub takes effect on the next
scan with no redeploy. The top-bar badge shows the current mode read-only. Without
`GITHUB_REPO`, the `AIRLOCK_LLM` env var is the default. Keep it `off` for the public link
and flip to `on` while presenting, so strangers cannot spend the shared LLM budget.

## Test
    uv run pytest -q

## Layout
- `app/` — FastAPI app, MCP client, static checks, LLM judge, prober agent loop, scoring, orchestrator
- `fixtures/` — clean and evil demo MCP servers
- `static/index.html` — the UI
- `docs/superpowers/` — design spec and implementation plan
- `hackathon.md` — build log and evidence
