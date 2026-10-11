# Airlock — neatHack build log

## Project
Airlock: paste an MCP server URL, get a graded security report. An agent connects,
inventories tools/prompts/resources, runs static + LLM analysis, safely probes tools
behind a code gate, detects rug pulls, and scores the server A–F.

## Team
SRP — Prathamesh Yeole (lead); teammates: pending

## Stack
Python 3.13 + uv, FastAPI + sse-starlette, `mcp` 2.3 client (Streamable HTTP with SSE
fallback), LiteLLM endpoint (`claude-sonnet-4.6` by default), neatlogs SDK, tiktoken,
Tailwind CDN + vanilla JS. Repo: pending (public GitHub repo to be created).

## How neatlogs, Entire, cfo.ai are used
- **neatlogs**: `neatlogs.wrap(AsyncOpenAI())` traces every judge and prober LLM call;
  `neatlogs.identify(session_id=<audit_id>)` groups one audit into one session so a
  trace can be compared run-to-run. Trace links: pending (needs `NEATLOGS_API_KEY`).
- **Entire**: to be enabled on the repo with `entire enable --agent claude-code`;
  checkpoint link + ID: pending.
- **cfo.ai**: business plan (pricing, costs, revenue, runway): pending.

## Build log
### 2026-10-11
Planned: design spec, implementation plan, then iteration one: scaffold, scoring,
static checks, fixture servers, MCP client, LLM client + test fake, judge, prober,
orchestrator + store, API + SSE, UI, hackathon wiring.
Done: all code tasks (1–11). Spec: `docs/superpowers/specs/2026-10-11-airlock-mcp-audit-design.md`.
Plan: `docs/superpowers/plans/2026-10-11-airlock-iteration-one.md`.
Tests that ran: `uv run pytest -q` → 53 passed.
Manual verification (fake LLM, real fixture servers over HTTP): evil fixture → F (3/100,
6 findings incl. rug pull critical), clean fixture → A (100), DeepWiki → A (100).
Screenshot: `docs/evil-report-fake-llm.png`.
Failures remaining / blocked: live LLM run, neatlogs doctor, Entire checkpoint, and the
before/after trace pair are blocked on API keys and the public repo.

## Evidence
- Before/after: pending. Plan: audit the evil fixture with the first live build, record
  trace link + `llm_usage.prompt_tokens` + findings count; make one measurable change
  (e.g. judge input truncation or response-check coverage), re-run, record again.
- Failure + recovery: the prober asks for `exec_shell`, the code gate refuses it, and the
  model continues with `read_notes` and `get_config` (visible in the Probe Log and in the
  trace). Also observed: `read_wiki_structure` called with empty args fails on DeepWiki
  and the run continues. Trace link: pending.
- Doctor (`python -m neatlogs doctor --probe`): pending.

## Demo
1. Evil fixture → F with tool poisoning, response injection, secret leak, context bloat,
   unannotated shell tool, rug pull.
2. Clean fixture → A.
3. A real public server (DeepWiki / Hugging Face) → real-world context cost and findings.
Reproduce: see README "Run".

## Known limitations and next steps
See spec section 15: hidden Unicode detection, tool-shadowing list, per-tool judge
batching, prompt/resource content retrieval, deeper schema analysis, OAuth, stdio/local
servers and skill folders, report sharing, EC2 deployment, threshold tuning.

## Submission
Repo: pending · Demo video: pending · Checkpoint: pending · Business plan: pending
