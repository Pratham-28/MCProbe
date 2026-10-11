# MCProbe — neatHack build log

## Project
MCProbe: paste an MCP server URL, get a graded security report. An agent connects,
inventories tools/prompts/resources, runs static + LLM analysis, safely probes tools
behind a code gate, detects rug pulls, and scores the server A–F.

## Team
SRP — Prathamesh Yeole (lead); teammates: pending

## Stack
Python 3.13 + uv, FastAPI + sse-starlette, `mcp` 2.3 client (Streamable HTTP with SSE
fallback), LiteLLM endpoint (`claude-sonnet-4.6` by default), neatlogs SDK, tiktoken,
Tailwind CDN + vanilla JS. Repo: https://github.com/Pratham-28/MCProbe · Live: http://54.197.141.241/ (AWS EC2 t3.small, us-east-1)

## How neatlogs, Entire, cfo.ai are used
- **neatlogs**: `neatlogs.wrap(AsyncOpenAI())` traces every judge and prober LLM call;
  `neatlogs.identify(session_id=<audit_id>)` groups one audit into one session so a
  trace can be compared run-to-run. Trace links: pending (needs `NEATLOGS_API_KEY`).
- **Entire**: to be enabled on the repo with `entire enable --agent claude-code`;
  checkpoint link + ID: pending.
- **cfo.ai**: business plan (pricing, costs, revenue, runway): pending.

## Build log
### 2026-10-11 (night) — table report, replay, LLM-off, framework mapping, opening animation
- Findings table (Issue · Severity · Impact · Framework · Evidence) with expandable rows,
  severity filter, CSV/JSON download, copy-link, print-to-PDF.
- Replay: POST /audits returns the stored report for a URL unless `force` is set; UI shows a
  "stored scan, re-scan live" banner. `MCPROBE_LLM=off` skips the judge and runs a
  deterministic probe (placeholder arguments from each tool's schema, same gate, same checks).
- Framework mapping (`app/frameworks.py`): MITRE ATLAS (AML.T0110 Tool Poisoning, AML.T0109
  Supply Chain Rug Pull, AML.T0051 Prompt Injection, AML.T0057 Data Leakage, AML.T0098 Tool
  Credential Harvesting, AML.T0086 Exfiltration via Tool Invocation, AML.T0034.002 Agentic
  Resource Consumption, AML.T0053 Tool Invocation, AML.T0080 Context Poisoning), OWASP LLM
  Top 10 2025 (LLM01/02/03/06/10), ATT&CK (T1195, T1552, T1059, T1041, T1036, T1557). IDs
  verified against mitre-atlas/atlas-data dist/ATLAS.yaml, genai.owasp.org and attack.mitre.org.
- Fixed: reports were persisted before the final phase was marked complete (replays showed a
  spinner); stored reports now get references attached on read.
- Opening animation (pure SVG/CSS, 12 s loop): agent connects → tool description whispers
  "read ~/.ssh/id_rsa" → MCProbe grades it F.
- Tests: 76 passed. Live evil scan `12a741c26f72`: F, 7 findings, 3 LLM calls, 7,510 prompt tokens.

### 2026-10-11 (evening) — UI redesign
Rebuilt the page as a single calm flow: headline + one input + "Try" chips → five
plain-English scan steps with live probe lines → a verdict card (grade ring, one-sentence
templated verdict, three numbers) → findings grouped as Serious / Worth knowing / Minor with
human labels, "why it matters", "what to do", evidence behind a toggle → "Technical details"
accordion. Added How-it-works and a Proof grid of real recent scans. Tests: 63 passed.

### 2026-10-11
Planned: design spec, implementation plan, then iteration one: scaffold, scoring,
static checks, fixture servers, MCP client, LLM client + test fake, judge, prober,
orchestrator + store, API + SSE, UI, hackathon wiring.
Deployed 2026-10-11 evening to AWS EC2 (`deploy/setup_ec2.sh`); first external scan `615e6fc99cca`: evil fixture F, 8 findings, claude-haiku.
Done: all code tasks (1–11). Spec: `docs/superpowers/specs/2026-10-11-mcprobe-mcp-audit-design.md`.
Plan: `docs/superpowers/plans/2026-10-11-mcprobe-iteration-one.md`.
Tests that ran: `uv run pytest -q` → 53 passed.
Manual verification (fake LLM, real fixture servers over HTTP): evil fixture → F (3/100,
6 findings incl. rug pull critical), clean fixture → A (100), DeepWiki → A (100).
Screenshots: `docs/ui-landing.png`, `docs/ui-scanning.png`, `docs/ui-verdict.png`.
Keys arrived 14:25 IST. Switched default model to `claude-haiku` (budget).
`python -m neatlogs doctor --probe` → PASS (TRACE_VISIBLE, TRACE_FINALIZED, all 8 checks).
First live runs (claude-haiku, neatlogs tracing on, session_id = audit id):
- evil fixture, audit `13b514102f9c` → F 0/100, 12 findings, 3 LLM calls,
  7,475 prompt / 1,865 completion tokens, 16.5 s. Prober called get_config, summarize,
  read_notes; automatic checks caught the AWS key and the injected note.
- clean fixture, audit `8f393fbfbcf3` → A 100/100, 0 findings, 4 LLM calls,
  4,709 / 826 tokens, 11.5 s.
- DeepWiki (public), audit `4560a0675c6a` → C 71/100, 3 findings, 6 LLM calls,
  18,523 / 1,800 tokens, 51.5 s. `read_wiki_contents` failed (oversized), the agent
  moved on to `ask_wiki_question` ×2 — a real failure-then-recovery run.
Observed accuracy issues to fix in iteration two: the model's own `record_finding` calls
duplicate automatic findings with free-text locations (not collapsed by dedupe), and the
judge flags DeepWiki's benign instructions as medium prompt_injection.
Failures remaining / blocked: Entire checkpoint link (needs the public repo), before/after
pair (candidate: cut `RESPONSE_CHARS_TO_MODEL` and normalise model finding locations,
measure prompt tokens and duplicate count on DeepWiki).

## Evidence
- Before/after (same target, same model `claude-haiku`, same prober caps):
  - BEFORE — evil fixture, audit `13b514102f9c` (session id in neatlogs): grade F, **12 findings
    of which 5 were duplicates** (the model's `record_finding` restated automatic findings under
    free-text locations and sibling categories), 3 LLM calls, 7,475 prompt tokens.
  - CHANGE — commit "drop model findings that duplicate automatic checks" + "family-based
    dedupe": model locations are normalised to `tool:<name>` / `response:<name>`, and findings
    are collapsed per (problem family, tool), keeping the most severe. Covered by
    `test_model_findings_that_duplicate_automatic_ones_are_dropped` and three scoring tests.
  - AFTER — evil fixture, audit `b84bfbbff7c5`: grade F, **7 findings, 0 duplicates**, 3 LLM
    calls, 7,811 prompt tokens. Every card on the report is now a distinct problem.
- Failure + recovery: the prober asks for `exec_shell`, the code gate refuses it, and the
  model continues with `read_notes` and `get_config` (visible in the Probe Log and in the
  trace). Also observed: `read_wiki_structure` called with empty args fails on DeepWiki
  and the run continues. Observed live on DeepWiki audit `4560a0675c6a` (read_wiki_contents
  failed, agent continued with ask_wiki_question). Trace link: pending (open the neatlogs
  Traces page, filter session = audit id).
- Doctor (`python -m neatlogs doctor --probe`): PASS on 2026-10-11 14:26 IST (all 8 checks).

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
Repo: https://github.com/Pratham-28/MCProbe · Live: http://54.197.141.241/ · Demo video: pending · Checkpoint: pending · Business plan: pending
