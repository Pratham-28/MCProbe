"""Runs the five phases, emits progress events, persists the report."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator

from app.judge import run_judge
from app.llm import audit_context, flush_traces
from app.mcp_client import ConnectionFailed, Connector, flatten_error
from app.models import Finding, Phase, Report, now
from app.prober import run_probe, run_probe_deterministic
from app.scoring import apply_scoring
from app.static_checks import run_static_checks
from app.store import Store

log = logging.getLogger("mcprobe.orchestrator")


class AuditRun:
    def __init__(self, report: Report):
        self.report = report
        self.events: list[dict] = []
        self.done = False
        self._queues: list[asyncio.Queue] = []

    def emit(self, event: str, data: dict) -> None:
        ev = {"event": event, "data": data}
        self.events.append(ev)
        for q in list(self._queues):
            q.put_nowait(ev)

    def close(self) -> None:
        for q in list(self._queues):
            q.put_nowait(None)

    async def subscribe(self) -> AsyncIterator[dict]:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.append(q)
        try:
            for ev in list(self.events):
                yield ev
            if self.done:
                return
            while True:
                ev = await q.get()
                if ev is None:
                    return
                yield ev
        finally:
            self._queues.remove(q)


class _PhaseTimer:
    def __init__(self, run: AuditRun, phase: Phase):
        self.run, self.phase, self.t0 = run, phase, time.perf_counter()
        self.status = run.report.phase(phase)
        self.set("running", "")

    def set(self, status: str, detail: str) -> None:
        self.status.status = status  # type: ignore[assignment]
        if detail:
            self.status.detail = detail
        self.status.seconds = round(time.perf_counter() - self.t0, 2)
        self.run.emit("phase", self.status.model_dump(mode="json"))


def _add(run: AuditRun, findings: list[Finding]) -> None:
    for fi in findings:
        run.report.findings.append(fi)
        run.emit("finding", fi.model_dump(mode="json"))


def _usage_delta(before: dict, after: dict) -> dict:
    return {k: int(after.get(k, 0)) - int(before.get(k, 0)) for k in ("prompt_tokens", "completion_tokens", "calls")}


async def run_audit(run: AuditRun, *, bearer_token: str | None, llm, connector: Connector, store: Store) -> Report:
    report = run.report
    report.model = getattr(llm, "model", "") if llm is not None else "none (LLM disabled)"
    usage_before = dict(getattr(llm, "usage", {}) or {})
    with audit_context(report.audit_id):
        try:
            try:
                await _run_phases(run, bearer_token, llm, connector)
            except Exception as exc:  # last-resort guard: never leave a run hanging
                log.exception("audit %s crashed", report.audit_id)
                run.emit("error", {"message": flatten_error(exc)})
            t = _PhaseTimer(run, "report")
            apply_scoring(report)
            if report.phase("connect").status == "failed" or report.phase("discover").status == "failed":
                report.score, report.grade = 0, "F"  # spec §12: a server we could not assess grades F
            report.llm_usage = _usage_delta(usage_before, getattr(llm, "usage", {}) or {})
            report.finished_at = now()
            t.set("completed", f"Grade {report.grade}, score {report.score}, {len(report.findings)} findings")
            try:
                store.save(report)  # after the final phase is marked complete, so replays look finished
            except Exception as exc:
                log.exception("audit %s could not be persisted", report.audit_id)
                run.emit("error", {"message": f"Report not saved: {flatten_error(exc)}"})
        finally:
            run.emit("done", report.model_dump(mode="json"))
            run.done = True
            run.close()
            try:
                flush_traces()
            except Exception:
                log.exception("neatlogs flush failed")
    return report


def _skip_rest(run: AuditRun, phases: tuple[str, ...]) -> None:
    for p in phases:
        run.report.phase(p).status = "skipped"  # type: ignore[arg-type]
        run.emit("phase", run.report.phase(p).model_dump(mode="json"))


async def _run_phases(run: AuditRun, bearer_token: str | None, llm, connector: Connector) -> None:
    report = run.report
    connect = _PhaseTimer(run, "connect")
    try:
        cm = connector(report.url, bearer_token)
        conn = await cm.__aenter__()
    except Exception as exc:
        msg = str(exc) if isinstance(exc, ConnectionFailed) else flatten_error(exc)
        _skip_rest(run, ("discover", "analyze", "probe"))
        if re.search(r"\b40[13]\b|Unauthorized|Forbidden", msg):
            connect.set("failed", "Authentication required: the server answered 401/403 to an anonymous client")
            _add(run, [Finding(
                category="connectivity", severity="critical", title="This server requires authentication",
                detail="The server refused an anonymous connection, so its tools could not be read or tested. "
                       "If it accepts an API key, add it with the token field and scan again. If it only "
                       "supports an OAuth login (Notion, GitHub and most SaaS servers do), MCProbe cannot "
                       "assess it yet; OAuth support is on the roadmap.",
                location="server.url", evidence=msg[:500],
                recommendation="Supply a bearer token, or wait for OAuth support. A server you cannot read is "
                               "a server you cannot vet, so treat it as unverified.",
                phase="connect", source="static")])
        else:
            connect.set("failed", msg[:300])
            _add(run, [Finding(category="connectivity", severity="critical", title="Could not connect to the MCP server",
                               detail=msg[:1000], location="server.url", evidence=report.url,
                               recommendation="Check the URL, transport (Streamable HTTP or SSE), and any required token.",
                               phase="connect", source="static")])
        return
    try:
        connect.set("completed", f"Connected via {conn.transport}")

        discover = _PhaseTimer(run, "discover")
        try:
            inv = await conn.inventory()
        except Exception as exc:
            msg = flatten_error(exc)
            discover.set("failed", msg[:300])
            _skip_rest(run, ("analyze", "probe"))
            _add(run, [Finding(category="connectivity", severity="critical", title="Could not read the server's tool list",
                               detail=msg[:1000], location="server.tools", evidence=report.url,
                               recommendation="The server connected but its tools/list response could not be processed; "
                                              "check that it speaks a supported MCP protocol version.",
                               phase="discover", source="static")])
            return
        report.inventory = inv
        run.emit("log", {"phase": "discover", "message": f"Found {len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources"})
        discover.set("completed", f"{len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources, {inv.total_tokens} tokens")

        analyze = _PhaseTimer(run, "analyze")
        static: list[Finding] = []
        judge_note = ""
        try:
            static = run_static_checks(inv, report.url)
            _add(run, static)
            run.emit("log", {"phase": "analyze", "message": f"Static checks: {len(static)} findings"})
        except Exception as exc:
            judge_note = f"; static checks failed: {flatten_error(exc)[:120]}"
            run.emit("log", {"phase": "analyze", "message": f"Static checks failed: {flatten_error(exc)[:200]}"})
        try:
            if llm is None:
                judge_note += "; LLM disabled, judge skipped"
                run.emit("log", {"phase": "analyze", "message": "LLM disabled: judge skipped"})
            else:
                judged = await run_judge(llm, inv)
                _add(run, judged)
                run.emit("log", {"phase": "analyze", "message": f"LLM judge: {len(judged)} findings"})
        except Exception as exc:
            judge_note += f"; judge failed: {flatten_error(exc)[:120]}"
            run.emit("log", {"phase": "analyze", "message": f"LLM judge failed: {flatten_error(exc)[:200]}"})
        analyze.set("completed", f"{len(static)} static findings{judge_note}")

        probe = _PhaseTimer(run, "probe")
        try:
            if llm is None:
                run.emit("log", {"phase": "probe", "message": "LLM disabled: calling gate-approved tools with placeholder arguments"})
                pf, calls = await run_probe_deterministic(conn, inv, run.emit)
            else:
                pf, calls = await run_probe(llm, conn, inv, run.emit)
            report.probe_calls = calls
            report.findings.extend(pf)  # already emitted by the prober
            probe.set("completed", f"{len(calls)} tool calls, {len(pf)} findings")
        except Exception as exc:
            probe.set("failed", flatten_error(exc)[:300])
    finally:
        try:
            await cm.__aexit__(None, None, None)
        except Exception:
            pass
