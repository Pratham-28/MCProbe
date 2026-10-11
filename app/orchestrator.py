"""Runs the five phases, emits progress events, persists the report."""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator

from app.judge import run_judge
from app.llm import audit_context, flush_traces
from app.mcp_client import ConnectionFailed, Connector, flatten_error
from app.models import Finding, Phase, Report, now
from app.prober import run_probe
from app.scoring import apply_scoring
from app.static_checks import run_static_checks
from app.store import Store

log = logging.getLogger("airlock.orchestrator")


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


async def run_audit(run: AuditRun, *, bearer_token: str | None, llm, connector: Connector, store: Store) -> Report:
    report = run.report
    report.model = getattr(llm, "model", "")
    with audit_context(report.audit_id):
        try:
            await _run_phases(run, bearer_token, llm, connector)
        except Exception as exc:  # last-resort guard: never leave a run hanging
            log.exception("audit %s crashed", report.audit_id)
            run.emit("error", {"message": flatten_error(exc)})
        finally:
            t = _PhaseTimer(run, "report")
            apply_scoring(report)
            if report.phase("connect").status == "failed":
                report.score, report.grade = 0, "F"  # spec §12: unreachable server grades F
            report.llm_usage = dict(getattr(llm, "usage", {}))
            report.finished_at = now()
            store.save(report)
            t.set("completed", f"Grade {report.grade}, score {report.score}, {len(report.findings)} findings")
            run.emit("done", report.model_dump(mode="json"))
            run.done = True
            run.close()
            flush_traces()
    return report


async def _run_phases(run: AuditRun, bearer_token: str | None, llm, connector: Connector) -> None:
    report = run.report
    connect = _PhaseTimer(run, "connect")
    try:
        cm = connector(report.url, bearer_token)
        conn = await cm.__aenter__()
    except Exception as exc:
        msg = str(exc) if isinstance(exc, ConnectionFailed) else flatten_error(exc)
        connect.set("failed", msg[:300])
        for p in ("discover", "analyze", "probe"):
            report.phase(p).status = "skipped"
            run.emit("phase", report.phase(p).model_dump(mode="json"))
        _add(run, [Finding(category="connectivity", severity="critical", title="Could not connect to the MCP server",
                           detail=msg[:1000], location="server.url", evidence=report.url,
                           recommendation="Check the URL, transport (Streamable HTTP or SSE), and any required token.",
                           phase="connect", source="static")])
        return
    try:
        connect.set("completed", f"Connected via {conn.transport}")

        discover = _PhaseTimer(run, "discover")
        inv = await conn.inventory()
        report.inventory = inv
        run.emit("log", {"phase": "discover", "message": f"Found {len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources"})
        discover.set("completed", f"{len(inv.tools)} tools, {len(inv.prompts)} prompts, {len(inv.resources)} resources, {inv.total_tokens} tokens")

        analyze = _PhaseTimer(run, "analyze")
        static = run_static_checks(inv, report.url)
        _add(run, static)
        run.emit("log", {"phase": "analyze", "message": f"Static checks: {len(static)} findings"})
        judge_note = ""
        try:
            judged = await run_judge(llm, inv)
            _add(run, judged)
            run.emit("log", {"phase": "analyze", "message": f"LLM judge: {len(judged)} findings"})
        except Exception as exc:
            judge_note = f"; judge failed: {flatten_error(exc)[:120]}"
            run.emit("log", {"phase": "analyze", "message": f"LLM judge failed: {flatten_error(exc)[:200]}"})
        analyze.set("completed", f"{len(static)} static findings{judge_note}")

        probe = _PhaseTimer(run, "probe")
        try:
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
