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
            if report.status == "unscannable":
                report.score, report.grade = 0, "?"
                from app.scoring import VERDICT_HEAD, verdict_sentence
                report.verdict = VERDICT_HEAD["?"] + " " + verdict_sentence("?", report.findings)
            report.llm_usage = _usage_delta(usage_before, getattr(llm, "usage", {}) or {})
            report.finished_at = now()
            t.set("completed", (f"Grade {report.grade}, score {report.score}, {len(report.findings)} findings"
                                if report.status == "scanned" else f"Not graded: {report.unscannable_reason}"))
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


def classify_failure(msg: str) -> str:
    """Map a connection/discovery error message onto an UnscannableReason."""
    m = msg or ""
    if m.lower().startswith("blocked") or "blocked:" in m.lower():
        return "blocked"
    if re.search(r"\b40[13]\b|Unauthorized|Forbidden", m):
        return "auth_required"
    if re.search(r"timed? ?out|TimeoutError|ReadTimeout|ConnectTimeout", m, re.I):
        return "timeout"
    if re.search(r"Connection refused|ConnectError|nodename nor servname|Name or service not known|"
                 r"getaddrinfo|No route to host|Network is unreachable|DNS", m, re.I):
        return "unreachable"
    return "not_mcp"


UNSCANNABLE_TEXT = {
    "auth_required": ("This server requires authentication",
                      "The server answered 401/403 to an anonymous client, so its tools could not be read or "
                      "tested. If it accepts an API key, add it with the token field and scan again. If it only "
                      "supports an OAuth login (Notion, GitHub and most SaaS servers do), MCProbe cannot assess "
                      "it yet; OAuth support is on the roadmap."),
    "timeout": ("The server did not answer in time",
                "No MCP handshake completed within the connection timeout. The server may be slow, asleep, or "
                "behind a firewall that drops connections."),
    "unreachable": ("The server could not be reached",
                    "DNS lookup or the TCP connection failed. Check the hostname, the port, and that the server "
                    "is running and reachable from the internet."),
    "not_mcp": ("This URL does not speak MCP",
                "The address answered, but not with an MCP handshake (it may be a web page, a docs site, or a "
                "repository URL). MCProbe needs the server's MCP endpoint, usually ending in /mcp or /sse."),
    "blocked": ("This address is not scannable from MCProbe",
                "The hostname resolves to a private, local or cloud-internal address. MCProbe only scans servers "
                "reachable on the public internet."),
}


def _mark_unscannable(run: AuditRun, reason: str, msg: str, phase: str, location: str) -> None:
    report = run.report
    report.status = "unscannable"
    report.unscannable_reason = reason  # type: ignore[assignment]
    title, detail = UNSCANNABLE_TEXT[reason]
    _add(run, [Finding(category="connectivity", severity="info", title=title, detail=detail,
                       location=location, evidence=msg[:500],
                       recommendation=("Add a bearer token and scan again." if reason == "auth_required"
                                       else "Fix the address and scan again."),
                       phase=phase, source="static")])  # type: ignore[arg-type]


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
        reason = classify_failure(msg)
        connect.set("failed", f"{UNSCANNABLE_TEXT[reason][0]} ({reason})")
        _mark_unscannable(run, reason, msg, "connect", "server.url")
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
            _mark_unscannable(run, classify_failure(msg) if classify_failure(msg) != "unreachable" else "not_mcp",
                              msg, "discover", "server.tools")
            return
        report.inventory = inv
        if not report.target_label:
            from urllib.parse import urlparse
            report.target_label = inv.server_name or (urlparse(report.url).hostname or report.url)
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
