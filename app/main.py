"""FastAPI entry point: JSON API, SSE progress stream, static UI."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import os

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from sse_starlette.sse import EventSourceResponse

from app.mcp_client import Connector, open_connection
from app.models import Report
from app.orchestrator import AuditRun, run_audit
from app.store import Store
from app.targets import TARGETS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
STATIC = Path(__file__).resolve().parent.parent / "static"


class AuditRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    label: str | None = None
    bearer_token: str | None = None
    force: bool = False  # skip replay of an existing report for the same URL

    @field_validator("url")
    @classmethod
    def must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")) or " " in v:
            raise ValueError("url must start with http:// or https://")
        return v


def create_app(*, llm=None, connector: Connector | None = None, store: Store | None = None) -> FastAPI:
    app = FastAPI(title="Airlock", version="0.1.0")
    app.state.runs = {}
    app.state.tasks = set()
    app.state.store = store or Store()
    app.state.connector = connector or open_connection
    app.state.llm = llm

    def llm_disabled() -> bool:
        return os.environ.get("AIRLOCK_LLM", "").lower() in ("off", "0", "false", "none")

    def get_llm():
        if llm_disabled():
            return None
        if app.state.llm is None:
            from app.llm import build_llm
            app.state.llm = build_llm()
        return app.state.llm

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/whitepaper")
    async def whitepaper():
        return FileResponse(STATIC / "whitepaper.html")

    @app.get("/targets")
    async def targets():
        return TARGETS

    @app.post("/audits", status_code=202)
    async def create_audit(req: AuditRequest, response: Response):
        if not req.force:
            existing = app.state.store.latest_for_url(req.url)
            if existing is not None:
                response.status_code = 200
                return {"audit_id": existing.audit_id, "replayed": True}
        try:
            llm = get_llm()
        except RuntimeError as e:
            raise HTTPException(500, str(e))
        label = req.label or next((t["label"] for t in TARGETS if t["url"] == req.url), None)
        run = AuditRun(Report(url=req.url, target_label=label))
        app.state.runs[run.report.audit_id] = run
        task = asyncio.create_task(run_audit(run, bearer_token=req.bearer_token, llm=llm,
                                             connector=app.state.connector, store=app.state.store))
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return {"audit_id": run.report.audit_id}

    @app.get("/audits")
    async def list_audits():
        return app.state.store.list_summaries()

    @app.get("/audits/{audit_id}")
    async def get_audit(audit_id: str):
        run = app.state.runs.get(audit_id)
        if run is not None:
            return JSONResponse(run.report.model_dump(mode="json"))
        report = app.state.store.load(audit_id)
        if report is None:
            raise HTTPException(404, "audit not found")
        return JSONResponse(report.model_dump(mode="json"))

    @app.get("/audits/{audit_id}/events")
    async def events(audit_id: str):
        run = app.state.runs.get(audit_id)
        if run is None:
            report = app.state.store.load(audit_id)
            if report is None:
                raise HTTPException(404, "audit not found")

            async def replay():
                yield {"event": "done", "data": report.model_dump_json()}
            return EventSourceResponse(replay())

        async def gen():
            async for ev in run.subscribe():
                yield {"event": ev["event"], "data": json.dumps(ev["data"])}
        return EventSourceResponse(gen())

    return app


app = create_app()
