"""Pydantic models shared by every phase and by the API."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal[
    "prompt_injection", "tool_poisoning", "excessive_permissions",
    "context_bloat", "data_exfiltration", "response_injection",
    "secret_leak", "schema_quality", "tool_shadowing", "insecure_transport",
    "connectivity",
]
Phase = Literal["connect", "discover", "analyze", "probe", "report"]
PHASES: list[Phase] = ["connect", "discover", "analyze", "probe", "report"]
Grade = Literal["A", "B", "C", "D", "F"]
Source = Literal["static", "judge", "prober"]


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def now() -> datetime:
    return datetime.now(timezone.utc)


class Finding(BaseModel):
    id: str = Field(default_factory=new_id)
    category: Category
    severity: Severity
    title: str
    detail: str
    location: str
    evidence: str = ""
    recommendation: str = ""
    phase: Phase
    source: Source

    def model_post_init(self, __context: Any) -> None:
        if len(self.evidence) > 500:
            self.evidence = self.evidence[:497] + "..."


class ToolInfo(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None
    tokens: int = 0


class Inventory(BaseModel):
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    instructions: str | None = None
    transport: Literal["streamable_http", "sse", "inproc"] = "streamable_http"
    authenticated: bool = False
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    total_tokens: int = 0


class PhaseStatus(BaseModel):
    phase: Phase
    status: Literal["pending", "running", "completed", "failed", "skipped"] = "pending"
    detail: str = ""
    seconds: float | None = None


class ProbeCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    response_excerpt: str = ""
    response_tokens: int = 0
    seconds: float = 0.0
    note: str = ""


class Report(BaseModel):
    audit_id: str = Field(default_factory=new_id)
    url: str
    target_label: str | None = None
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime | None = None
    phases: list[PhaseStatus] = Field(
        default_factory=lambda: [PhaseStatus(phase=p) for p in PHASES]
    )
    inventory: Inventory | None = None
    findings: list[Finding] = Field(default_factory=list)
    probe_calls: list[ProbeCall] = Field(default_factory=list)
    score: int = 0
    grade: Grade = "F"
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    )
    llm_usage: dict[str, int] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}
    )
    model: str = ""

    def phase(self, name: Phase) -> PhaseStatus:
        return next(p for p in self.phases if p.phase == name)
