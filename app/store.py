"""JSON-file persistence for finished reports."""
from __future__ import annotations

import os
from pathlib import Path

from app.frameworks import attach_references
from app.models import Report


class Store:
    def __init__(self, data_dir: Path | str | None = None):
        self.dir = Path(data_dir or os.environ.get("MCPROBE_DATA_DIR", "data/audits"))
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, audit_id: str) -> Path:
        return self.dir / f"{audit_id}.json"

    def save(self, report: Report) -> Path:
        p = self.path(report.audit_id)
        p.write_text(report.model_dump_json(indent=2))
        return p

    @staticmethod
    def _read(p: Path) -> Report:
        r = Report.model_validate_json(p.read_text())
        attach_references(r.findings)  # reports saved before the mapping existed
        if r.finished_at is not None and r.phase("report").status == "running":
            r.phase("report").status = "completed"  # reports saved before the ordering fix
        return r

    def load(self, audit_id: str) -> Report | None:
        p = self.path(audit_id)
        if not p.exists():
            return None
        return self._read(p)

    def latest_for_url(self, url: str) -> Report | None:
        """Newest finished report for this URL, or None."""
        best: Report | None = None
        for p in self.dir.glob("*.json"):
            try:
                r = self._read(p)
            except Exception:
                continue
            if r.url != url or r.finished_at is None:
                continue
            if best is None or r.finished_at > best.finished_at:
                best = r
        return best

    def list_summaries(self) -> list[dict]:
        reports: list[Report] = []
        for p in self.dir.glob("*.json"):
            try:
                reports.append(Report.model_validate_json(p.read_text()))
            except Exception:
                continue
        reports.sort(key=lambda r: r.finished_at or r.started_at, reverse=True)
        return [{
            "audit_id": r.audit_id, "url": r.url, "target_label": r.target_label,
            "grade": r.grade, "score": r.score,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "server_name": r.inventory.server_name if r.inventory else None,
        } for r in reports]
