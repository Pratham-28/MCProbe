"""Compare two scans of the same server: grade change and tool-definition drift."""
from __future__ import annotations

from app.models import Report
from app.prober import _diff_definitions


def _defs(r: Report) -> dict[str, dict]:
    if not r.inventory:
        return {}
    return {t.name: {"description": t.description or "", "input_schema": t.input_schema or {}} for t in r.inventory.tools}


def compare_reports(prev: Report, cur: Report) -> dict:
    diff = _diff_definitions(_defs(prev), _defs(cur))
    added = sorted(n for n, d in diff.items() if "added" in d)
    removed = sorted(n for n, d in diff.items() if "removed" in d)
    changed = [{"name": n, "fields": d} for n, d in sorted(diff.items()) if "added" not in d and "removed" not in d]
    return {
        "previous": {"audit_id": prev.audit_id, "grade": prev.grade, "score": prev.score,
                     "finished_at": prev.finished_at.isoformat() if prev.finished_at else None,
                     "findings": len(prev.findings)},
        "current": {"audit_id": cur.audit_id, "grade": cur.grade, "score": cur.score, "findings": len(cur.findings)},
        "grade_change": {"from": prev.grade, "to": cur.grade, "score_delta": cur.score - prev.score},
        "tools": {"added": added, "removed": removed, "changed": changed},
    }


GRADE_COLORS = {"A": "#059669", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626", "?": "#64748b"}


def badge_svg(grade: str, score: int, status: str) -> str:
    """A shields.io-style badge: left 'MCProbe', right '<grade> <score>' in the grade colour."""
    right = "? not scanned" if status == "unscannable" or grade == "?" else f"{grade} {score}"
    color = GRADE_COLORS.get(grade, "#64748b")
    lw, rw = 64, 12 + 7 * len(right)
    w = lw + rw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="MCProbe: {right}">'
            f'<title>MCProbe: {right}</title>'
            f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
            f'<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
            f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
            f'<rect width="{w}" height="20" fill="url(#s)"/></g>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw/2}" y="15" fill="#010101" fill-opacity=".3">MCProbe</text><text x="{lw/2}" y="14">MCProbe</text>'
            f'<text x="{lw + rw/2}" y="15" fill="#010101" fill-opacity=".3">{right}</text><text x="{lw + rw/2}" y="14">{right}</text>'
            f'</g></svg>')
