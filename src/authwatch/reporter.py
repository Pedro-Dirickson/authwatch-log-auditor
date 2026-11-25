"""Terminal summary and JSON export of detected incidents."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from . import __version__
from .detector import Incident
from .parser import AuthEvent

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_RULE_LABELS = {
    "BRUTE_FORCE": "Brute Force",
    "USER_ENUMERATION": "User Enumeration",
    "OFF_HOURS_LOGIN": "Off-Hours Login",
}


def summarize(events: Sequence[AuthEvent], incidents: Sequence[Incident]) -> dict:
    """Aggregate counters shared by the text and JSON outputs."""
    statuses = Counter(e.status for e in events)
    return {
        "events_parsed": len(events),
        "failed_logins": statuses.get("FAILED", 0),
        "successful_logins": statuses.get("SUCCESS", 0),
        "unique_source_ips": len({e.source_ip for e in events}),
        "incidents_total": len(incidents),
        "incidents_by_rule": dict(Counter(i.rule for i in incidents)),
        "incidents_by_severity": {
            s: n for s in _SEVERITIES if (n := sum(1 for i in incidents if i.severity == s))
        },
    }


def render_text(
    events: Sequence[AuthEvent],
    incidents: Sequence[Incident],
    source: str | Path | None = None,
    settings: dict | None = None,
) -> str:
    """Human-readable report for the terminal (ASCII only, safe on any console)."""
    stats = summarize(events, incidents)
    rule = "=" * 72
    lines = [rule, "AuthWatch - Authentication Log Audit", rule]
    if source is not None:
        lines.append(f"File            : {source}")
    if settings:
        lines.append("Settings        : " + ", ".join(f"{k}={v}" for k, v in settings.items()))
    lines += [
        f"Events parsed   : {stats['events_parsed']} "
        f"({stats['failed_logins']} failed, {stats['successful_logins']} successful)",
        f"Source IPs      : {stats['unique_source_ips']}",
        f"Incidents       : {stats['incidents_total']}",
    ]
    if stats["incidents_by_severity"]:
        lines.append(
            "By severity     : "
            + ", ".join(f"{s} {n}" for s, n in stats["incidents_by_severity"].items())
        )
    lines.append(rule)

    if not incidents:
        lines.append("No suspicious activity detected.")
        return "\n".join(lines)

    for number, incident in enumerate(incidents, start=1):
        label = _RULE_LABELS.get(incident.rule, incident.rule)
        lines.append(f"[{number}] {incident.severity:<8} {label} - {incident.source_ip}")
        lines.append(f"    {incident.description}")
        if incident.users:
            lines.append(f"    Users : {', '.join(incident.users)}")
        lines.append(
            f"    Time  : {incident.first_seen:%Y-%m-%d %H:%M:%S}"
            + (f" -> {incident.last_seen:%H:%M:%S}" if incident.last_seen != incident.first_seen else "")
        )
        line_numbers = [e.line_number for e in incident.events if e.line_number is not None]
        if line_numbers:
            lines.append(f"    Lines : {_compact_ranges(line_numbers)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_report(
    events: Sequence[AuthEvent],
    incidents: Iterable[Incident],
    source: str | Path | None = None,
    settings: dict | None = None,
) -> dict:
    incidents = list(incidents)
    return {
        "tool": "authwatch",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_file": str(source) if source is not None else None,
        "settings": settings or {},
        "summary": summarize(events, incidents),
        "incidents": [i.to_dict() for i in incidents],
    }


def export_json(report: dict, path: str | Path) -> Path:
    """Write ``report`` as pretty-printed JSON, creating parent folders."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _compact_ranges(numbers: Iterable[int]) -> str:
    """[1, 2, 3, 7, 9, 10] -> '1-3, 7, 9-10'."""
    values = sorted(set(numbers))
    parts: list[str] = []
    start = prev = values[0]
    for value in values[1:] + [None]:
        if value is not None and value == prev + 1:
            prev = value
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        if value is not None:
            start = prev = value
    return ", ".join(parts)
