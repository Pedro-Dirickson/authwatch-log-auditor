"""Parsing of authentication logs into structured events.

Supported formats:

* Linux ``auth.log`` / ``secure`` lines written by ``sshd``, both the classic
  syslog timestamp (``Nov 24 03:12:45``) and the RFC 3339 timestamp used by
  modern rsyslog/journald setups (``2026-11-24T03:12:45.123456+00:00``).
* JSON Lines (one JSON object per line) produced by web/API gateways.

Timestamps are normalised to *naive* datetimes holding the wall-clock time
recorded in the log itself, so events from different sources can be compared
and the hour of day reflects what the log says.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

FAILED = "FAILED"
SUCCESS = "SUCCESS"


@dataclass(frozen=True)
class AuthEvent:
    """A single authentication attempt extracted from a log line."""

    timestamp: datetime
    source_ip: str
    user: str
    status: str  # FAILED or SUCCESS
    source: str  # "ssh" or "api"
    invalid_user: bool = False
    line_number: int | None = field(default=None, compare=False)
    raw: str = field(default="", compare=False, repr=False)

    @property
    def failed(self) -> bool:
        return self.status == FAILED

    @property
    def succeeded(self) -> bool:
        return self.status == SUCCESS


# --------------------------------------------------------------------------- #
# SSH (auth.log)
# --------------------------------------------------------------------------- #

_SYSLOG_TS = r"(?P<syslog_ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
_ISO_TS = r"(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"

_SSH_RE = re.compile(
    # OpenSSH >= 9.8 logs authentication from "sshd-session" instead of "sshd".
    rf"^(?:{_SYSLOG_TS}|{_ISO_TS})\s+\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+"
    r"(?P<result>Failed|Accepted)\s+\S+\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>.*?)\s+"
    r"from\s+(?P<ip>[0-9A-Fa-f:.]+)\s+port\s+\d+"
)


def _parse_syslog_timestamp(value: str, year: int) -> datetime:
    # Syslog timestamps omit the year; pad single-digit days ("Nov  4").
    return datetime.strptime(f"{year} {' '.join(value.split())}", "%Y %b %d %H:%M:%S")


def _parse_iso_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).replace(tzinfo=None)


def parse_ssh_line(line: str, year: int | None = None, line_number: int | None = None) -> AuthEvent | None:
    """Parse one ``sshd`` line. Returns ``None`` for unrelated lines.

    ``year`` is used for classic syslog timestamps, which carry no year
    (defaults to the current year).
    """
    match = _SSH_RE.match(line.strip())
    if not match:
        return None

    if match.group("syslog_ts"):
        timestamp = _parse_syslog_timestamp(match.group("syslog_ts"), year or datetime.now().year)
    else:
        timestamp = _parse_iso_timestamp(match.group("iso_ts"))

    return AuthEvent(
        timestamp=timestamp,
        source_ip=match.group("ip"),
        user=match.group("user"),
        status=SUCCESS if match.group("result") == "Accepted" else FAILED,
        source="ssh",
        invalid_user=bool(match.group("invalid")),
        line_number=line_number,
        raw=line.rstrip("\n"),
    )


# --------------------------------------------------------------------------- #
# JSONL (web / API access logs)
# --------------------------------------------------------------------------- #

_TS_KEYS = ("timestamp", "@timestamp", "time", "ts", "datetime")
_IP_KEYS = ("source_ip", "ip", "client_ip", "remote_addr", "src_ip")
_USER_KEYS = ("user", "username", "user_name", "login", "email")
_STATUS_KEYS = ("status", "result", "outcome", "event", "status_code")

_SUCCESS_WORDS = {"success", "succeeded", "successful", "ok", "accepted", "login_success", "allowed"}
_FAILED_WORDS = {"failed", "failure", "fail", "denied", "rejected", "error", "login_failed", "unauthorized", "forbidden"}


def _first(record: dict, keys: Iterable[str]):
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return None


def _normalise_status(value) -> str | None:
    if isinstance(value, bool):
        return SUCCESS if value else FAILED
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        code = int(value)
        if 200 <= code < 300:
            return SUCCESS
        if code in (401, 403):
            return FAILED
        return None
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _SUCCESS_WORDS:
            return SUCCESS
        if word in _FAILED_WORDS:
            return FAILED
    return None


def parse_json_line(line: str, line_number: int | None = None) -> AuthEvent | None:
    """Parse one JSONL record. Returns ``None`` if it is not an auth event."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    raw_ts = _first(record, _TS_KEYS)
    ip = _first(record, _IP_KEYS)
    status = _normalise_status(_first(record, _STATUS_KEYS))
    if raw_ts is None or ip is None or status is None:
        return None

    try:
        if isinstance(raw_ts, (int, float)):
            timestamp = datetime.fromtimestamp(raw_ts)
        else:
            timestamp = _parse_iso_timestamp(str(raw_ts))
    except (ValueError, OverflowError, OSError):
        return None

    return AuthEvent(
        timestamp=timestamp,
        source_ip=str(ip),
        user=str(_first(record, _USER_KEYS) or "-"),
        status=status,
        source="api",
        invalid_user=bool(record.get("invalid_user", False)),
        line_number=line_number,
        raw=line.rstrip("\n"),
    )


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #

def parse_line(line: str, year: int | None = None, line_number: int | None = None) -> AuthEvent | None:
    """Detect the format of ``line`` and parse it."""
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("{"):
        return parse_json_line(stripped, line_number=line_number)
    return parse_ssh_line(stripped, year=year, line_number=line_number)


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    """Yield events from an iterable of lines, skipping anything unparseable."""
    for number, line in enumerate(lines, start=1):
        event = parse_line(line, year=year, line_number=number)
        if event is not None:
            yield event


def parse_file(path: str | Path, year: int | None = None) -> list[AuthEvent]:
    """Parse a whole log file (auth.log or JSONL, auto-detected per line)."""
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        return list(parse_lines(handle, year=year))
