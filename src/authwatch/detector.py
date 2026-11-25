"""Anomaly detection rules applied to parsed authentication events.

Rules:

* **Brute Force** - at least ``threshold`` failed attempts from the same IP
  within a sliding ``window``.
* **User Enumeration** - failed attempts against at least ``min_users``
  distinct usernames from the same IP within a sliding ``window``.
* **Off-Hours Login** - a successful login between ``start_hour`` (inclusive)
  and ``end_hour`` (exclusive), by default 00:00-04:59.

A sustained attack produces a single incident that grows while the rule keeps
firing, instead of one incident per extra failed attempt.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable

from .parser import AuthEvent

BRUTE_FORCE = "BRUTE_FORCE"
USER_ENUMERATION = "USER_ENUMERATION"
OFF_HOURS_LOGIN = "OFF_HOURS_LOGIN"

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=5)
DEFAULT_MIN_USERS = 3
DEFAULT_OFF_HOURS = (0, 5)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Incident:
    rule: str
    severity: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    users: list[str]
    description: str
    events: list[AuthEvent] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "users": self.users,
            "description": self.description,
            "lines": [e.line_number for e in self.events if e.line_number is not None],
        }


def _by_ip(events: Iterable[AuthEvent], predicate: Callable[[AuthEvent], bool]) -> dict[str, list[AuthEvent]]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if predicate(event):
            grouped[event.source_ip].append(event)
    for bucket in grouped.values():
        bucket.sort(key=lambda e: e.timestamp)
    return grouped


def _sliding_bursts(
    events: list[AuthEvent],
    window: timedelta,
    triggered: Callable[[int, Counter], bool],
) -> list[list[AuthEvent]]:
    """Return maximal bursts of time-sorted ``events`` where the rule fires.

    ``triggered(count, users)`` is evaluated on the events inside the window
    ending at each event. A burst starts at the oldest event of the first
    window that fires and keeps growing while subsequent windows still fire.
    Events already assigned to a burst are never reused by the next one.
    """
    bursts: list[list[AuthEvent]] = []
    in_window: deque[AuthEvent] = deque()
    users: Counter = Counter()
    burst: list[AuthEvent] | None = None

    for event in events:
        in_window.append(event)
        users[event.user] += 1
        while event.timestamp - in_window[0].timestamp > window:
            old = in_window.popleft()
            users[old.user] -= 1
            if not users[old.user]:
                del users[old.user]

        if triggered(len(in_window), users):
            if burst is None:
                burst = list(in_window)
            else:
                burst.append(event)
        elif burst is not None:
            bursts.append(burst)
            burst = None
            # Start fresh so closed-burst events are not counted twice.
            in_window.clear()
            users.clear()
            in_window.append(event)
            users[event.user] += 1

    if burst is not None:
        bursts.append(burst)
    return bursts


def _distinct_users(events: Iterable[AuthEvent]) -> list[str]:
    return sorted({e.user for e in events})


def _fmt_window(window: timedelta) -> str:
    minutes = window.total_seconds() / 60
    return f"{minutes:g} min"


def detect_brute_force(
    events: Iterable[AuthEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
) -> list[Incident]:
    """N failed attempts from the same IP within ``window``.

    Severity is HIGH (2x threshold or more) or MEDIUM, escalated to CRITICAL
    when the same IP logs in successfully within ``window`` after the burst.
    """
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    events = list(events)
    successes = _by_ip(events, lambda e: e.succeeded)
    incidents: list[Incident] = []

    for ip, failures in _by_ip(events, lambda e: e.failed).items():
        for burst in _sliding_bursts(failures, window, lambda count, _u: count >= threshold):
            first, last = burst[0].timestamp, burst[-1].timestamp
            compromise = next(
                (s for s in successes.get(ip, []) if last <= s.timestamp <= last + window),
                None,
            )
            severity = "HIGH" if len(burst) >= 2 * threshold else "MEDIUM"
            description = (
                f"{len(burst)} failed logins from {ip} between "
                f"{first:%Y-%m-%d %H:%M:%S} and {last:%H:%M:%S} "
                f"(threshold {threshold} in {_fmt_window(window)})"
            )
            related = list(burst)
            if compromise is not None:
                severity = "CRITICAL"
                description += (
                    f"; followed by SUCCESSFUL login as '{compromise.user}' "
                    f"at {compromise.timestamp:%H:%M:%S} - possible compromise"
                )
                related.append(compromise)
            incidents.append(
                Incident(
                    rule=BRUTE_FORCE,
                    severity=severity,
                    source_ip=ip,
                    first_seen=first,
                    last_seen=related[-1].timestamp,
                    event_count=len(burst),
                    users=_distinct_users(related),
                    description=description,
                    events=related,
                )
            )
    return incidents


def detect_user_enumeration(
    events: Iterable[AuthEvent],
    min_users: int = DEFAULT_MIN_USERS,
    window: timedelta = DEFAULT_WINDOW,
) -> list[Incident]:
    """Failed attempts against ``min_users`` distinct users from one IP."""
    if min_users < 2:
        raise ValueError("min_users must be >= 2")
    incidents: list[Incident] = []

    for ip, failures in _by_ip(events, lambda e: e.failed).items():
        for burst in _sliding_bursts(failures, window, lambda _c, users: len(users) >= min_users):
            users = _distinct_users(burst)
            invalid = sorted({e.user for e in burst if e.invalid_user})
            severity = "HIGH" if len(users) >= 2 * min_users or invalid else "MEDIUM"
            description = (
                f"{ip} tried {len(users)} distinct usernames in "
                f"{len(burst)} failed attempts within {_fmt_window(window)}"
            )
            if invalid:
                description += f" ({len(invalid)} non-existent: {', '.join(invalid)})"
            incidents.append(
                Incident(
                    rule=USER_ENUMERATION,
                    severity=severity,
                    source_ip=ip,
                    first_seen=burst[0].timestamp,
                    last_seen=burst[-1].timestamp,
                    event_count=len(burst),
                    users=users,
                    description=description,
                    events=burst,
                )
            )
    return incidents


def detect_off_hours(
    events: Iterable[AuthEvent],
    start_hour: int = DEFAULT_OFF_HOURS[0],
    end_hour: int = DEFAULT_OFF_HOURS[1],
) -> list[Incident]:
    """Successful logins with ``start_hour <= hour < end_hour``.

    Ranges wrapping midnight (e.g. 22 -> 6) are supported.
    """
    if not (0 <= start_hour <= 23 and 0 <= end_hour <= 24):
        raise ValueError("hours must be within 0-24")

    def is_off_hours(ts: datetime) -> bool:
        if start_hour <= end_hour:
            return start_hour <= ts.hour < end_hour
        return ts.hour >= start_hour or ts.hour < end_hour

    incidents = []
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.succeeded and is_off_hours(event.timestamp):
            incidents.append(
                Incident(
                    rule=OFF_HOURS_LOGIN,
                    severity="LOW",
                    source_ip=event.source_ip,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    event_count=1,
                    users=[event.user],
                    description=(
                        f"Successful {event.source} login as '{event.user}' from "
                        f"{event.source_ip} at {event.timestamp:%Y-%m-%d %H:%M:%S} "
                        f"(off-hours {start_hour:02d}:00-{end_hour:02d}:00)"
                    ),
                    events=[event],
                )
            )
    return incidents


def analyze(
    events: Iterable[AuthEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
    min_users: int = DEFAULT_MIN_USERS,
    off_hours: tuple[int, int] = DEFAULT_OFF_HOURS,
) -> list[Incident]:
    """Run every rule and return incidents ordered by severity, then time."""
    events = list(events)
    incidents = (
        detect_brute_force(events, threshold=threshold, window=window)
        + detect_user_enumeration(events, min_users=min_users, window=window)
        + detect_off_hours(events, start_hour=off_hours[0], end_hour=off_hours[1])
    )
    incidents.sort(key=lambda i: (_SEVERITY_ORDER.get(i.severity, 99), i.first_seen))
    return incidents
