"""Command-line interface: ``authwatch --file auth.log [options]``.

Exit codes: 0 = no incidents, 1 = incidents detected, 2 = usage/input error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from typing import Sequence

from . import __version__
from .detector import DEFAULT_MIN_USERS, DEFAULT_THRESHOLD, DEFAULT_WINDOW, analyze
from .parser import parse_file
from .reporter import build_report, export_json, render_text

EXIT_CLEAN = 0
EXIT_INCIDENTS = 1
EXIT_ERROR = 2


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authwatch",
        description=(
            "Audit SSH auth.log or JSONL API logs for brute force, "
            "user enumeration and off-hours logins."
        ),
        epilog="Exit codes: 0 = clean, 1 = incidents detected, 2 = error.",
    )
    parser.add_argument("-f", "--file", required=True, help="log file to analyse (auth.log or JSONL)")
    parser.add_argument(
        "-t", "--threshold", type=_positive_int, default=DEFAULT_THRESHOLD,
        help=f"failed attempts from one IP that trigger Brute Force (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "-w", "--window", type=_positive_float, default=DEFAULT_WINDOW.total_seconds() / 60,
        help=f"sliding time window in minutes (default: {DEFAULT_WINDOW.total_seconds() / 60:g})",
    )
    parser.add_argument(
        "-u", "--min-users", type=_positive_int, default=DEFAULT_MIN_USERS,
        help=f"distinct usernames from one IP that trigger User Enumeration (default: {DEFAULT_MIN_USERS})",
    )
    parser.add_argument(
        "-y", "--year", type=int, default=None,
        help="year for syslog timestamps, which omit it (default: current year)",
    )
    parser.add_argument("-e", "--export", metavar="PATH", help="write the incident report as JSON to PATH")
    parser.add_argument("-q", "--quiet", action="store_true", help="do not print the terminal report")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.min_users < 2:
        parser.error("--min-users must be at least 2")

    try:
        events = parse_file(args.file, year=args.year)
    except OSError as exc:
        print(f"authwatch: error: cannot read {args.file}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_ERROR

    window = timedelta(minutes=args.window)
    incidents = analyze(events, threshold=args.threshold, window=window, min_users=args.min_users)
    settings = {"threshold": args.threshold, "window_minutes": args.window, "min_users": args.min_users}

    if not args.quiet:
        print(render_text(events, incidents, source=args.file, settings=settings))

    if args.export:
        report = build_report(events, incidents, source=args.file, settings=settings)
        try:
            path = export_json(report, args.export)
        except OSError as exc:
            print(f"authwatch: error: cannot write {args.export}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_ERROR
        if not args.quiet:
            print(f"\nJSON report written to {path}")

    return EXIT_INCIDENTS if incidents else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
