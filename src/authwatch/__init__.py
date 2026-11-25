"""AuthWatch - lightweight security auditor for authentication logs."""

from .detector import Incident, analyze
from .parser import FAILED, SUCCESS, AuthEvent, parse_file, parse_line

__version__ = "0.1.0"

__all__ = [
    "AuthEvent",
    "FAILED",
    "Incident",
    "SUCCESS",
    "analyze",
    "parse_file",
    "parse_line",
]
