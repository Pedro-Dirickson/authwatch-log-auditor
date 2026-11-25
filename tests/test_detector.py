import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from authwatch.detector import (
    BRUTE_FORCE,
    OFF_HOURS_LOGIN,
    USER_ENUMERATION,
    analyze,
    detect_brute_force,
    detect_off_hours,
    detect_user_enumeration,
)
from authwatch.parser import (
    FAILED,
    SUCCESS,
    AuthEvent,
    parse_file,
    parse_json_line,
    parse_line,
    parse_ssh_line,
)

BASE = datetime(2026, 11, 24, 10, 0, 0)


def ev(seconds, ip="10.0.0.1", user="root", status=FAILED, invalid=False):
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        source_ip=ip,
        user=user,
        status=status,
        source="ssh",
        invalid_user=invalid,
    )


class SSHParserTests(unittest.TestCase):
    def test_failed_password(self):
        e = parse_ssh_line(
            "Nov 24 03:12:45 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2",
            year=2026,
        )
        self.assertEqual(e.timestamp, datetime(2026, 11, 24, 3, 12, 45))
        self.assertEqual((e.source_ip, e.user, e.status), ("203.0.113.7", "root", FAILED))
        self.assertFalse(e.invalid_user)

    def test_failed_invalid_user(self):
        e = parse_ssh_line(
            "Nov  4 03:12:45 web01 sshd[99]: Failed password for invalid user oracle from 198.51.100.2 port 4444 ssh2",
            year=2026,
        )
        self.assertEqual(e.user, "oracle")
        self.assertTrue(e.invalid_user)
        self.assertEqual(e.timestamp.day, 4)

    def test_accepted_publickey(self):
        e = parse_ssh_line(
            "Nov 24 09:00:01 web01 sshd[77]: Accepted publickey for deploy from 192.168.1.20 port 50000 ssh2: RSA SHA256:abc",
            year=2026,
        )
        self.assertEqual((e.user, e.status), ("deploy", SUCCESS))

    def test_iso_timestamp_and_ipv6(self):
        e = parse_ssh_line(
            "2026-11-24T01:02:03.123456-03:00 web01 sshd[5]: Accepted password for pedro from 2001:db8::1 port 22 ssh2"
        )
        self.assertEqual(e.timestamp, datetime(2026, 11, 24, 1, 2, 3, 123456))
        self.assertEqual(e.source_ip, "2001:db8::1")

    def test_openssh_98_sshd_session_and_journalctl_offset(self):
        e = parse_ssh_line(
            "2026-11-24T10:14:04-0300 web01 sshd-session[4321]: Failed password for root from 203.0.113.7 port 22 ssh2"
        )
        self.assertEqual(e.timestamp, datetime(2026, 11, 24, 10, 14, 4))
        self.assertEqual((e.user, e.status), ("root", FAILED))

    def test_ignores_unrelated_lines(self):
        self.assertIsNone(parse_ssh_line("Nov 24 03:12:45 web01 CRON[1]: pam_unix(cron:session): session opened"))
        self.assertIsNone(parse_ssh_line("Nov 24 03:12:45 web01 sshd[1]: Connection closed by 1.2.3.4 port 22"))
        self.assertIsNone(parse_line("   "))


class JSONParserTests(unittest.TestCase):
    def test_textual_status(self):
        e = parse_json_line(json.dumps(
            {"timestamp": "2026-11-24T02:30:00Z", "ip": "203.0.113.9", "user": "alice", "status": "failed"}
        ))
        self.assertEqual(e.timestamp, datetime(2026, 11, 24, 2, 30))
        self.assertEqual((e.source_ip, e.user, e.status, e.source), ("203.0.113.9", "alice", FAILED, "api"))

    def test_http_status_codes_and_aliases(self):
        ok = parse_json_line('{"time": "2026-11-24T12:00:00", "client_ip": "1.1.1.1", "username": "bob", "status_code": 200}')
        bad = parse_json_line('{"time": "2026-11-24T12:00:00", "client_ip": "1.1.1.1", "username": "bob", "status_code": 401}')
        self.assertEqual(ok.status, SUCCESS)
        self.assertEqual(bad.status, FAILED)

    def test_rejects_non_auth_records(self):
        self.assertIsNone(parse_json_line('{"timestamp": "2026-11-24T12:00:00", "ip": "1.1.1.1", "status_code": 500}'))
        self.assertIsNone(parse_json_line('{"msg": "hello"}'))
        self.assertIsNone(parse_json_line("{not json"))

    def test_parse_file_mixed_formats(self):
        content = "\n".join([
            "Nov 24 03:12:45 web01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
            "garbage line",
            '{"timestamp": "2026-11-24T03:13:00Z", "ip": "203.0.113.7", "user": "admin", "status": "failure"}',
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.log"
            path.write_text(content, encoding="utf-8")
            events = parse_file(path, year=2026)
        self.assertEqual([e.source for e in events], ["ssh", "api"])
        self.assertEqual([e.line_number for e in events], [1, 3])


class BruteForceTests(unittest.TestCase):
    def test_triggers_at_threshold_within_window(self):
        events = [ev(i * 30) for i in range(5)]  # 5 failures in 2 minutes
        incidents = detect_brute_force(events, threshold=5, window=timedelta(minutes=5))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule, BRUTE_FORCE)
        self.assertEqual(incidents[0].event_count, 5)
        self.assertEqual(incidents[0].severity, "MEDIUM")

    def test_below_threshold_no_incident(self):
        events = [ev(i * 30) for i in range(4)]
        self.assertEqual(detect_brute_force(events, threshold=5), [])

    def test_failures_spread_outside_window_not_flagged(self):
        events = [ev(i * 120) for i in range(10)]  # one failure every 2 min
        self.assertEqual(detect_brute_force(events, threshold=5, window=timedelta(minutes=5)), [])

    def test_sustained_attack_is_single_incident(self):
        events = [ev(i * 10) for i in range(30)]
        incidents = detect_brute_force(events, threshold=5, window=timedelta(minutes=5))
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].event_count, 30)
        self.assertEqual(incidents[0].severity, "HIGH")

    def test_separate_bursts_are_separate_incidents(self):
        events = [ev(i) for i in range(5)] + [ev(3600 + i) for i in range(5)]
        incidents = detect_brute_force(events, threshold=5, window=timedelta(minutes=5))
        self.assertEqual(len(incidents), 2)
        self.assertEqual([i.event_count for i in incidents], [5, 5])

    def test_ips_are_counted_independently(self):
        events = [ev(i, ip="10.0.0.1") for i in range(3)] + [ev(i, ip="10.0.0.2") for i in range(3)]
        self.assertEqual(detect_brute_force(events, threshold=5), [])

    def test_success_after_burst_is_critical(self):
        events = [ev(i * 5) for i in range(6)] + [ev(60, status=SUCCESS)]
        incidents = detect_brute_force(events, threshold=5)
        self.assertEqual(incidents[0].severity, "CRITICAL")
        self.assertIn("possible compromise", incidents[0].description)

    def test_unordered_input(self):
        events = [ev(s) for s in (40, 0, 30, 10, 20)]
        self.assertEqual(len(detect_brute_force(events, threshold=5)), 1)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_brute_force([], threshold=0)


class UserEnumerationTests(unittest.TestCase):
    def test_distinct_users_trigger(self):
        events = [ev(i * 10, user=u, invalid=True) for i, u in enumerate(["admin", "oracle", "test"])]
        incidents = detect_user_enumeration(events, min_users=3)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule, USER_ENUMERATION)
        self.assertEqual(incidents[0].users, ["admin", "oracle", "test"])
        self.assertEqual(incidents[0].severity, "HIGH")  # non-existent users involved

    def test_same_user_repeated_is_not_enumeration(self):
        events = [ev(i, user="root") for i in range(20)]
        self.assertEqual(detect_user_enumeration(events, min_users=3), [])

    def test_users_spread_outside_window(self):
        events = [ev(i * 600, user=f"u{i}") for i in range(5)]
        self.assertEqual(detect_user_enumeration(events, min_users=3, window=timedelta(minutes=5)), [])

    def test_successful_logins_do_not_count(self):
        events = [ev(i, user=f"u{i}", status=SUCCESS) for i in range(5)]
        self.assertEqual(detect_user_enumeration(events, min_users=3), [])

    def test_different_ips_not_combined(self):
        events = [ev(i, ip=f"10.0.0.{i}", user=f"u{i}") for i in range(5)]
        self.assertEqual(detect_user_enumeration(events, min_users=3), [])


class OffHoursTests(unittest.TestCase):
    def at(self, hour, minute=0, status=SUCCESS):
        return AuthEvent(datetime(2026, 11, 24, hour, minute), "10.0.0.5", "pedro", status, "ssh")

    def test_success_in_off_hours(self):
        incidents = detect_off_hours([self.at(0, 0), self.at(3, 15), self.at(4, 59)])
        self.assertEqual(len(incidents), 3)
        self.assertTrue(all(i.rule == OFF_HOURS_LOGIN for i in incidents))

    def test_business_hours_and_boundary(self):
        self.assertEqual(detect_off_hours([self.at(5, 0), self.at(12), self.at(23, 59)]), [])

    def test_failures_ignored(self):
        self.assertEqual(detect_off_hours([self.at(2, status=FAILED)]), [])

    def test_range_wrapping_midnight(self):
        events = [self.at(22), self.at(1), self.at(12)]
        self.assertEqual(len(detect_off_hours(events, start_hour=22, end_hour=6)), 2)


class AnalyzeTests(unittest.TestCase):
    def test_combined_and_sorted_by_severity(self):
        night = BASE.replace(hour=2)
        events = [
            AuthEvent(night + timedelta(seconds=i), "198.51.100.1", u, FAILED, "ssh", invalid_user=True)
            for i, u in enumerate(["a", "b", "c", "d", "e"])
        ]
        events.append(AuthEvent(night + timedelta(seconds=30), "198.51.100.1", "root", SUCCESS, "ssh"))
        incidents = analyze(events, threshold=5, min_users=3)
        rules = [i.rule for i in incidents]
        self.assertEqual(rules, [BRUTE_FORCE, USER_ENUMERATION, OFF_HOURS_LOGIN])
        self.assertEqual(incidents[0].severity, "CRITICAL")
        json.dumps([i.to_dict() for i in incidents])  # must be JSON serialisable


if __name__ == "__main__":
    unittest.main()
