import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path

from authwatch.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_INCIDENTS, main
from authwatch.detector import BRUTE_FORCE, OFF_HOURS_LOGIN, USER_ENUMERATION
from authwatch.parser import FAILED, SUCCESS, AuthEvent
from authwatch.reporter import _compact_ranges, build_report, render_text

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_auth.log"
ATTACKER = "185.220.101.47"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:  # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class SampleLogTests(unittest.TestCase):
    def test_sample_detects_brute_force_and_off_hours(self):
        code, out, _ = run("--file", str(SAMPLE), "--year", "2026")
        self.assertEqual(code, EXIT_INCIDENTS)
        self.assertIn(f"Brute Force - {ATTACKER}", out)
        self.assertIn("Off-Hours Login - 91.214.124.33", out)
        self.assertIn("backup_admin", out)

    def test_normal_traffic_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            run("--file", str(SAMPLE), "--year", "2026", "--export", str(target), "--quiet")
            report = json.loads(target.read_text(encoding="utf-8"))
        flagged = {i["source_ip"] for i in report["incidents"]}
        self.assertEqual(flagged, {ATTACKER, "91.214.124.33"})

    def test_export_json_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nested" / "report.json"
            code, out, _ = run("-f", str(SAMPLE), "-y", "2026", "--export", str(target))
            self.assertEqual(code, EXIT_INCIDENTS)
            self.assertIn("JSON report written", out)
            report = json.loads(target.read_text(encoding="utf-8"))

        self.assertEqual(report["tool"], "authwatch")
        self.assertEqual(report["settings"], {"threshold": 5, "window_minutes": 5.0, "min_users": 3})
        self.assertEqual(report["summary"]["incidents_total"], 3)
        self.assertEqual(
            report["summary"]["incidents_by_rule"],
            {BRUTE_FORCE: 1, USER_ENUMERATION: 1, OFF_HOURS_LOGIN: 1},
        )
        brute = next(i for i in report["incidents"] if i["rule"] == BRUTE_FORCE)
        self.assertEqual(brute["source_ip"], ATTACKER)
        self.assertEqual(brute["event_count"], 14)
        self.assertEqual(brute["first_seen"], "2026-11-24T10:14:04")
        self.assertTrue(brute["lines"])

    def test_high_threshold_suppresses_brute_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            run("-f", str(SAMPLE), "-y", "2026", "--threshold", "50", "-e", str(target), "-q")
            rules = {i["rule"] for i in json.loads(target.read_text(encoding="utf-8"))["incidents"]}
        self.assertNotIn(BRUTE_FORCE, rules)
        self.assertIn(OFF_HOURS_LOGIN, rules)

    def test_tiny_window_suppresses_brute_force(self):
        # Attack attempts are ~6 s apart, so a 6-second window never holds 5 failures.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.json"
            run("-f", str(SAMPLE), "-y", "2026", "--window", "0.1", "-e", str(target), "-q")
            rules = {i["rule"] for i in json.loads(target.read_text(encoding="utf-8"))["incidents"]}
        self.assertNotIn(BRUTE_FORCE, rules)

    def test_quiet_prints_nothing(self):
        code, out, _ = run("-f", str(SAMPLE), "-y", "2026", "-q")
        self.assertEqual(code, EXIT_INCIDENTS)
        self.assertEqual(out, "")


class CliEdgeCaseTests(unittest.TestCase):
    def test_clean_log_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "clean.log"
            log.write_text(
                "Nov 24 09:00:00 h sshd[1]: Accepted publickey for pedro from 10.0.0.1 port 22 ssh2\n",
                encoding="utf-8",
            )
            code, out, _ = run("-f", str(log), "-y", "2026")
        self.assertEqual(code, EXIT_CLEAN)
        self.assertIn("No suspicious activity detected.", out)

    def test_jsonl_input(self):
        lines = [
            json.dumps({"timestamp": f"2026-11-24T14:00:0{i}Z", "ip": "203.0.113.5",
                        "user": "api", "status": 401})
            for i in range(6)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "api.jsonl"
            log.write_text("\n".join(lines), encoding="utf-8")
            code, out, _ = run("-f", str(log))
        self.assertEqual(code, EXIT_INCIDENTS)
        self.assertIn("Brute Force - 203.0.113.5", out)

    def test_missing_file(self):
        code, _, err = run("--file", "does/not/exist.log")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot read", err)

    def test_file_is_required(self):
        code, _, err = run()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--file", err)

    def test_invalid_threshold_and_window(self):
        for argv in (("--threshold", "0"), ("--threshold", "abc"), ("--window", "-1"), ("--min-users", "1")):
            with self.subTest(argv=argv):
                code, _, _ = run("-f", str(SAMPLE), *argv)
                self.assertEqual(code, EXIT_ERROR)


class ReporterTests(unittest.TestCase):
    def test_compact_ranges(self):
        self.assertEqual(_compact_ranges([3, 1, 2, 7, 9, 10]), "1-3, 7, 9-10")
        self.assertEqual(_compact_ranges([5]), "5")

    def test_render_and_report_without_incidents(self):
        events = [AuthEvent(datetime(2026, 11, 24, 9), "10.0.0.1", "a", SUCCESS, "ssh"),
                  AuthEvent(datetime(2026, 11, 24, 9), "10.0.0.2", "b", FAILED, "ssh")]
        text = render_text(events, [])
        self.assertIn("Events parsed   : 2 (1 failed, 1 successful)", text)
        report = build_report(events, [])
        self.assertEqual(report["summary"]["unique_source_ips"], 2)
        self.assertEqual(report["incidents"], [])


if __name__ == "__main__":
    unittest.main()
