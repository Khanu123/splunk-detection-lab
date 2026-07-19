import unittest
from dataclasses import replace
import tempfile
from pathlib import Path

from splunk_detection_lab.detector import (
    detect_bruteforce,
    detect_password_spray,
    detect_privileged_unusual_source,
    load_events,
    run_all,
    write_report,
)


class SplunkDetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events()

    def test_bruteforce_detects_success_after_failures(self):
        finding = detect_bruteforce(self.events)[0]

        self.assertEqual(finding["src_ip"], "198.51.100.44")
        self.assertTrue(finding["success_after_failures"])
        self.assertEqual(finding["severity"], "critical")

    def test_password_spray_detects_many_users(self):
        finding = detect_password_spray(self.events)[0]

        self.assertEqual(finding["src_ip"], "203.0.113.77")
        self.assertGreaterEqual(finding["unique_users"], 5)

    def test_privileged_external_login_is_flagged(self):
        findings = detect_privileged_unusual_source(self.events)

        self.assertTrue(any(item["user"] == "admin" for item in findings))
        self.assertFalse(any(item["user"] == "service_backup" for item in findings))

    def test_run_all_returns_three_detection_types(self):
        types = {item["type"] for item in run_all(self.events)}

        self.assertEqual(types, {"BRUTE_FORCE", "PASSWORD_SPRAY", "PRIVILEGED_UNUSUAL_SOURCE"})

    def test_failures_outside_window_do_not_trigger(self):
        spread = [replace(event, timestamp=f"2026-07-07T{9 + index:02d}:00:00") for index, event in enumerate(self.events[:4])]
        self.assertEqual(detect_bruteforce(spread), [])

    def test_success_before_failures_does_not_escalate_to_critical(self):
        success = replace(self.events[4], timestamp="2026-07-07T08:59:00")
        finding = detect_bruteforce([success, *self.events[:4]])[0]
        self.assertFalse(finding["success_after_failures"])
        self.assertEqual(finding["severity"], "high")

    def test_password_spray_requires_users_in_same_window(self):
        spray = [replace(event, timestamp=f"2026-07-07T{index + 1:02d}:00:00") for index, event in enumerate(self.events[5:11])]
        self.assertEqual(detect_password_spray(spray), [])

    def test_malformed_external_ip_is_flagged_without_crashing(self):
        event = replace(self.events[4], src_ip="unknown")
        self.assertEqual(detect_privileged_unusual_source([event])[0]["src_ip"], "unknown")

    def test_report_contains_validated_detection_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.md"
            write_report(run_all(self.events), path)
            report = path.read_text(encoding="utf-8")
        self.assertIn("BRUTE_FORCE", report)
        self.assertIn("PASSWORD_SPRAY", report)


if __name__ == "__main__":
    unittest.main()
