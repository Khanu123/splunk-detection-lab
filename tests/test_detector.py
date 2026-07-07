import unittest

from splunk_detection_lab.detector import (
    detect_bruteforce,
    detect_password_spray,
    detect_privileged_unusual_source,
    load_events,
    run_all,
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


if __name__ == "__main__":
    unittest.main()
