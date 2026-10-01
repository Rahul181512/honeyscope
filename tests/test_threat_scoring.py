"""Unit tests for the Threat Scoring Module."""

import unittest

from core import threat_scoring as ts


def login_attempt(user="root", password="toor", dst=2222):
    return {"event_type": "login_attempt", "service": "ssh", "dst_port": dst,
            "username": user, "password": password, "payload": None}


def probe(port):
    return {"event_type": "port_probe", "service": "sensor",
            "dst_port": port, "payload": None}


class TestSeverityBoundaries(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(ts.severity_for_score(7.9), "LOW")
        self.assertEqual(ts.severity_for_score(8.0), "MEDIUM")
        self.assertEqual(ts.severity_for_score(17.9), "MEDIUM")
        self.assertEqual(ts.severity_for_score(18.0), "HIGH")
        self.assertEqual(ts.severity_for_score(31.9), "HIGH")
        self.assertEqual(ts.severity_for_score(32.0), "CRITICAL")


class TestSingleEvents(unittest.TestCase):
    def test_single_failed_login_is_low(self):
        score, sev, pattern = ts.evaluate(login_attempt(), [])
        self.assertAlmostEqual(score, 3.0)
        self.assertEqual(sev, "LOW")
        self.assertEqual(pattern, "unknown")

    def test_sql_injection_detected(self):
        event = {"event_type": "http_request", "service": "http",
                 "payload": "/product.php?id=1' UNION SELECT password FROM users--"}
        score, sev, pattern = ts.evaluate(event, [])
        self.assertEqual(pattern, "sql_injection")
        self.assertAlmostEqual(score, 8.0)   # weight 1 + bonus 7
        self.assertEqual(sev, "MEDIUM")

    def test_xss_detected(self):
        event = {"event_type": "http_request",
                 "payload": '/search?q=<script>alert(1)</script>'}
        _score, _sev, pattern = ts.evaluate(event, [])
        self.assertEqual(pattern, "xss")

    def test_traversal_detected(self):
        event = {"event_type": "http_request",
                 "payload": "/download?file=../../../../etc/passwd"}
        _score, _sev, pattern = ts.evaluate(event, [])
        self.assertEqual(pattern, "path_traversal")

    def test_scanner_user_agent(self):
        event = {"event_type": "http_request", "payload": "/",
                 "user_agent": "sqlmap/1.7.11#stable"}
        _score, _sev, pattern = ts.evaluate(event, [])
        self.assertEqual(pattern, "scanner_tool")


class TestBehaviour(unittest.TestCase):
    def test_brute_force_detection(self):
        history = [login_attempt(user=u) for u in
                   ("admin", "test", "ubuntu", "pi")]
        score, sev, pattern = ts.evaluate(login_attempt(), history)
        self.assertEqual(pattern, "brute_force")
        # 3 base + 8 brute + velocity min(4,10)*1.2 = 15.8
        self.assertAlmostEqual(score, 15.8)
        self.assertEqual(sev, "MEDIUM")

    def test_credential_stuffing_detection(self):
        history = [login_attempt(user=f"user{i}") for i in range(6)]
        score, sev, pattern = ts.evaluate(login_attempt(user="user99"),
                                          history)
        self.assertEqual(pattern, "credential_stuffing")
        # 3 + 8(brute also true: 6 prior failures) + 14 stuffing + 7.2
        self.assertAlmostEqual(score, 32.2)
        self.assertEqual(sev, "CRITICAL")

    def test_port_scan_detection(self):
        history = [probe(p) for p in (1433, 3306, 3389, 5432)]
        score, sev, pattern = ts.evaluate(probe(5900), history)
        self.assertEqual(pattern, "port_scan")
        self.assertAlmostEqual(score, 9.0)   # 1 + 8
        self.assertEqual(sev, "MEDIUM")

    def test_web_pattern_wins_over_scan_label(self):
        # scanning IP whose latest hit carries an SQLi payload
        history = [probe(p) for p in (1433, 3306, 3389, 5432, 6379)]
        event = {"event_type": "http_request", "dst_port": 8080,
                 "payload": "/x?id=1' OR '1'='1"}
        _score, _sev, pattern = ts.evaluate(event, history)
        self.assertEqual(pattern, "sql_injection")

    def test_command_weight(self):
        score, sev, pattern = ts.evaluate(
            {"event_type": "command", "payload": "whoami"}, [])
        self.assertAlmostEqual(score, 4.0)
        self.assertEqual(sev, "LOW")


if __name__ == "__main__":
    unittest.main()
