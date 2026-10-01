"""Unit tests for the Log Parser / Normalizer module."""

import unittest

from core.parser import normalize, parse_auth_log_line, parse_cowrie_json


class TestNormalize(unittest.TestCase):
    def test_fills_defaults(self):
        ev = normalize({"src_ip": "10.0.0.9"})
        self.assertEqual(ev["src_ip"], "10.0.0.9")
        self.assertEqual(ev["protocol"], "tcp")
        self.assertEqual(ev["service"], "other")
        self.assertEqual(ev["event_type"], "connection")
        self.assertTrue(ev["ts"].endswith("Z"))
        self.assertGreater(ev["epoch"], 1_600_000_000)

    def test_missing_src_ip_raises(self):
        with self.assertRaises(ValueError):
            normalize({"service": "ssh"})

    def test_payload_truncated(self):
        ev = normalize({"src_ip": "1.2.3.4",
                        "payload": "A" * 9000})
        self.assertLessEqual(len(ev["payload"]), 4096)

    def test_unknown_keys_dropped_but_geo_kept(self):
        ev = normalize({"src_ip": "1.2.3.4", "hacker_extra": True,
                        "geo_country": "Spain"})
        self.assertNotIn("hacker_extra", ev)
        self.assertEqual(ev["geo_country"], "Spain")

    def test_port_coercion(self):
        ev = normalize({"src_ip": "1.2.3.4", "src_port": "55555"})
        self.assertEqual(ev["src_port"], 55555)
        ev2 = normalize({"src_ip": "1.2.3.4", "dst_port": 0})
        self.assertIsNone(ev2["dst_port"])


class TestAuthLogParser(unittest.TestCase):
    LINE = ("Jan 14 03:22:01 labserver sshd[4123]: Failed password for "
            "invalid user admin from 203.0.113.55 port 44312 ssh2")

    def test_parses_failed_password(self):
        raw = parse_auth_log_line(self.LINE)
        self.assertIsNotNone(raw)
        self.assertEqual(raw["username"], "admin")
        self.assertEqual(raw["src_ip"], "203.0.113.55")
        self.assertEqual(raw["src_port"], 44312)
        self.assertEqual(raw["event_type"], "login_attempt")
        self.assertEqual(raw["service"], "ssh")

    def test_ignores_other_lines(self):
        self.assertIsNone(parse_auth_log_line(
            "Jan 14 03:22:01 labserver systemd[1]: Started Daily apt upgrade."))


class TestCowrieImport(unittest.TestCase):
    def test_login_failed_mapping(self):
        obj = {
            "eventid": "cowrie.login.failed",
            "src_ip": "198.51.100.7", "srcport": 40001,
            "dstport": 22, "username": "root", "password": "123456",
            "timestamp": "2026-02-01T10:11:12.123456Z",
        }
        raw = parse_cowrie_json(obj)
        self.assertIsNotNone(raw)
        self.assertEqual(raw["event_type"], "login_attempt")
        self.assertEqual(raw["username"], "root")
        self.assertEqual(raw["password"], "123456")
        self.assertEqual(raw["service"], "ssh")

    def test_command_mapping(self):
        obj = {"eventid": "cowrie.command.input", "input": "uname -a",
               "src_ip": "198.51.100.7"}
        raw = parse_cowrie_json(obj)
        self.assertEqual(raw["event_type"], "command")
        self.assertEqual(raw["payload"], "uname -a")

    def test_unknown_event_returns_none(self):
        self.assertIsNone(parse_cowrie_json(
            {"eventid": "cowrie.client.version", "version": "SSH-2.0-X"}))


if __name__ == "__main__":
    unittest.main()
