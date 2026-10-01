"""Unit + integration tests for the storage layer and collection pipeline."""

import tempfile
import time
import unittest
from pathlib import Path

from core.collector import Collector
from core.database import Database


def login(user="root", password="toor", ip="203.0.113.10", port=2222):
    return {"service": "ssh", "event_type": "login_attempt",
            "src_ip": ip, "src_port": 40000, "dst_port": port,
            "username": user, "password": password}


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_insert_and_query(self):
        self.db.insert_event({"src_ip": "1.1.1.1", "service": "http",
                              "event_type": "http_request",
                              "payload": "GET /"})
        rows, total = self.db.query_events(service="http")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["src_ip"], "1.1.1.1")

    def test_search_filter(self):
        self.db.insert_event({"src_ip": "9.9.9.9", "username": "neo"})
        self.db.insert_event({"src_ip": "8.8.8.8", "username": "trinity"})
        rows, total = self.db.query_events(q="trinity")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["src_ip"], "8.8.8.8")

    def test_severity_filter_and_pagination(self):
        for i in range(7):
            self.db.insert_event({"src_ip": f"10.0.0.{i}",
                                  "severity": "HIGH" if i < 2 else "LOW",
                                  "epoch": time.time() + i})
        rows, total = self.db.query_events(severity="HIGH")
        self.assertEqual(total, 2)
        page1, _ = self.db.query_events(per_page=3, page=1)
        page2, _ = self.db.query_events(per_page=3, page=2)
        self.assertEqual(len(page1), 3)
        self.assertEqual(page1[0]["id"], page2[0]["id"] + 3)  # newest first

    def test_recent_for_ip_window(self):
        old = {"src_ip": "5.5.5.5", "event_type": "login_attempt",
               "epoch": time.time() - 3600}
        fresh = {"src_ip": "5.5.5.5", "event_type": "login_attempt"}
        other = {"src_ip": "6.6.6.6", "event_type": "login_attempt"}
        for ev in (old, fresh, other):
            self.db.insert_event(ev)
        hist = self.db.recent_for_ip("5.5.5.5", minutes=10)
        self.assertEqual(len(hist), 1)          # only the fresh one

    def test_top_usernames(self):
        for _ in range(3):
            self.db.insert_event(login(user="root"))
        self.db.insert_event(login(user="admin"))
        top = self.db.top_usernames(5)
        self.assertEqual(top[0]["value"], "root")
        self.assertEqual(top[0]["count"], 3)

    def test_ip_meta_tracking(self):
        self.db.insert_event({"src_ip": "7.7.7.7", "severity": "LOW"})
        self.db.insert_event({"src_ip": "7.7.7.7", "severity": "CRITICAL"})
        meta = self.db.ip_meta_get("7.7.7.7")
        self.assertEqual(meta["total_events"], 2)
        self.assertEqual(meta["max_severity"], "CRITICAL")

    def test_stats_and_timeline(self):
        for i in range(4):
            self.db.insert_event({"src_ip": f"11.0.0.{i}"})
        stats = self.db.stats()
        self.assertEqual(stats["total_events"], 4)
        self.assertEqual(stats["unique_ips"], 4)
        tl = self.db.timeline(hours=48, buckets=24)
        self.assertEqual(len(tl), 24)

    def test_reset(self):
        self.db.insert_event({"src_ip": "2.2.2.2"})
        self.db.reset()
        self.assertEqual(self.db.count(), 0)


class TestCollectorPipeline(unittest.TestCase):
    """End-to-end: normalize -> score -> store through Collector."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "pipeline.db")
        self.collector = Collector(self.db, raw_writer=None,
                                   window_minutes=10)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_bruteforce_escalates_across_events(self):
        sev_seen = []
        for user in ("admin", "test", "ubuntu", "pi", "oracle"):
            ev = self.collector.collect(
                login(user=user, ip="198.51.100.77"))
            sev_seen.append((ev["severity"], ev["attack_pattern"]))
        # first event LOW/unknown, later events escalate to brute_force
        self.assertEqual(sev_seen[0][1], "unknown")
        final_score = self.db.stats()["by_severity"]
        # the 5th consecutive failure crosses the MEDIUM threshold
        self.assertGreaterEqual(final_score.get("MEDIUM", 0), 1)
        patterns = {p: c for p, c in
                    self.db.stats().get("by_pattern", {}).items()}
        self.assertIn("brute_force", patterns)
        self.assertGreater(patterns["brute_force"], 0)

    def test_private_ip_labelled_without_network(self):
        ev = self.collector.collect(
            {"service": "http", "src_ip": "127.0.0.1",
             "event_type": "http_request", "dst_port": 8080,
             "payload": "GET / HTTP/1.1"})
        self.assertEqual(ev["geo_country"], "Loopback (local machine)")

    def test_alert_hook_fires_on_high(self):
        fired = []
        collector = Collector(self.db, raw_writer=None,
                              window_minutes=10,
                              on_alert=lambda ev: fired.append(ev))
        for i in range(6):
            collector.collect(login(user=f"u{i}", ip="203.0.113.200"))
        self.assertTrue(fired)
        self.assertIn(fired[-1]["severity"], ("HIGH", "CRITICAL"))

    def test_invalid_event_rejected(self):
        self.assertIsNone(self.collector.collect({"no_src_ip": True}))

    def test_historical_replay_scores_correctly(self):
        """Events replayed from old logs must escalate against their own era."""
        base = time.time() - 7200          # two hours ago
        severities = []
        for i in range(6):
            raw = login(user=f"u{i}", ip="203.0.113.90")
            raw["epoch"] = base + i * 30
            ev = self.collector.collect(raw)
            severities.append(ev["severity"])
        self.assertEqual(severities[0], "LOW")
        self.assertIn(severities[-1], ("MEDIUM", "HIGH", "CRITICAL"))


if __name__ == "__main__":
    unittest.main()
