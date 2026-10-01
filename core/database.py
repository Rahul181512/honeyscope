"""Storage layer: SQLite database for security events and per-IP intelligence."""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from . import threat_scoring

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    epoch           REAL NOT NULL,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    username        TEXT,
    password        TEXT,
    payload         TEXT,
    user_agent      TEXT,
    severity        TEXT DEFAULT 'LOW',
    score           REAL DEFAULT 0,
    attack_pattern  TEXT DEFAULT 'unknown',
    geo_country     TEXT,
    geo_city        TEXT,
    geo_asn         TEXT,
    geo_lat         REAL,
    geo_lon         REAL
);
CREATE INDEX IF NOT EXISTS idx_events_epoch   ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_sev     ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
CREATE TABLE IF NOT EXISTS ip_meta (
    ip               TEXT PRIMARY KEY,
    first_seen       TEXT,
    last_seen        TEXT,
    total_events     INTEGER DEFAULT 0,
    max_severity     TEXT DEFAULT 'LOW',
    is_private       INTEGER DEFAULT 0,
    country          TEXT,
    city             TEXT,
    asn              TEXT,
    lat              REAL,
    lon              REAL
);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    """Thread-safe SQLite wrapper (single shared connection + RLock + WAL)."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ write
    def insert_event(self, ev: dict) -> int:
        """Insert one normalized event and update per-IP metadata."""
        if not ev.get("ts"):
            ev["ts"] = utc_now_iso()
        if not ev.get("epoch"):
            ev["epoch"] = time.time()
        ev.setdefault("protocol", "tcp")
        ev.setdefault("service", "other")
        ev.setdefault("event_type", "connection")
        ev.setdefault("severity", "LOW")
        ev.setdefault("score", 0)
        ev.setdefault("attack_pattern", "unknown")

        cols = ("ts", "epoch", "src_ip", "src_port", "dst_port", "protocol",
                "service", "event_type", "username", "password", "payload",
                "user_agent", "severity", "score", "attack_pattern",
                "geo_country", "geo_city", "geo_asn", "geo_lat", "geo_lon")
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO events ({', '.join(cols)}) "
                f"VALUES ({', '.join('?' for _ in cols)})",
                [ev.get(c) for c in cols],
            )
            self._touch_ip_meta(ev)
            self._conn.commit()
            return int(cur.lastrowid)

    def insert_events(self, events: list[dict]) -> int:
        n = 0
        for ev in events:
            try:
                self.insert_event(ev)
                n += 1
            except Exception:
                continue
        return n

    def _touch_ip_meta(self, ev: dict) -> None:
        ip = ev["src_ip"]
        rank = threat_scoring.SEVERITY_RANK.get(ev.get("severity", "LOW"), 0)
        row = self._conn.execute(
            "SELECT max_severity, is_private, country, city, asn, lat, lon"
            " FROM ip_meta WHERE ip=?",
            (ip,),
        ).fetchone()
        private_flag = 1 if ev.get("_is_private") else 0
        if row is None:
            self._conn.execute(
                "INSERT INTO ip_meta (ip, first_seen, last_seen, total_events,"
                " max_severity, is_private, country, city, asn, lat, lon)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ip, ev["ts"], ev["ts"], 1, ev.get("severity", "LOW"),
                 private_flag, ev.get("geo_country"), ev.get("geo_city"),
                 ev.get("geo_asn"), ev.get("geo_lat"), ev.get("geo_lon")),
            )
        else:
            prev_rank = threat_scoring.SEVERITY_RANK.get(row["max_severity"] or "LOW", 0)
            worst = ev.get("severity", "LOW") if rank >= prev_rank else row["max_severity"]
            self._conn.execute(
                "UPDATE ip_meta SET last_seen=?, total_events=total_events+1,"
                " max_severity=?,"
                " country=COALESCE(?, country), city=COALESCE(?, city),"
                " asn=COALESCE(?, asn), lat=COALESCE(?, lat), lon=COALESCE(?, lon)"
                " WHERE ip=?",
                (ev["ts"], worst, ev.get("geo_country"), ev.get("geo_city"),
                 ev.get("geo_asn"), ev.get("geo_lat"), ev.get("geo_lon"), ip),
            )

    # ------------------------------------------------------------------- read
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return dict(row)

    def recent_for_ip(self, ip: str, minutes: int = 10,
                      limit: int = 300,
                      before_epoch: float | None = None) -> list[dict]:
        """Recent events from *ip* inside a sliding window.

        The window is anchored to ``before_epoch`` when given (so imported /
        replayed historical logs are scored against their own era), otherwise
        to the current wall clock.
        """
        reference = before_epoch if before_epoch is not None else time.time()
        cutoff = reference - minutes * 60
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_type, dst_port, username, payload FROM events"
                " WHERE src_ip=? AND epoch>? AND epoch<=?"
                " ORDER BY epoch DESC LIMIT ?",
                (ip, cutoff, reference, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def query_events(self, q: str | None = None, severity: str | None = None,
                     service: str | None = None, pattern: str | None = None,
                     ip: str | None = None, page: int = 1,
                     per_page: int = 50) -> tuple[list[dict], int]:
        where, params = [], []
        if q:
            like = f"%{q}%"
            where.append("(src_ip LIKE ? OR username LIKE ? OR password LIKE ?"
                         " OR payload LIKE ? OR user_agent LIKE ?"
                         " OR event_type LIKE ? OR attack_pattern LIKE ?)")
            params += [like] * 7
        if severity:
            where.append("severity=?")
            params.append(severity.upper())
        if service:
            where.append("service=?")
            params.append(service.lower())
        if pattern:
            where.append("attack_pattern=?")
            params.append(pattern.lower())
        if ip:
            where.append("src_ip=?")
            params.append(ip)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        page = max(1, int(page))
        per_page = min(500, max(1, int(per_page)))

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM events {clause}", params
            ).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM events {clause} ORDER BY epoch DESC LIMIT ? OFFSET ?",
                params + [per_page, (page - 1) * per_page],
            ).fetchall()
        return [dict(r) for r in rows], total

    def get_event(self, event_id: int) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return dict(row) if row else None

    def distinct(self, column: str) -> list[str]:
        assert column in ("severity", "service", "attack_pattern", "event_type")
        with self._lock:
            rows = self._conn.execute(
                f"SELECT DISTINCT {column} AS v FROM events ORDER BY v").fetchall()
        return [r["v"] for r in rows if r["v"]]

    def stats(self) -> dict:
        now = time.time()
        with self._lock:
            c = self._conn
            total = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            ips = c.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
            last24 = c.execute(
                "SELECT COUNT(*) FROM events WHERE epoch>?", (now - 86400,)
            ).fetchone()[0]
            creds = c.execute(
                "SELECT COUNT(*) FROM events WHERE username IS NOT NULL"
                " AND username != ''").fetchone()[0]
            cmds = c.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='command'"
            ).fetchone()[0]
            def grouped(col):
                return {r[0]: r[1] for r in c.execute(
                    f"SELECT {col}, COUNT(*) FROM events GROUP BY {col}")}
            by_severity = grouped("severity")
            by_service = grouped("service")
            by_pattern = grouped("attack_pattern")
        return {
            "total_events": total,
            "unique_ips": ips,
            "events_last_24h": last24,
            "credentials_captured": creds,
            "commands_captured": cmds,
            "by_severity": by_severity,
            "by_service": by_service,
            "by_pattern": by_pattern,
            "critical_events": by_severity.get("CRITICAL", 0),
        }

    def timeline(self, hours: int = 48, buckets: int = 48) -> list[dict]:
        """Bucketed event counts (with CRITICAL sub-count) for charts."""
        cutoff = time.time() - hours * 3600
        with self._lock:
            rows = self._conn.execute(
                "SELECT epoch, severity FROM events WHERE epoch>? ORDER BY epoch",
                (cutoff,)).fetchall()
        span = hours * 3600 / max(1, buckets)
        edges = [cutoff + i * span for i in range(buckets + 1)]
        out = [{"start": e, "count": 0, "critical": 0} for e in edges[:-1]]
        for row in rows:
            idx = int((row["epoch"] - cutoff) // span)
            if 0 <= idx < buckets:
                out[idx]["count"] += 1
                if row["severity"] == "CRITICAL":
                    out[idx]["critical"] += 1
        for item in out:
            item["label"] = datetime.fromtimestamp(
                item.pop("start"), tz=timezone.utc).strftime("%d %b %H:%M")
        return out

    def top_ips(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT src_ip AS ip, COUNT(*) AS count,"
                " MAX(CASE severity WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2"
                "     WHEN 'MEDIUM' THEN 1 ELSE 0 END) AS rank,"
                " MAX(ts) AS last_seen"
                " FROM events GROUP BY src_ip ORDER BY count DESC LIMIT ?",
                (limit,)).fetchall()
            meta = {r["ip"]: dict(r)
                    for r in self._conn.execute("SELECT * FROM ip_meta")}
        sev_by_rank = {v: k for k, v in threat_scoring.SEVERITY_RANK.items()}
        out = []
        for r in rows:
            m = meta.get(r["ip"], {})
            out.append({
                "ip": r["ip"], "count": r["count"],
                "max_severity": sev_by_rank.get(r["rank"], "LOW"),
                "last_seen": r["last_seen"],
                "country": m.get("country"),
                "city": m.get("city"),
                "is_private": bool(m.get("is_private")),
                "asn": m.get("asn"),
            })
        return out

    def _top_field(self, field: str, limit: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {field} AS value, COUNT(*) AS count,"
                " COUNT(DISTINCT src_ip) AS sources"
                f" FROM events WHERE {field} IS NOT NULL AND {field} != ''"
                f" GROUP BY {field} ORDER BY count DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def top_usernames(self, limit: int = 15) -> list[dict]:
        return self._top_field("username", limit)

    def top_passwords(self, limit: int = 15) -> list[dict]:
        return self._top_field("password", limit)

    def credential_combos(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT username, password, COUNT(*) AS count,"
                " COUNT(DISTINCT src_ip) AS sources"
                " FROM events WHERE username != '' AND username IS NOT NULL"
                " GROUP BY username, password ORDER BY count DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def ip_intel(self, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM ip_meta ORDER BY total_events DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def ip_meta_get(self, ip: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ip_meta WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def ip_meta_set_geo(self, ip: str, country: str, city: str, asn: str,
                        lat: float, lon: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE ip_meta SET country=?, city=?, asn=?, lat=?, lon=?"
                " WHERE ip=?", (country, city, asn, lat, lon, ip))
            self._conn.commit()

    def export_all(self) -> Iterator[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY epoch DESC").fetchall()
        yield from (dict(r) for r in rows)

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ------------------------------------------------------------------ admin
    def reset(self) -> None:
        with self._lock:
            self._conn.executescript(
                "DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS ip_meta;")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
