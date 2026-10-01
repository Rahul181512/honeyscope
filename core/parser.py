"""Log Parser / Normalizer Module.

Responsibilities:
  * ``normalize()``   - turn any raw honeypot event dict into a validated,
                        structured record ready for scoring + storage;
  * ``RawLogWriter``  - append every raw interaction to a JSONL file
                        (logs/raw_events.jsonl) for replay/audit;
  * importers for external formats: our own JSONL replay, Cowrie JSON logs,
    and Linux auth.log style SSH failure lines.
"""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

MAX_PAYLOAD = 4096
MAX_STR = 256


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value, limit: int = MAX_STR) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def normalize(raw: dict) -> dict:
    """Validate/coerce a raw event into a structured record."""
    ev = {
        "ts": None,
        "epoch": None,
        "src_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "tcp",
        "service": "other",
        "event_type": "connection",
        "username": None,
        "password": None,
        "payload": None,
        "user_agent": None,
        # geo fields may arrive pre-attached (imports / offline seeding)
        "geo_country": None,
        "geo_city": None,
        "geo_asn": None,
        "geo_lat": None,
        "geo_lon": None,
    }
    ev.update({k: v for k, v in (raw or {}).items() if k in ev})

    if not ev.get("ts"):
        ev["ts"] = utc_now_iso()
    if not ev.get("epoch"):
        try:
            dt = datetime.strptime(ev["ts"], "%Y-%m-%dT%H:%M:%SZ")
            ev["epoch"] = dt.replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            ev["epoch"] = time.time()

    if not _clean(ev.get("src_ip")):
        raise ValueError("event is missing src_ip")
    ev["src_ip"] = str(ev["src_ip"])[:64]
    ev["src_port"] = int(ev.get("src_port") or 0) or None
    ev["dst_port"] = int(ev.get("dst_port") or 0) or None
    ev["protocol"] = (_clean(ev.get("protocol"), 16) or "tcp").lower()
    ev["service"] = (_clean(ev.get("service"), 32) or "other").lower()
    ev["event_type"] = (_clean(ev.get("event_type"), 40)
                        or "connection").lower()
    ev["username"] = _clean(ev.get("username"), 128)
    ev["password"] = _clean(ev.get("password"), 128)
    ev["user_agent"] = _clean(ev.get("user_agent"), 256)
    payload = _clean(ev.get("payload"), MAX_PAYLOAD)
    ev["payload"] = payload
    return ev


class RawLogWriter:
    """Thread-safe JSONL writer for raw interaction logs."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, default=str)
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def iter_raw_log(path: str | Path) -> Iterator[dict]:
    """Yield events from one of our JSONL raw log files."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


# --------------------------------------------------------------------------
# External format importers
# --------------------------------------------------------------------------
_COWRIE_LOGIN_FAILED = ("cowrie.login.failed",)
_COWRIE_LOGIN_SUCCESS = ("cowrie.login.success",)
_COWRIE_COMMAND = ("cowrie.command.input",)

_AUTH_LOG_RX = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2")


def parse_cowrie_json(obj: dict) -> Optional[dict]:
    """Map one Cowrie JSON log entry onto our normalized schema."""
    eventid = obj.get("eventid", "")
    ts = obj.get("timestamp")
    base = {
        "service": "ssh",
        "protocol": "tcp",
        "dst_port": obj.get("dstport"),
        "src_ip": obj.get("src_ip"),
        "src_port": obj.get("srcport"),
    }
    if ts:
        base["ts"] = str(ts)[:19].replace("T", ":") and \
            _to_iso(str(ts))
    if eventid in _COWRIE_LOGIN_FAILED or eventid in _COWRIE_LOGIN_SUCCESS:
        base.update({
            "event_type": ("login_success" if eventid in _COWRIE_LOGIN_SUCCESS
                           else "login_attempt"),
            "username": obj.get("username"),
            "password": obj.get("password"),
        })
        return base
    if eventid in _COWRIE_COMMAND:
        base.update({"event_type": "command",
                     "payload": obj.get("input") or obj.get("command")})
        return base
    if eventid.startswith("cowrie.connection"):
        base.setdefault("event_type", "connection")
        return base
    return None


def _to_iso(ts: str) -> str:
    """'2024-02-01T10:11:12.123456Z' / '+0530' variants -> ISO UTC Z string."""
    text = ts.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(text.split("+")[0].split("-0")[0][:26], fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return utc_now_iso()


def parse_auth_log_line(line: str) -> Optional[dict]:
    """Parse 'Failed password for user from IP port N ssh2' lines."""
    match = _AUTH_LOG_RX.search(line)
    if not match:
        return None
    year = datetime.now(timezone.utc).year
    hh, mm, ss = match.group("time").split(":")
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    month = months.index(match.group("month")) + 1
    iso = f"{year:04d}-{month:02d}-{int(match.group('day')):02d}T{hh}:{mm}:{ss}Z"
    return {
        "service": "ssh",
        "event_type": "login_attempt",
        "username": match.group("user"),
        "src_ip": match.group("ip"),
        "src_port": int(match.group("port")),
        "ts": iso,
        "payload": line.strip()[:MAX_PAYLOAD],
    }
