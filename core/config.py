"""Central configuration for the HoneyScope project.

Configuration priority (lowest -> highest):
    1. DEFAULTS below
    2. optional ``config.json`` in the project root
    3. environment variables ``HONEYPOT_DB_PATH``, ``HONEYPOT_GEO_LOOKUP_ENABLED``
"""

from __future__ import annotations

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORT_OUT_DIR = BASE_DIR / "reports" / "out"
CHART_JS_PATH = BASE_DIR / "dashboard" / "static" / "vendor" / "chart.umd.min.js"

DEFAULTS: dict = {
    "title": "HoneyScope",
    "db_path": str(DATA_DIR / "honeypot.db"),
    "raw_log_path": str(LOG_DIR / "raw_events.jsonl"),
    "bind_host": "127.0.0.1",           # safest default: loopback only
    "services": {
        "ssh":    {"enabled": True, "port": 2222, "accept_any_credentials": False},
        "http":   {"enabled": True, "port": 8081},
        "ftp":    {"enabled": True, "port": 2121},
        "telnet": {"enabled": True, "port": 2323},
    },
    # Silent TCP sensors: any connection is recorded as a port-probe event.
    # All ports are >1024 so the lab runs WITHOUT administrator/root rights.
    "sensor_ports": [
        1433, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
        8000, 8009, 8443, 9000, 9042, 9200, 11211, 27017,
    ],
    "geo_lookup_enabled": False,        # privacy: online lookups are OFF by default
    "brute_force_window_minutes": 10,
    "scan_window_minutes": 10,
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | os.PathLike | None = None) -> dict:
    """Load merged configuration."""
    cfg = _deep_merge(DEFAULTS, {})
    candidates = [Path(path)] if path else [BASE_DIR / "config.json"]
    for cand in candidates:
        if cand and Path(cand).exists():
            with open(cand, "r", encoding="utf-8") as fh:
                cfg = _deep_merge(cfg, json.load(fh))
    if os.environ.get("HONEYPOT_DB_PATH"):
        cfg["db_path"] = os.environ["HONEYPOT_DB_PATH"]
    if os.environ.get("HONEYPOT_GEO_LOOKUP_ENABLED"):
        cfg["geo_lookup_enabled"] = os.environ[
            "HONEYPOT_GEO_LOOKUP_ENABLED"
        ].lower() in ("1", "true", "yes")
    if os.environ.get("HONEYPOT_BIND_HOST"):
        cfg["bind_host"] = os.environ["HONEYPOT_BIND_HOST"]
    return cfg


def ensure_dirs() -> None:
    """Create runtime directories (data, logs, report output)."""
    for d in (DATA_DIR, LOG_DIR, REPORT_OUT_DIR):
        d.mkdir(parents=True, exist_ok=True)
