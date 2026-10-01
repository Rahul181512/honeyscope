"""Collection pipeline: raw event -> normalize -> score -> enrich -> store."""

from __future__ import annotations

from typing import Callable, Optional

from . import geoip, parser, threat_scoring


class Collector:
    """Single funnel through which every captured interaction passes."""

    def __init__(self, db, raw_writer: Optional[parser.RawLogWriter] = None,
                 window_minutes: int = 10, geo_enabled: bool = False,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.db = db
        self.raw_writer = raw_writer
        self.window_minutes = window_minutes
        self.geo_enabled = geo_enabled
        self.on_alert = on_alert          # called for HIGH / CRITICAL events

    def collect(self, raw: dict) -> Optional[dict]:
        try:
            ev = parser.normalize(raw)
        except (ValueError, TypeError):
            return None

        history = self.db.recent_for_ip(ev["src_ip"],
                                        minutes=self.window_minutes,
                                        before_epoch=ev.get("epoch"))
        score, severity, pattern = threat_scoring.evaluate(ev, history)
        ev["score"] = score
        ev["severity"] = severity
        ev["attack_pattern"] = pattern

        ev = geoip.enrich(ev, self.db, enabled=self.geo_enabled)

        if self.raw_writer is not None:
            audit = {k: v for k, v in ev.items() if not k.startswith("_")}
            try:
                self.raw_writer.write(audit)
            except OSError:
                pass

        ev["id"] = self.db.insert_event(ev)

        if severity in ("HIGH", "CRITICAL") and self.on_alert:
            try:
                self.on_alert(ev)
            except Exception:
                pass
        return ev
