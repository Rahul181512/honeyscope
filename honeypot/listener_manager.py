"""Listener Manager: starts/stops every decoy service and reports status."""

from __future__ import annotations

import threading
import time
from typing import Callable

from core.config import DEFAULTS
from core.collector import Collector
from .base_sensor import FtpSensor, TCPSensor, TelnetSensor
from .http_honeypot import HTTPHoneypot
from .ssh_honeypot import SSHHoneypot

SENSOR_LABELS = {
    1433: "MSSQL probe sensor", 2375: "Docker API sensor", 3000: "Dev-server sensor",
    3306: "MySQL probe sensor", 3389: "RDP probe sensor", 5000: "UPnP/Flask sensor",
    5432: "PostgreSQL sensor", 5900: "VNC probe sensor", 6379: "Redis sensor",
    8000: "HTTP-alt sensor", 8009: "AJP/Tomcat sensor", 8081: "HTTP-alt sensor",
    8443: "HTTPS-alt sensor", 9000: "Hadoop/FastCGI sensor",
    9042: "Cassandra sensor", 9200: "Elasticsearch sensor",
    11211: "Memcached sensor", 27017: "MongoDB sensor",
}


class ListenerManager:
    def __init__(self, cfg: dict, collector: Collector):
        self.cfg = cfg
        self.collector = collector
        self.components: list = []
        self.build_errors: list[str] = []
        self.started_at: float | None = None
        self._build()

    def _emit(self) -> Callable[[dict], None]:
        return self.collector.collect

    def _build(self) -> None:
        bind = self.cfg.get("bind_host", DEFAULTS["bind_host"])
        services = {**DEFAULTS["services"], **self.cfg.get("services", {})}
        emit = self._emit()

        def _add(factory, label):
            try:
                self.components.append(factory())
            except OSError as exc:
                self.build_errors.append(f"{label}: {exc}")

        ssh = services.get("ssh", {})
        if ssh.get("enabled"):
            _add(lambda: SSHHoneypot(
                int(ssh.get("port", 2222)), emit, bind,
                accept_any_credentials=bool(ssh.get(
                    "accept_any_credentials", False))),
                f"SSH decoy :{ssh.get('port', 2222)}")

        http = services.get("http", {})
        if http.get("enabled"):
            _add(lambda: HTTPHoneypot(int(http.get("port", 8081)), emit, bind),
                 f"HTTP decoy :{http.get('port', 8081)}")

        ftp = services.get("ftp", {})
        if ftp.get("enabled"):
            _add(lambda: FtpSensor(int(ftp.get("port", 2121)), emit, bind),
                 f"FTP decoy :{ftp.get('port', 2121)}")

        telnet = services.get("telnet", {})
        if telnet.get("enabled"):
            _add(lambda: TelnetSensor(int(telnet.get("port", 2323)), emit, bind),
                 f"Telnet decoy :{telnet.get('port', 2323)}")

        for port in self.cfg.get("sensor_ports", DEFAULTS["sensor_ports"]):
            label = SENSOR_LABELS.get(int(port), f"TCP sensor :{port}")
            _add(lambda p=int(port), l=label: TCPSensor(l, p, emit, bind),
                 f"{label} :{port}")

    # ---------------------------------------------------------------- control
    def start_all(self) -> list[str]:
        errors = list(self.build_errors)
        for comp in self.components:
            try:
                comp.start()
            except OSError as exc:
                errors.append(f"{comp.label} (:{comp.port}): {exc}")
        self.started_at = time.time()
        return errors

    def stop_all(self) -> None:
        for comp in self.components:
            try:
                comp.stop()
            except Exception:
                pass

    # ----------------------------------------------------------------- status
    def status(self) -> dict:
        return {
            "uptime_seconds": round(time.time() - self.started_at)
            if self.started_at else 0,
            "listeners": [
                {
                    "name": getattr(comp, "label", comp.service_name),
                    "service": comp.service_name,
                    "port": comp.port,
                    "running": comp.is_alive(),
                    "connections_seen": getattr(comp, "connections_seen", None),
                    "error": getattr(comp, "bind_error", None),
                }
                for comp in self.components
            ],
        }
