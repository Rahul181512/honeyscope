#!/usr/bin/env python3
"""HoneyScope - Honeypot with Attack Visualization Dashboard.

Main entry point. Starts any combination of:
  * decoy services (SSH / HTTP / FTP / Telnet + TCP probe sensors),
  * the Flask visualization dashboard,
and provides CLI helpers (reset database, import external logs).

Usage:
    python run.py                       # decoys + dashboard together
    python run.py --mode dashboard      # dashboard only
    python run.py --mode honeypot       # decoys only
    python run.py --mode reset-db       # wipe the SQLite database
    python run.py --mode import --file logs/raw_events.jsonl --format raw
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time

from core import config
from core.collector import Collector
from core.database import Database
from core.parser import (RawLogWriter, iter_raw_log, parse_auth_log_line,
                         parse_cowrie_json)

TITLE = r"""
 _   _                        ___  ___
| | | | ___  _ __   ___  _ __ / _ \/ __|
| |_| |/ _ \| '_ \ / _ \| '_ \ (_) \__ \
|  _  | (_) | | | | (_) | | | |\__, |___/
|_| |_|\___/|_| |_|\___/|_| |_|  /_/
     Honeypot + Attack Visualization Dashboard   v1.0.0
"""

ETHICS_NOTICE = """
[!] ETHICS NOTICE
    Honeypot decoys are defensive research tools. Only deploy them on
    machines/networks you own or are explicitly authorised to monitor.
"""


def alert_console(ev: dict) -> None:
    """Console hook for HIGH/CRITICAL events."""
    print(f"  [!] {ev['ts']} {ev['severity']:<8} {ev['src_ip']}:{ev.get('src_port')}"
          f" -> :{ev.get('dst_port')} [{ev['service']}/{ev['event_type']}]"
          f" pattern={ev['attack_pattern']} score={ev['score']}", flush=True)


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback
    except (socket.gaierror, ValueError):
        return False


def do_import(collector: Collector, path: str, fmt: str) -> None:
    count = skipped = 0
    for obj in iter_raw_log(path):
        if fmt == "cowrie":
            raw = parse_cowrie_json(obj)
        elif fmt == "authlog":
            continue  # handled below (line-based)
        else:
            raw = obj
        if raw and collector.collect(raw):
            count += 1
        else:
            skipped += 1
    if fmt == "authlog":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                raw = parse_auth_log_line(line)
                if raw and collector.collect(raw):
                    count += 1
                else:
                    skipped += 1
    print(f"[+] Imported {count} events from {path}"
          f" ({skipped} skipped/unrecognised).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="run.py",
        description="HoneyScope honeypot + attack visualization dashboard")
    ap.add_argument("--mode", default="all",
                    choices=["all", "honeypot", "dashboard",
                             "reset-db", "import"],
                    help="what to run (default: all)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="dashboard bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5555,
                    help="dashboard port (default: 5555)")
    ap.add_argument("--ssh-port", type=int, default=None,
                    help="override decoy SSH port")
    ap.add_argument("--http-port", type=int, default=None,
                    help="override decoy HTTP port")
    ap.add_argument("--ftp-port", type=int, default=None,
                    help="override decoy FTP port")
    ap.add_argument("--telnet-port", type=int, default=None,
                    help="override decoy Telnet port")
    ap.add_argument("--config", default=None,
                    help="optional path to config.json")
    ap.add_argument("--i-own-this-network", action="store_true",
                    help="required consent flag when binding non-loopback "
                         "interfaces (see docs/ethics_and_safety.md)")
    ap.add_argument("--file", help="log file to import (with --mode import)")
    ap.add_argument("--format", default="raw",
                    choices=["raw", "cowrie", "authlog"],
                    help="import format (default: raw JSONL)")
    args = ap.parse_args(argv)

    cfg = config.load_config(args.config)
    for svc, flag in (("ssh", "ssh_port"), ("http", "http_port"),
                      ("ftp", "ftp_port"), ("telnet", "telnet_port")):
        override = getattr(args, flag)
        if override:
            cfg["services"][svc]["port"] = override
    config.ensure_dirs()

    print(TITLE)

    if args.mode == "reset-db":
        Database(cfg["db_path"]).reset()
        print(f"[+] Database reset: {cfg['db_path']}")
        return 0

    db = Database(cfg["db_path"])
    collector = Collector(
        db,
        raw_writer=RawLogWriter(cfg["raw_log_path"]),
        window_minutes=cfg["brute_force_window_minutes"],
        geo_enabled=cfg["geo_lookup_enabled"],
        on_alert=alert_console,
    )

    if args.mode == "import":
        if not args.file:
            print("[!] --file is required with --mode import")
            return 2
        do_import(collector, args.file, args.format)
        return 0

    manager = None
    if args.mode in ("all", "honeypot"):
        decoy_bind = cfg["bind_host"]
        if not is_loopback(decoy_bind) and not args.i_own_this_network:
            print(ETHICS_NOTICE)
            print("[!] Refusing to expose honeypot decoys on a non-loopback "
                  "interface.\n    Re-run with --i-own-this-network to "
                  "confirm you are authorized.")
            return 3
        from honeypot.listener_manager import ListenerManager
        manager = ListenerManager(cfg, collector)
        errors = manager.start_all()
        status = manager.status()["listeners"]
        print("[+] Decoy services listening:")
        for l in status:
            marker = "+" if l["running"] else "-"
            print(f"    [{marker}] {l['name']:<26} :{l['port']}")
        for err in errors:
            print(f"    [x] {err}")

    try:
        if args.mode in ("all", "dashboard"):
            from dashboard import create_app
            app = create_app(db, manager=manager, cfg=cfg)
            print(f"[+] Dashboard ready:  http://{args.host}:{args.port}")
            print("    Pages: Overview / Events / Attacker Intel / "
                  "Credentials / Report")
            print(ETHICS_NOTICE)
            app.run(host=args.host, port=args.port,
                    debug=False, threaded=True)
        else:
            print("[+] Honeypot-only mode - press Ctrl+C to stop.")
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        if manager is not None:
            manager.stop_all()
        print("\n[+] Stopped gracefully. Data saved in "
              f"{cfg['db_path']}\n    Raw audit log: {cfg['raw_log_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
