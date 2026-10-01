# User Guide

## 1. Prerequisites

- Python 3.10+ (developed on 3.14)
- pip
- Any OS (macOS / Linux / Windows). No admin/root rights needed with default ports.

## 2. Installation

```bash
cd honeypot-dashboard
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Dependencies: `flask` (dashboard), `paramiko` (real SSH handshakes),
`requests` (optional geolocation).

## 3. First run

```bash
python run.py
```

You should see:

```
[+] Decoy services listening:
    [+] SSH decoy                    :2222
    [+] HTTP decoy                   :8081
    ...
[+] Dashboard ready:  http://127.0.0.1:5555
```

Open http://127.0.0.1:5555 in a browser.

> The dashboard is empty at first — that's normal. Load demo data or run the
> simulator below.

## 4. Instant demo dataset (no network activity)

```bash
python scripts/seed_demo_data.py --wipe --hours 72
```

Inserts ~700 synthetic events spread over 72 hours through the *real*
scoring pipeline, so severities and patterns behave exactly like live data.
Country labels are hard-coded demo values; no online lookup happens.

To start clean again: `python run.py --mode reset-db`.

## 5. Attacking your own decoys

### Built-in simulator (safest)

```bash
python scripts/simulate_attacks.py --all            # every scenario
python scripts/simulate_attacks.py --scenario ssh   # SSH brute force only
python scripts/simulate_attacks.py --scenario web   # SQLi/XSS/traversal
```

The simulator refuses non-local targets unless you pass
`--i-own-this-network`.

Expected dashboard results:

| Scenario | What appears |
|---|---|
| port-scan | `port_probe` events on many sensors → `port_scan` pattern |
| ssh | escalating `login_attempt` events → `brute_force`, later CRITICAL |
| stuffing | 8+ distinct usernames vs `/login` → `credential_stuffing` |
| web | `sql_injection`, `xss`, `path_traversal`, `webshell_probing` events |
| ftp / telnet | credential attempts from those decoys |

### External tools (authorized lab only)

```bash
nmap -p 1433,2375,3000,3306,3389,5000,5432,5900,6379,8000,8009,8443,9000,9042,9200,11211,27017 127.0.0.1
curl "http://127.0.0.1:8081/product.php?id=1'%20OR%20'1'='1"
hydra -l root -P rockyou.txt 127.0.0.1 -s 2222 ssh -t 4   # if installed
```

## 6. Using the dashboard

- **Overview** refreshes itself every 5 seconds.
- **Events**: search box accepts IPs, usernames, payload fragments;
  combine with severity/service/pattern filters. Click a row for full detail.
- **Attacker Intel**: shows private ranges labelled locally (🏠); public IPs
  show 🌍 + country when geolocation is enabled.
- **Security Report**: click *Generate report now*, then open the HTML file
  (works offline; print to PDF for submission).

## 7. Capturing interactive commands (advanced)

By default the SSH decoy rejects all passwords (observation-only mode).
To also capture what attackers type after a "successful" login, set in
`config.json`:

```json
{ "services": { "ssh": { "accept_any_credentials": true } } }
```

The decoy then serves a sandboxed fake shell whose replies are hard-coded
strings. Commands such as `whoami`, `uname -a`, `wget …` are logged as
`command` events. **Nothing is ever executed** — there is no subprocess or
eval anywhere in the code.

## 8. Importing external logs

```bash
# replay your own raw audit trail into a fresh database
python run.py --mode import --file logs/raw_events.jsonl --format raw

# import a Cowrie honeypot JSON log
python run.py --mode import --file cowrie.json --format cowrie

# import Linux auth.log style SSH failures
python run.py --mode import --file /var/log/auth.log --format authlog
```

## 9. Enabling public-IP geolocation

Set `"geo_lookup_enabled": true` (or env `HONEYPOT_GEO_LOOKUP_ENABLED=1`).
Public attacker IPs are looked up via the free ip-api.com endpoint and cached
in SQLite. Private/lab addresses never trigger network calls.

## 10. Backups & reset

Everything lives in three folders: `data/` (SQLite), `logs/` (raw JSONL),
`reports/out/`. Copy them to back up; delete `data/honeypot.db*` or use
`--mode reset-db` to start fresh.

## 11. Docker

```bash
docker compose up --build      # dashboard on :5555
```
