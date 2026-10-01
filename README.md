# 🍯 HoneyScope — Honeypot with Attack Visualization Dashboard

**B.Tech Project · Cyber Security / Network Defense / Threat Intelligence**

HoneyScope is a low-cost, self-contained defensive security lab: a set of safe
decoy services (SSH, HTTP, FTP, Telnet + 17 TCP probe sensors) records
unauthorized access attempts in an isolated environment, a threat-scoring
engine classifies every event by severity and attack pattern, and a live web
dashboard visualizes attacker behaviour. A one-click generator produces a
self-contained HTML security report with charts and defensive recommendations.

Everything runs on a normal laptop — no paid cloud, no root access required.

---

## ✨ Features

| Synopsis Module | Implementation |
|---|---|
| **Honeypot Listener Module** | Paramiko-based SSH decoy (records auth attempts; optional sandboxed fake shell), fake router-admin HTTP decoy that captures credential-stuffing, FTP & Telnet decoys with real protocol conversations, silent TCP sensors on 17 common service ports |
| **Log Parser Module** | Every interaction normalized into structured events; raw JSONL audit trail (`logs/raw_events.jsonl`); importers for **Cowrie JSON logs** and **Linux auth.log** SSH failures; full replay support |
| **Threat Scoring Module** | Rule engine assigns score + severity (LOW/MEDIUM/HIGH/CRITICAL) and pattern labels: `brute_force`, `credential_stuffing`, `port_scan`, `sql_injection`, `xss`, `path_traversal`, `webshell_probing`, `scanner_tool` |
| **Dashboard Module** | Flask + Chart.js dark SOC theme: KPI cards, attack timeline, severity/service/pattern charts, top-attacker bar chart, searchable & filterable event table with detail modal, attacker IP intel table, top attempted usernames/passwords, live auto-refresh every 5 s |
| **Report Module** | Timestamped **fully self-contained HTML report** (Chart.js embedded — opens offline, prints to PDF), Markdown summary, CSV/JSON dataset export |

Extra engineering:

- 🔒 **Privacy-first geolocation** — private/loopback IPs labelled locally;
  public lookups (ip-api.com) are opt-in via config and cached.
- 🧯 **Ethical guardrail** — decoys refuse to bind non-loopback interfaces
  without an explicit `--i-own-this-network` consent flag.
- 💪 **Zero-friction lab** — all default ports >1024 (no admin rights),
  busy ports degrade gracefully and are reported on the dashboard,
  Chart.js is vendored so the dashboard works fully offline.

---

## 🚀 Quickstart

```bash
cd honeypot-dashboard

# 1. create a virtual environment (once)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. start everything (decoys + dashboard)
python run.py
```

Open **http://127.0.0.1:5555** — the dashboard starts **empty (0 events)**.
That is intentional: the project captures REAL attacks only, nothing is
pre-loaded.

### ▶️ Live demo (for teachers)

Run this while the dashboard is open — it performs real attacks against the
decoys and narrates each scenario as the dashboard updates live:

```bash
python scripts/live_demo.py        # interactive (press Enter between scenes)
```

Full walkthrough with talking points: **docs/demo_guide.md**.

Individual scenarios on demand:

```bash
python scripts/simulate_attacks.py --all             # every attack type at once
python scripts/simulate_attacks.py --scenario ssh    # just the SSH brute force
```

> `scripts/seed_demo_data.py` exists only for offline **synthetic** preview;
> it is never part of a live demo and is clearly labelled as fake.

---

## 🧭 Dashboard tour

| Page | What you see |
|---|---|
| **Overview** | KPI cards, 48-hour attack timeline, severity doughnut, service distribution, top-10 attacker IPs, attack-pattern ranking, live event feed, honeypot listener health |
| **Events** | Full event log: free-text search + severity/service/pattern filters, pagination, click any row for the complete record (credentials, payload, user-agent, geo) |
| **Attacker Intel** | Per-IP aggregation: location, ASN, totals, worst severity, first/last seen, one-click jump to that IP's log |
| **Credentials** | Top attempted usernames/passwords chart and username+password combination table |
| **Security Report** | One-click report generation + CSV/JSON exports |

---

## 🏃 Run modes

```bash
python run.py                          # decoys + dashboard (default)
python run.py --mode dashboard         # dashboard only (analysis of old data)
python run.py --mode honeypot          # headless collector
python run.py --mode reset-db          # wipe SQLite
python run.py --mode import --file logs/raw_events.jsonl --format raw
python run.py --mode import --file cowrie.json --format cowrie
python run.py --mode import --file /var/log/auth.log --format authlog

# useful flags
--host 0.0.0.0        # dashboard bind (decoys keep their own bind_host)
--port 5555           # dashboard port
--ssh-port/--http-port/--ftp-port/--telnet-port   # decoy port overrides
--i-own-this-network  # REQUIRED consent when decoys bind non-loopback
```

## 🐳 Docker

```bash
docker compose up --build
# dashboard -> http://localhost:5555
docker compose exec honeyscope python scripts/simulate_attacks.py \
    --host honeyscope --all      # attack it from inside, or use nmap from host
```

---

## ⚙️ Configuration

Defaults live in `core/config.py`. Copy `config.example.json` → `config.json`
to override. Environment variables `HONEYPOT_DB_PATH`,
`HONEYPOT_BIND_HOST`, `HONEYPOT_GEO_LOOKUP_ENABLED` also work.

| Key | Default | Meaning |
|---|---|---|
| `db_path` | `data/honeypot.db` | SQLite database file |
| `raw_log_path` | `logs/raw_events.jsonl` | Raw JSONL audit trail |
| `bind_host` | `127.0.0.1` | Decoy bind address (keep loopback!) |
| `services.ssh.port` | `2222` | SSH decoy port |
| `services.ssh.accept_any_credentials` | `false` | If `true`, the decoy *accepts* logins and serves a **pure string-matching fake shell** to capture commands (nothing is ever executed) |
| `services.http.port` | `8081` | HTTP decoy port (fake router login page) |
| `services.ftp.port` / `services.telnet.port` | `2121` / `2323` | Other decoys |
| `sensor_ports` | 17 ports | Silent probe-detection ports |
| `geo_lookup_enabled` | `false` | Online public-IP geolocation (cached) |
| `brute_force_window_minutes` | `10` | Behavioural analysis window |

---

## 📁 Project structure

```
honeypot-dashboard/
├── run.py                     # entry point (all modes)
├── core/
│   ├── config.py              # defaults + overrides
│   ├── database.py            # SQLite storage layer
│   ├── parser.py              # normalization + Cowrie/auth.log importers
│   ├── threat_scoring.py      # scoring/severity/pattern engine
│   ├── geoip.py               # private-IP labels + opt-in lookup
│   └── collector.py           # pipeline: normalize→score→enrich→store
├── honeypot/
│   ├── base_sensor.py         # generic TCP sensor, FTP + Telnet decoys
│   ├── ssh_honeypot.py        # paramiko SSH decoy (+ optional fake shell)
│   ├── http_honeypot.py       # HTTP decoy with credential capture
│   └── listener_manager.py    # lifecycle + status of all listeners
├── dashboard/
│   ├── app.py                 # Flask factory & pages
│   ├── api.py                 # REST API (JSON)
│   ├── templates/             # Jinja2 pages
│   └── static/                # CSS, JS, vendored Chart.js
├── reports/generator.py       # self-contained HTML + MD reports
├── scripts/
│   ├── simulate_attacks.py    # controlled attack simulator
│   └── seed_demo_data.py      # synthetic dataset generator
├── tests/                     # unit + integration tests (unittest)
├── docs/                      # architecture, guides, final report, viva prep
├── data/                      # created at runtime (SQLite db)
├── logs/                      # created at runtime (raw JSONL)
└── reports/out/               # generated security reports
```

---

## 🧪 Testing

```bash
python -m unittest discover -s tests -v     # 34 tests: parser, scoring, DB, pipeline
```

Manual evaluation plan with Nmap/curl/Hydra examples and expected results:
see **docs/testing_guide.md**. Teacher-facing walkthrough:
see **docs/demo_guide.md**.

---

## 🛠 Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` on a decoy port | Change the port (`config.json` or CLI flag). macOS uses 5000/7000 (AirPlay); many dev stacks use 8080. Busy sensors are skipped automatically and shown as stopped on the Overview page |
| Dashboard not reachable | Check the console output for the actual URL/port |
| No data on the dashboard | Run the simulator or seeder; check `/api/status` shows listeners running |
| Low-port decoys (22/80…) need privileges | Not recommended; prefer the high-port defaults |
| Want attacker countries on Intel page | Set `geo_lookup_enabled: true` (needs internet; results cached) |

---

## 🔒 Safety & ethics

This is a **defensive** teaching tool. It never attacks, exploits or pivots;
the fake shell cannot execute anything (string matching only). All testing
must happen on machines you own or are explicitly authorized to monitor —
the software enforces a consent flag before binding any non-loopback
interface. See **docs/ethics_and_safety.md**.

## 🗺 Future scope

Threat-intelligence feed enrichment (AbuseIPDB), automatic firewall blocking,
ML-based anomaly clustering of attacker behaviour, alerting (email/Telegram),
multi-node collection with a central aggregator.

## 📚 References

- OWASP Python Honeypot — <https://github.com/OWASP/Python-Honeypot>
- Cowrie SSH/Telnet Honeypot — <https://github.com/cowrie/cowrie>
- The-HoneyPot — <https://github.com/neelspatel999/The-HoneyPot>
