# Architecture

HoneyScope follows the four-layer design from the project synopsis:
**honeypot collection → log parsing → storage → visualization**, plus a
threat-scoring stage that sits between parsing and storage.

```
                       ATTACKER (lab only: localhost / owned VM)
                            │  ssh / http / ftp / telnet / probes
                            ▼
┌─────────────────────── LAYER 1: COLLECTION ────────────────────────┐
│  honeypot/listener_manager.py  – starts/stops every decoy thread    │
│  ├─ ssh_honeypot.py     paramiko server: logs every password auth;  │
│  │                      optional sandboxed fake shell (strings only)│
│  ├─ http_honeypot.py    ThreadingHTTPServer: fake router login page,│
│  │                      captures form POSTs + all request metadata  │
│  ├─ base_sensor.FtpSensor     USER/PASS conversation                │
│  ├─ base_sensor.TelnetSensor  login prompt conversation             │
│  └─ base_sensor.TCPSensor × 17  silent ports → port_probe events    │
└────────────────────────────────┬───────────────────────────────────┘
                                 │  raw event dict
                                 ▼
┌─────────────────────── LAYER 2: PARSING ───────────────────────────┐
│  core/parser.normalize()   validate/coerce/truncate fields          │
│  core/parser.RawLogWriter  append JSONL audit trail                 │
│  importers: own JSONL replay · Cowrie JSON · auth.log lines         │
└────────────────────────────────┬───────────────────────────────────┘
                                 │  structured event
                                 ▼
┌────────────────────── THREAT SCORING (core/threat_scoring.py) ─────┐
│  payload signatures (SQLi/XSS/traversal/shell-probe/scanner UA)     │
│  + behavioural history per source IP (sliding 10-min window):       │
│     ≥5 failed logins → brute_force                                  │
│     ≥6 distinct usernames → credential_stuffing                     │
│     ≥5 distinct ports → port_scan                                   │
│  ⇒ (score, severity LOW/MEDIUM/HIGH/CRITICAL, attack_pattern)       │
└────────────────────────────────┬───────────────────────────────────┘
                                 ▼
┌─────────────────────── LAYER 3: STORAGE ───────────────────────────┐
│  core/database.py  SQLite (WAL, single connection + RLock)          │
│  tables: events (20 columns, indexed), ip_meta (per-IP aggregate,   │
│  geo cache).  core/geoip.py labels private IPs locally; online      │
│  lookups are opt-in and cached into ip_meta.                        │
└────────────────────────────────┬───────────────────────────────────┘
                                 ▼
┌─────────────────────── LAYER 4: VISUALIZATION ─────────────────────┐
│  dashboard/app.py   Flask pages (Overview/Events/Intel/Creds/Report)│
│  dashboard/api.py   REST JSON API (/api/stats, /api/events, …)      │
│  static/js/dashboard.js  vanilla JS + vendored Chart.js             │
│  reports/generator.py  self-contained HTML report + Markdown + CSV  │
└────────────────────────────────────────────────────────────────────┘
```

## Event flow (example: SSH brute force)

1. Attacker connects to :2222 → paramiko transport handshake completes
   (server banner faked as `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`).
2. Each `check_auth_password()` callback emits
   `{service:"ssh", event_type:"login_attempt", username, password, …}`.
3. The handler keeps the session open briefly so repeated attempts from the
   same client are captured; clients normally disconnect after failure.
4. `Collector.collect()` normalizes, pulls the source IP's last 10 minutes
   of activity from SQLite, scores the event, enriches geo labels, appends
   the raw dict to `logs/raw_events.jsonl`, inserts the row.
5. Events 5+ cross the brute-force threshold → severity escalates to
   MEDIUM/HIGH; ≥6 distinct usernames adds the stuffing bonus → CRITICAL.
6. HIGH/CRITICAL events trigger console alerts (`run.py:alert_console`)
   and appear instantly on the dashboard's next 5-second poll.

## Database schema

### events

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | autoincrement |
| ts / epoch | TEXT / REAL | UTC ISO-8601 + unix time |
| src_ip, src_port, dst_port | TEXT/INT | connection tuple |
| protocol | TEXT | tcp |
| service | TEXT | ssh/http/ftp/telnet/sensor |
| event_type | TEXT | login_attempt/login_success/command/http_request/port_probe/banner_grab/connection |
| username, password | TEXT | captured credentials (may be NULL) |
| payload | TEXT | truncated to 4096 chars |
| user_agent | TEXT | HTTP client signature |
| severity, score, attack_pattern | TEXT/REAL | scoring output |
| geo_country, geo_city, geo_asn, geo_lat, geo_lon | — | enrichment |

Indexes on epoch, src_ip, severity, service.

### ip_meta

One row per source IP: first_seen, last_seen, total_events, max_severity,
is_private flag, cached country/city/asn/lat/lon.

## Threat-scoring model

Base weights: command 4 · login_success 6 · login_attempt 3 ·
http_request 1 · port_probe 1 · connection/banner_grab 0.5.

Bonuses: SQLi +7 · XSS/path-traversal +6 · shell probing +5 · scanner UA +4 ·
brute_force +8 · stuffing +14 · scan +8 · login velocity +1.2×(failures, cap 10).

Severity thresholds: ≥32 CRITICAL · ≥18 HIGH · ≥8 MEDIUM · else LOW.
The most specific label wins: web payloads > stuffing > brute force > scan.

## Design decisions

- **Threads over async**: each listener is an independent daemon thread;
  SQLite serialised behind one RLock with WAL mode — simple, robust, and
  adequate for lab-scale traffic.
- **Scoring anchored to event epoch**: history windows are relative to the
  incoming event's timestamp, so replayed/imported historical logs are scored
  against their own era (unit-tested).
- **Graceful degradation**: busy ports never crash startup; they are reported
  as stopped listeners on the Overview page.
- **Vendored Chart.js**: dashboards and generated reports work fully offline.
- **No execution ever**: the SSH fake shell is pure string matching — there
  is no `subprocess`, `os.system` or `eval` anywhere in the codebase.
