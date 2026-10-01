# Testing Guide

## A. Automated unit tests

34 tests cover the parser, scoring engine, storage layer and the end-to-end
collection pipeline (including historical replay scoring):

```bash
python -m unittest discover -s tests -v
```

Expected output: `Ran 34 tests ... OK`.

## B. Controlled evaluation cases (Methodology step 6)

Run the system (`python run.py`) in one terminal and execute each case in a
second terminal. Verify via dashboard and/or SQLite:

```bash
sqlite3 data/honeypot.db "SELECT ts, src_ip, event_type, username,
       severity, attack_pattern FROM events ORDER BY id DESC LIMIT 20;"
```

### TC1 — Failed login brute force
```bash
python scripts/simulate_attacks.py --scenario ssh
```
- **Expect:** 8 `login_attempt` events from 127.0.0.1; events ≥5 tagged
  `brute_force`; severity escalates LOW → MEDIUM (+HIGH with more attempts).
- **Pass criterion:** `by_pattern.brute_force > 0` in `/api/stats`.

### TC2 — Port scan
```bash
python scripts/simulate_attacks.py --scenario port-scan
# or with nmap:
nmap -p 1433,3306,3389,5432,5900,6379,8000,8443,9000,9200,27017 127.0.0.1
```
- **Expect:** one `port_probe` per touched sensor; once ≥5 distinct ports
  occur inside 10 minutes they are tagged `port_scan`.
- **Pass criterion:** `port_scan` count ≥ number of probes − 4.

### TC3 — Credential stuffing over HTTP
```bash
python scripts/simulate_attacks.py --scenario stuffing
```
- **Expect:** POSTs to the fake router page captured with usernames/
  passwords; events with ≥6th distinct username tagged
  `credential_stuffing` (CRITICAL).
- **Pass criterion:** Credentials page chart lists all attempted usernames.

### TC4 — Web payload attacks
```bash
python scripts/simulate_attacks.py --scenario web
curl "http://127.0.0.1:8081/download?file=../../../../etc/passwd"
curl -A "sqlmap/1.7" "http://127.0.0.1:8081/"
```
- **Expect:** patterns `sql_injection`, `xss`, `path_traversal`,
  `webshell_probing`, `scanner_tool`; MEDIUM severities.

### TC5 — FTP / Telnet protocol decoys
```bash
python scripts/simulate_attacks.py --scenario ftp
python scripts/simulate_attacks.py --scenario telnet
```
- **Expect:** `login_attempt` events containing the exact credentials used.

### TC6 — Fake shell command capture (optional mode)
Enable `services.ssh.accept_any_credentials`, restart, connect:
```bash
ssh root@127.0.0.1 -p 2222     # any password accepted by decoy
whoami
cat /etc/shadow
exit
```
- **Expect:** `login_success` + two `command` events; canned responses only;
  nothing executed on the host.

### TC7 — Report generation
Dashboard → Security Report → *Generate report now*.
- **Expect:** files created under `reports/out/`; HTML opens offline and
  contains KPI numbers matching `/api/stats`.

### TC8 — Ethical guardrail
```bash
python run.py --bind-host-override ... # try HONEYPOT_BIND_HOST=0.0.0.0 python run.py
```
- **Expect:** refusal message unless `--i-own-this-network` is supplied.

## C. Results table (fill during your evaluation)

| TC | Date | Result | Events captured | Patterns observed | Pass? |
|----|------|--------|-----------------|-------------------|-------|
| TC1 | | | | | |
| TC2 | | | | | |
| TC3 | | | | | |
| TC4 | | | | | |
| TC5 | | | | | |
| TC6 | | | | | |
| TC7 | | | | | |
| TC8 | | | | | |

Paste screenshots of the Overview page before/after each scenario into your
final report (docs/final_report.md).
