# FINAL REPORT (Template — fill in your details)

**GOVT. ENGINEERING COLLEGE, AJMER**
Department of Computer Science, Information Technology & Cyber Security

## B.Tech Project — I (VII Semester)

**Title:** Honeypot with Attack Visualization Dashboard (HoneyScope)
**Session:** 2026–2027
**Submitted by:**
| Name | Roll No. |
|---|---|
| [Name 1] | [Roll No.] |
| [Name 2] | [Roll No.] |
| [Name 3] | [Roll No.] |
| [Name 4] | [Roll No.] |
**Supervisor:** [Supervisor Name]

---

## Abstract

Organizations of every size receive constant scanning, brute-force and
automated exploitation attempts, yet students and small teams rarely have an
affordable platform to observe such threats safely. This project presents
HoneyScope, a self-contained honeypot laboratory that deploys safe decoy
services (SSH, HTTP, FTP, Telnet and seventeen TCP probe sensors) on a local
or isolated machine. Every interaction is parsed into structured events,
scored by a rule-based threat engine into severity levels and attack-pattern
labels, stored in SQLite, and visualized through a live web dashboard with
charts, searchable event tables and attacker intelligence views. A report
module produces a self-contained HTML security report with defensive
recommendations. The system runs on ordinary laptop hardware at zero cost,
requires no privileged access with default configuration, and enforces strict
ethical guardrails.

**Keywords:** honeypot, intrusion observation, brute force, credential
stuffing, port scanning, threat scoring, Flask, SQLite, Chart.js

---

## 1. Introduction

A honeypot is a controlled decoy designed to attract, record and study
unauthorized access attempts. Unlike firewalls or antivirus tools it makes no
attempt to prevent attacks; its value is *intelligence*: which credentials are
attacked, from where, how often, and with what payloads. HoneyScope implements
a low-interaction honeypot family with a modern analytics layer, letting
students observe real attacker behaviour without any risk to production
systems.

## 2. Literature Survey (summary)

- **Cowrie** [1] — the reference medium-interaction SSH/Telnet honeypot;
  inspired our fake-shell design and log-import compatibility.
- **OWASP Python Honeypot** [2] — demonstrated minimal decoy architecture.
- **T-Pot / The-HoneyPot** [3] — showed the value of dashboards aggregating
  multiple decoys.
- Classical taxonomy: low vs medium vs high interaction honeypots;
  research vs production deployment.

Gap identified: no single, zero-cost, easily-demonstrated project combines
decoys + scoring + visualization + reporting for academic labs.

## 3. Objectives

1. Deploy a safe honeypot in a local VM/Docker/authorized machine.
2. Capture IP, port, timestamp, protocol, credentials, payload samples.
3. Classify events by severity and pattern (brute force, scanning,
   stuffing, suspicious payloads).
4. Build a dashboard with charts, timeline, IP table, top credentials and
   basic geolocation.
5. Generate security reports summarising trends with recommendations.

## 4. Proposed System

Four layers (details in `docs/architecture.md`):

```
Collection (5 service types) → Parsing/Normalization → Threat Scoring →
Storage (SQLite) → Visualization (Flask + Chart.js) → Reporting
```

## 5. Implementation Summary

- **Language:** Python 3.10+ (~2,500 lines across 16 modules).
- **Decoys:** paramiko-based SSH server (records every password attempt;
  optional sandboxed string-only fake shell), ThreadingHTTPServer serving a
  realistic router-admin login page, line-oriented FTP/Telnet conversations,
  silent TCP sensors on common service ports.
- **Scoring engine:** payload signature detection (SQL injection, XSS, path
  traversal, webshell probing, scanner user-agents) combined with sliding-
  window behavioural analysis per source IP (brute force ≥5 failures,
  credential stuffing ≥6 usernames, scan ≥5 ports). Severity thresholds:
  LOW <8 ≤ MEDIUM <18 ≤ HIGH <32 ≤ CRITICAL.
- **Storage:** SQLite (WAL mode) with indexed `events` table (20 columns)
  and per-IP `ip_meta` aggregate including cached geolocation.
- **Dashboard:** five pages, REST JSON API, vendored Chart.js (offline),
  5-second live refresh, full-text search and faceted filters.
- **Reporting:** timestamped self-contained HTML report (charts embedded),
  Markdown summary, CSV/JSON dataset exports.
- **Safety engineering:** consent flag required for non-loopback binding;
  no subprocess/eval anywhere; private-IP geolocation resolved locally.

## 6. Testing

Automated suite: **34 unit/integration tests** (`python -m unittest discover -s tests`)
covering normalization, Cowrie/auth-log import parsing, severity boundaries,
behavioural thresholds, storage filters/pagination, pipeline escalation and
historical replay.

Manual evaluation cases TC1–TC8 with expected results are defined in
`docs/testing_guide.md`; paste your measured results and dashboard
screenshots there and in section 7.

## 7. Results & Discussion

*(Fill from your runs — suggested structure)*

| Scenario | Events captured | Patterns detected | Peak severity |
|---|---|---|---|
| SSH brute force (TC1) | | brute_force | |
| Port scan (TC2) | | port_scan | |
| Credential stuffing (TC3) | | credential_stuffing | |
| Web attacks (TC4) | | sqli/xss/traversal | |

Observations typically include: dominance of `root/admin` username attempts;
reused weak passwords (`123456`, `password`, `toor`); scanning concentrated
on database/remote-access ports; rapid severity escalation once behavioural
thresholds engage.

## 8. Conclusion & Future Scope

HoneyScope demonstrates, end to end, how low-cost decoy services plus
structured analytics make attacker behaviour visible and teachable.
Future extensions: threat-intelligence enrichment (AbuseIPDB), automatic
firewall blocking, ML-based clustering of attacker campaigns, alerting
integrations, multi-node aggregation.

## 9. Limitations

Low-interaction only (no kernel-level deception); rule-based scoring (no ML);
geolocation depends on opt-in third-party lookup; not hardened for hostile
public-internet exposure — lab use only.

## 10. Ethical Declaration

The system was deployed and tested exclusively on team-owned localhost/lab
resources. No third-party systems were scanned or attacked. Collected data is
synthetic or loopback-generated and handled per `docs/ethics_and_safety.md`.

## References

1. Cowrie Honeypot — https://github.com/cowrie/cowrie
2. OWASP Python Honeypot — https://github.com/OWASP/Python-Honeypot
3. The-HoneyPot — https://github.com/neelspatel999/The-HoneyPot
4. Flask documentation — https://flask.palletsprojects.com
5. SQLite documentation — https://www.sqlite.org/docs.html
6. Chart.js documentation — https://www.chartjs.org/docs/

## Appendix A — How to run

```bash
pip install -r requirements.txt
python run.py                                  # start everything
python scripts/seed_demo_data.py --wipe        # demo dataset
python scripts/simulate_attacks.py --all       # live attack scenarios
```
