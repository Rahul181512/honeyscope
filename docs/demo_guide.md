# Live Demonstration Guide (for teachers / viva)

This guide shows you how to run a **completely real** attack demonstration in
front of an audience. There is **no pre-loaded or fake data** — every number
on the dashboard is genuine traffic captured from your own decoys.

> ⏱ Suggested duration: **5–7 minutes** end-to-end.

---

## 0. One-time setup (before the audience arrives)

```bash
cd honeypot-dashboard
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 1. start the honeypot + dashboard
python run.py

# 2. make sure the dataset is clean (dashboard shows 0 events)
python run.py --mode reset-db        # or use "Clear all events" on Events page
```

Open the dashboard in **two browser tabs** side by side:

- Tab 1 → **Overview** (`http://127.0.0.1:5555/`)
- Tab 2 → **Events** (`http://127.0.0.1:5555/events`)

Have a terminal open next to them. You're ready.

---

## The demo (interactive, narrated)

Run the guided demo script — it narrates every step and waits for your
**Enter** key between scenarios so you control the pacing:

```bash
python scripts/live_demo.py
```

### What happens, scene by scene

| # | Scenario | Real traffic sent | What to point at on the dashboard |
|---|---|---|---|
| 1 | **Port scan** | 11 real TCP connects across sensor ports, from a real local address | Events → filter `service = sensor`; `port_scan` appears in the Attack Patterns chart |
| 2 | **SSH brute force** | 8 real SSH handshakes, each with a different username/password | Events → filter `severity = HIGH / CRITICAL`; click a row to show the tried `root/toor`, `admin/admin` … |
| 3 | **Credential stuffing** | 8 real HTTP POSTs to the decoy login form | **Credentials** page — username/password chart and combo table fill up live |
| 4 | **Web app attacks** | SQLi, XSS, path-traversal, webshell probes (with sqlmap signature) | Events → open a row and read the raw payload (e.g. `1' OR '1'='1 UNION SELECT …`) |
| 5 | **FTP + Telnet** | Real USER/PASS conversations on :2121 and :2323 | Events → new `ftp`/`telnet` login attempts |
| 6* | **Command capture** | Attacker opens an interactive shell and types commands | Events → filter type `command`; show exactly what the attacker typed |

\* Stage 6 runs automatically **only if** the SSH decoy is in shell mode
(see “Option C” below). Otherwise it prints a one-line explanation and skips.

Each scenario is sourced from a **distinct real local address** (the machine's
LAN IP, plus loopback). On the **Attacker Intel** page you'll see several
separate attacker rows — genuine connections, not fabricated rows.

---

## Closing the demo (60 seconds)

1. **Overview** — KPI cards, 48-hour timeline, severity doughnut,
   attack-pattern ranking. Say: *"this is live data — nothing was pre-loaded."*
2. **Events** — filter `severity = CRITICAL`, open two or three detail modals.
3. **Attacker Intel** — the distinct source IPs.
4. **Security Report** — click **"Generate report now"** and open the
   self-contained HTML report (charts embedded, prints to PDF) to show the
   findings + defensive recommendations.

To run the whole thing again cleanly:
`python run.py --mode reset-db` or the **Clear all events** button.

---

## Option A — run it non-interactively (practice)

```bash
python scripts/live_demo.py --auto     # no Enter prompts, full speed
```

Use this while rehearsing. Interactive mode (`--auto` omitted) is what you
use in front of the audience.

---

## Option B — attack from a *second device* (the most convincing)

Attacks from your own laptop all come from the laptop's own addresses. To show
a genuinely *separate* attacker machine:

1. Authorize LAN binding (you own this lab network):
   ```bash
   python run.py --i-own-this-network      # decoys bind 0.0.0.0 via config
   ```
   (or set `"bind_host": "0.0.0.0"` in `config.json`.)
2. From a classmate's laptop / phone on the same Wi-Fi, run:
   ```bash
   ssh root@<YOUR_LAN_IP> -p 2222                       # or a browser to
   curl "http://<YOUR_LAN_IP>:8081/login" -d "username=admin&password=admin"
   ```
3. Their real IP now appears on the dashboard — full stop, real attacker.

---

## Option C — demonstrate command capture (interactive shell)

The decoy can *accept* logins and serve a sandboxed fake shell that logs every
command — while executing nothing. Enable it in `config.json`:

```json
{ "services": { "ssh": { "accept_any_credentials": true } } }
```

Restart `python run.py`, then run the demo — stage 6 now shows an attacker
typing `whoami`, `cat /etc/passwd`, `wget … | sh` and the dashboard captures
each keystroke line as a `command` event.

---

## Talking points (viva prep)

- Everything is **low-interaction honeypot behaviour** recorded as structured
  events, scored by rule-based severity/pattern classification, stored in
  SQLite, visualised in Flask + Chart.js.
- The fake shell **never executes anything** — pure string matching, no
  `subprocess`/`eval` in the codebase.
- Geolocation is **privacy-first**: private/lab IPs are labelled locally;
  public lookups are opt-in and cached.
- The consent gate (`--i-own-this-network`) and the simulator's target check
  are the ethical guardrails — see `docs/ethics_and_safety.md`.
