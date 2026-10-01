# Viva Preparation — Likely Questions & Answers

**Q1. What is a honeypot and how is it different from a firewall?**
A honeypot is a decoy system whose value lies in being attacked — it records
and studies intrusions instead of blocking them. A firewall blocks traffic by
policy; a honeypot has no production value, so *any* interaction with it is
suspicious by definition and becomes intelligence.

**Q2. Low vs medium vs high interaction — where does HoneyScope fit?**
Low-interaction honeypots emulate limited protocol behaviour (banners, login
prompts); high-interaction ones expose real OSes. HoneyScope is low-to-medium
interaction: real SSH handshakes via paramiko and complete protocol
conversations, but a sandboxed string-matching shell rather than a real OS.

**Q3. Why did you implement your own decoys instead of deploying Cowrie?**
Educational transparency and control: every line of capture logic is
inspectable, the whole stack is one Python codebase with no daemon
dependencies, and we still interoperate by importing Cowrie JSON logs.

**Q4. How does the SSH decoy work?**
It opens a TCP listener on :2222; each client socket is handed to a
paramiko Transport acting as an SSH server with a generated ECDSA host key
and a faked version banner. Every `check_auth_password()` callback is logged
with the attempted credentials, then AUTH_FAILED is returned (unless decoy
shell mode is enabled).

**Q5. Is accepting attacker logins dangerous?**
In our implementation, no: the "shell" matches command strings against a
hard-coded response table. There is no subprocess, os.system or eval in the
codebase, so nothing the attacker types can execute. Network egress from the
process can additionally be restricted by running it in Docker/an isolated VM.

**Q6. How do you detect brute force?**
Sliding-window counting per source IP (default 10 minutes): when a source's
consecutive failed-login count reaches 5, events earn the `brute_force`
pattern label and score bonuses. Distinct-username counting ≥6 triggers
`credential_stuffing`; distinct destination ports ≥5 triggers `port_scan`.

**Q7. Why is scoring anchored to the event timestamp rather than wall clock?**
So that imported/replayed historical logs are scored against their own era —
the same pipeline behaves identically for live capture and offline import
(this exact behaviour is unit-tested).

**Q8. What severities exist and what do thresholds mean?**
LOW (<8), MEDIUM (≥8), HIGH (≥18), CRITICAL (≥32) computed from base event
weights plus payload-signature and behavioural bonuses (see
docs/architecture.md table).

**Q9. How is data stored and why SQLite?**
Two tables — `events` (one row per captured interaction, indexed by time/IP/
severity/service) and `ip_meta` (per-IP aggregates + geo cache). SQLite gives
zero-administration persistence, SQL analytics for the API, WAL concurrency
for our threaded writers, and a single portable file for submission.

**Q10. How does the dashboard get live updates?**
The Overview page polls `/api/stats`, `/api/timeline`, `/api/events` … every
5 seconds; charts are redrawn from fresh JSON. No websockets needed at lab
scale — simpler and firewall-friendly.

**Q11. How does geolocation preserve privacy?**
Private/loopback/reserved addresses are labelled entirely locally. Public IPs
are looked up only if `geo_lookup_enabled` is true, via ip-api.com, and
results are cached in `ip_meta` so each IP is queried once.

**Q12. What happens if two decoys want the same port?**
Startup never crashes: bind failures are caught, reported in the console and
reflected as stopped listeners on the Overview page. You can reassign ports
via config.json or CLI flags.

**Q13. How would you extend this with machine learning?**
Export the CSV dataset, engineer features per IP/time-window (attempt rates,
credential diversity, payload entropy), then cluster (DBSCAN/k-means) or train
an anomaly detector (Isolation Forest) to flag novel behaviour beyond the
rule thresholds; feed scores back as an extra severity signal.

**Q14. What ethical safeguards does the project enforce?**
Loopback-by-default binding; hard refusal to expose decoys on non-loopback
interfaces without `--i-own-this-network`; simulator refuses non-private
targets; no exploitation/offensive capability; data minimisation (payloads
truncated); documented acceptable use.

**Q15. Difference between `login_attempt` and `login_success` here?**
Any credential try against a decoy is `login_attempt`. `login_success` exists
only when decoy-shell mode accepts credentials — it marks entry into the fake
shell, not a real compromise.

**Q16. How would you deploy this on a college network?**
Only with written authorization: run inside Docker on an isolated VLAN with
no egress, bind specific interfaces, alert on CRITICAL events, review data
weekly, and publish anonymised findings for awareness sessions.

**Q17. Why Flask and not Streamlit/Django?**
Flask gives a lightweight API + template layer with full control over polling
endpoints and static assets, while remaining a single-process dependency-light
deployment that students can read end-to-end.

**Q18. What are the system's limitations?**
Low interaction only; IPv4 focus; rule-based (not ML) scoring; single-node;
not hardened against determined public-internet attackers — by design it is a
lab instrument.

**Q19. How did you test the project?**
34 automated unit/integration tests plus eight manual evaluation cases
(TC1–TC8 in docs/testing_guide.md) executed with the built-in simulator,
nmap and curl, verified both through the REST API and direct SQLite queries.

**Q20. What did you learn personally?**
How noisy real-world scanning is, why default credentials remain the top
compromise vector, how much design effort safe failure-handling takes, and
how visualization turns raw logs into security insight.
