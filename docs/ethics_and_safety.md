# Ethics & Safety Policy

## Scope of permitted use

HoneyScope is an academic DEFENSIVE security tool. Permitted environments:

- your own laptop/workstation (loopback),
- virtual machines you own,
- explicitly authorized, isolated lab network segments.

Written authorization is required before exposing decoys on any network you
do not personally own.

## Built-in guardrails

1. **Loopback default** — all decoys bind `127.0.0.1` unless reconfigured.
2. **Consent gate** — non-loopback binding exits with an ethics notice unless
   `--i-own-this-network` is passed; Docker compose ships with the flag set
   because building the image itself constitutes consent.
3. **Simulator target check** — `simulate_attacks.py` resolves its target and
   refuses anything that is not loopback/private without the same flag.
4. **No offensive capability** — the codebase contains no exploit code, no
   scanning of remote hosts, no privilege escalation, and the fake shell has
   no execution path (pure string matching; no `subprocess`/`os.system`/
   `eval`).
5. **Data minimisation** — payloads truncated to 4 KB, credentials stored
   only as captured from decoy interactions, raw audit trail kept locally.

## Data handling

- All data stays in `data/` and `logs/` on the host; nothing is uploaded.
- Demo datasets are synthetic; live captures on shared machines should be
  anonymised before screenshots are included in reports.
- Delete captures when the exercise ends: `python run.py --mode reset-db`.

## Legal note (India)

Unauthorised access to computer resources is an offence under the Information
Technology Act, 2000 (ss. 43, 66) and the Bharatiya Nyaya Sanhita's computer-
related provisions. Running honeypot decoys on networks without authorization
may create civil and criminal liability. This project's guardrails exist to
keep your experimentation lawful.

## Responsible disclosure

If honeypot data reveals a genuine compromise on an authorized network,
report findings privately to the network owner/security officer first; do not
publish attacker infrastructure details until remediation is confirmed.
