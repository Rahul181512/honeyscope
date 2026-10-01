"""Threat Scoring Module.

Assigns a numeric score, a severity level (LOW/MEDIUM/HIGH/CRITICAL) and an
attack-pattern label to every incoming event, based on:
  * event type weights,
  * payload content (SQL injection / XSS / path traversal / scanner signatures),
  * frequency behaviour of the source IP (brute force, port scanning,
    credential stuffing) observed in recent history.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}

#: score >= threshold  ->  severity
THRESHOLDS = ((32.0, "CRITICAL"), (18.0, "HIGH"), (8.0, "MEDIUM"))

EVENT_WEIGHTS = {
    "connection": 0.5,
    "banner_grab": 0.5,
    "port_probe": 1.0,
    "http_request": 1.0,
    "login_attempt": 3.0,
    "login_success": 6.0,
    "command": 4.0,
}

# --- suspicious payload signatures -------------------------------------------
_WEB_SIGNATURES = (
    ("sql_injection",
     re.compile(r"union[\s\S]{0,12}select|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
                r"'\s*or\s*'|drop\s+table|sleep\s*\(|benchmark\s*\(|"
                r"information_schema|(?:--|#)\s*$|;\s*(?:delete|update|insert)\b", re.I)),
    ("xss",
     re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|"
                r"document\.cookie|<img\s[^>]*src", re.I)),
    ("path_traversal",
     re.compile(r"\.\./|\.\.\\|%2e%2e(?:%2f|%5c|/|\\)|/etc/(?:passwd|shadow)|"
                r"boot\.ini|win\.ini|\.env\b", re.I)),
    ("webshell_probing",
     re.compile(r"/(?:cmd|shell|c99|r57|alfa|wso)\.(?:php|asp|jsp)|phpmyadmin|"
                r"wp-login\.php|\.git/config|xmlrpc\.php", re.I)),
)

_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nessus|masscan|zgrab|nmap|gobuster|dirbuster|wfuzz|"
    r"hydra|metasploit|acunetix|netsparker", re.I)

# --- behavioural thresholds ---------------------------------------------------
BRUTE_FORCE_MIN = 5          # failed logins from one IP inside the window
STUFFING_MIN_USERS = 6       # distinct usernames tried by one IP
SCAN_MIN_PORTS = 5           # distinct destination ports touched by one IP

_PATTERN_PRIORITY = (
    "sql_injection", "xss", "path_traversal", "webshell_probing", "scanner_tool",
    "credential_stuffing", "brute_force", "port_scan",
)


def detect_payload_pattern(text: Optional[str], user_agent: str = "") -> Optional[str]:
    """Return a payload/UA based attack-pattern label or None."""
    haystack = ""
    if text:
        haystack += text[:4096] + "\n"
    if user_agent:
        haystack += user_agent
    if not haystack.strip():
        return None
    for name, rx in _WEB_SIGNATURES:
        if rx.search(haystack):
            return name
    if _SCANNER_UA.search(user_agent or ""):
        return "scanner_tool"
    return None


def severity_for_score(score: float) -> str:
    for threshold, severity in THRESHOLDS:
        if score >= threshold:
            return severity
    return "LOW"


def evaluate(event: dict, history: Iterable[dict]) -> tuple[float, str, str]:
    """Score *event* against *history* (recent events from the same source IP).

    Returns ``(score, severity, attack_pattern)``. Pure function - unit tested.
    """
    history = list(history or [])
    event_type = event.get("event_type") or "connection"

    score = EVENT_WEIGHTS.get(event_type, 1.0)

    # ---- payload-based detection -------------------------------------------
    pattern = detect_payload_pattern(
        event.get("payload"), event.get("user_agent") or "")
    if pattern == "sql_injection":
        score += 7
    elif pattern in ("xss", "path_traversal"):
        score += 6
    elif pattern in ("webshell_probing",):
        score += 5
    elif pattern == "scanner_tool":
        score += 4

    # ---- behavioural aggregation --------------------------------------------
    hist_failed = sum(1 for h in history if h.get("event_type") == "login_attempt")
    hist_usernames = {
        (h.get("username") or "").strip().lower()
        for h in history
        if h.get("event_type") in ("login_attempt", "login_success")
        and (h.get("username") or "").strip()
    }
    if (event.get("username") or "").strip():
        hist_usernames.add(event["username"].strip().lower())

    hist_ports = {h.get("dst_port") for h in history if h.get("dst_port")}
    if event.get("dst_port"):
        hist_ports.add(event["dst_port"])

    is_login = event_type in ("login_attempt", "login_success")

    brute_force = is_login and (hist_failed + 1) >= BRUTE_FORCE_MIN
    stuffing = is_login and len(hist_usernames) >= STUFFING_MIN_USERS
    port_scan = (not is_login) and len(hist_ports) >= SCAN_MIN_PORTS

    if brute_force:
        score += 8
    if stuffing:
        score += 14
    if port_scan:
        score += 8
    if is_login:
        # velocity bonus: repeated attention from the same source
        score += min(hist_failed, 10) * 1.2

    score = round(score, 1)

    # ---- choose the most specific pattern ------------------------------------
    chosen = "unknown"
    if brute_force:
        chosen = "brute_force"
    if port_scan:
        chosen = "port_scan"
    if stuffing:
        chosen = "credential_stuffing"
    if pattern and pattern in _PATTERN_PRIORITY:
        chosen = pattern

    return score, severity_for_score(score), chosen


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b
