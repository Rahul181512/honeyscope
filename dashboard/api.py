"""REST API for the dashboard (all JSON endpoints under /api/)."""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path

from flask import Blueprint, Response, jsonify, request, send_from_directory

from core.config import REPORT_OUT_DIR
from reports.generator import generate_report, latest_report

api_bp = Blueprint("api", __name__, url_prefix="/api")

# flask current-app access
from flask import current_app as _app  # noqa: E402


def _db():
    return _app.config["DB"]


def _manager():
    return _app.config.get("MANAGER")


# ------------------------------------------------------------------ overview
@api_bp.get("/stats")
def stats():
    data = _db().stats()
    return jsonify(data)


@api_bp.get("/timeline")
def timeline():
    hours = min(720, max(1, int(request.args.get("hours", 48))))
    buckets = min(200, max(6, int(request.args.get("buckets", 48))))
    return jsonify(_db().timeline(hours=hours, buckets=buckets))


@api_bp.get("/top/ips")
def top_ips():
    limit = min(100, max(1, int(request.args.get("limit", 10))))
    return jsonify(_db().top_ips(limit=limit))


@api_bp.get("/top/usernames")
def top_usernames():
    return jsonify(_db().top_usernames(
        limit=min(50, max(1, int(request.args.get("limit", 12))))))


@api_bp.get("/top/passwords")
def top_passwords():
    return jsonify(_db().top_passwords(
        limit=min(50, max(1, int(request.args.get("limit", 12))))))


@api_bp.get("/credentials/combos")
def credential_combos():
    return jsonify(_db().credential_combos(
        limit=min(100, max(1, int(request.args.get("limit", 20))))))


@api_bp.get("/status")
def status():
    mgr = _manager()
    out = {
        "listeners": [],
        "uptime_seconds": None,
        "total_events": _db().count(),
        "version": "1.0.0",
    }
    if mgr is not None:
        out.update(mgr.status())
    return jsonify(out)


@api_bp.get("/meta/filters")
def meta_filters():
    d = _db()
    return jsonify({
        "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "services": sorted(d.distinct("service")),
        "patterns": sorted(d.distinct("attack_pattern")),
    })


# -------------------------------------------------------------------- events
@api_bp.get("/events")
def events():
    args = request.args
    rows, total = _db().query_events(
        q=args.get("q") or None,
        severity=args.get("severity") or None,
        service=args.get("service") or None,
        pattern=args.get("pattern") or None,
        ip=args.get("ip") or None,
        page=int(args.get("page", 1)),
        per_page=int(args.get("per_page", 50)),
    )
    return jsonify({"total": total, "page": int(args.get("page", 1)),
                    "per_page": int(args.get("per_page", 50)),
                    "events": rows})


@api_bp.get("/events/<int:event_id>")
def event_detail(event_id: int):
    ev = _db().get_event(event_id)
    return (jsonify(ev), 200) if ev else (jsonify({"error": "not found"}), 404)


@api_bp.get("/intel")
def intel():
    return jsonify({"ips": _db().ip_intel(
        limit=min(1000, max(1, int(request.args.get("limit", 300)))))})


@api_bp.get("/events/by-ip/<path:ip>")
def events_by_ip(ip: str):
    rows, total = _db().query_events(ip=ip, per_page=100)
    return jsonify({"total": total, "events": rows})


# ------------------------------------------------------------------- exports
@api_bp.get("/export/events.csv")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    rows = list(_db().export_all())
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows:
            writer.writerow([row[k] for k in rows[0].keys()])
    return Response(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=honeyscope_events.csv"})


@api_bp.get("/export/events.json")
def export_json():
    rows = list(_db().export_all())
    return Response(
        json.dumps(rows, ensure_ascii=False, default=str),
        mimetype="application/json",
        headers={"Content-Disposition":
                 "attachment; filename=honeyscope_events.json"})


# -------------------------------------------------------------------- report
@api_bp.post("/report/generate")
def report_generate():
    paths = generate_report(_db(), chart_js_path=_app.config["CFG"].get("_chart_js"))
    summary = _db().stats()
    return jsonify({
        "ok": True,
        "files": {k: os.path.basename(v) for k, v in paths.items()},
        "summary": {
            "total_events": summary["total_events"],
            "unique_ips": summary["unique_ips"],
            "critical_events": summary["critical_events"],
            "credentials_captured": summary["credentials_captured"],
        },
    })


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


@api_bp.get("/report/file")
def report_file():
    name = request.args.get("name", "")
    if not _SAFE_NAME.match(name):
        return jsonify({"error": "invalid name"}), 400
    return send_from_directory(REPORT_OUT_DIR, name, as_attachment=False)


@api_bp.get("/report/latest")
def report_latest():
    path = latest_report()
    if not path:
        return jsonify({"error": "no report generated yet"}), 404
    return jsonify({"file": os.path.basename(path)})


# -------------------------------------------------------------------- admin
@api_bp.post("/reset")
def reset_dataset():
    """Wipe captured events and the raw audit log (start a demo fresh)."""
    from core.config import load_config
    _db().reset()
    raw_log = load_config().get("raw_log_path")
    try:
        Path(raw_log).write_text("", encoding="utf-8")
    except OSError:
        pass
    return jsonify({"ok": True, "events": 0})
