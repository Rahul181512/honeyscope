"""Flask application factory and page routes."""

from __future__ import annotations

from flask import Flask, render_template

from .api import api_bp


def create_app(db, manager=None, cfg: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["DB"] = db
    app.config["MANAGER"] = manager
    app.config["CFG"] = cfg or {}
    app.json.sort_keys = False
    app.register_blueprint(api_bp)

    @app.context_processor
    def _globals():
        return {
            "project_title": (cfg or {}).get("title", "HoneyScope"),
            "geo_enabled": bool((cfg or {}).get("geo_lookup_enabled", False)),
        }

    @app.route("/")
    def overview():
        return render_template("index.html", active_page="overview")

    @app.route("/events")
    def events():
        return render_template("events.html", active_page="events")

    @app.route("/intel")
    def intel():
        return render_template("intel.html", active_page="intel")

    @app.route("/credentials")
    def credentials():
        return render_template("credentials.html", active_page="credentials")

    @app.route("/report")
    def report_page():
        return render_template("report.html", active_page="report")

    return app
