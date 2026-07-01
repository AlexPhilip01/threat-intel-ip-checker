"""
Flask routes.

Two things live here:
  1. The dashboard page itself (/)
  2. A small JSON API the page's JS polls / posts to (/api/watchlist...)

Adding an IP triggers an immediate check in a background thread so the
HTTP response doesn't block on 3 outbound API calls — the dashboard
shows "PENDING" for the second or two until that finishes, then polling
picks up the real result.
"""
import threading
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

from checker.engine import build_sources, check_ip
from checker.validator import validate_ip

from . import state
from .scheduler import run_check_cycle

bp = Blueprint("dashboard", __name__)


def _check_and_store(ip: str) -> None:
    sources = build_sources()
    result = check_ip(ip, sources)
    state.set_result(ip, result)


@bp.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@bp.route("/")
def dashboard_page():
    return render_template("dashboard.html")


@bp.route("/api/watchlist", methods=["GET"])
def get_watchlist():
    return jsonify({"watchlist": state.snapshot()})


@bp.route("/api/watchlist", methods=["POST"])
def add_to_watchlist():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip") or "").strip()

    is_valid, is_private, error = validate_ip(ip)
    if not is_valid:
        return jsonify({"error": error}), 400

    added_at = datetime.now(timezone.utc).isoformat()
    added = state.add_ip(ip, added_at)
    if not added:
        return jsonify({"error": f"{ip} is already on the watchlist"}), 409

    # Kick off the first check right away rather than waiting for the
    # next scheduled cycle (which may be hours away).
    threading.Thread(target=_check_and_store, args=(ip,), daemon=True).start()

    return jsonify({"ip": ip, "is_private": is_private, "status": "added"}), 201


@bp.route("/api/watchlist/<ip>", methods=["DELETE"])
def remove_from_watchlist(ip):
    removed = state.remove_ip(ip)
    if not removed:
        return jsonify({"error": f"{ip} is not on the watchlist"}), 404
    return jsonify({"ip": ip, "status": "removed"})


@bp.route("/api/watchlist/refresh", methods=["POST"])
def refresh_all():
    """Manually trigger a re-check of the whole watchlist right now."""
    threading.Thread(target=run_check_cycle, daemon=True).start()
    return jsonify({"status": "refresh started"}), 202
