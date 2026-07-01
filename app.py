"""
Flask app factory + entry point.

    Local dev:   python app.py
    Production:  gunicorn app:app --workers 1 --threads 4 --timeout 60

--workers 1 matters: the watchlist lives in process memory (see
dashboard/state.py). Multiple gunicorn workers would each keep their own
separate watchlist, so adding an IP in one request and listing it in the
next could silently "lose" it if a different worker answered. Multiple
*threads* within that single worker is fine — that's how concurrent
requests are still handled.
"""
import logging
import os

from dotenv import load_dotenv

load_dotenv()

from flask import Flask  # noqa: E402

from dashboard.routes import bp as dashboard_bp  # noqa: E402
from dashboard.scheduler import start_scheduler  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def create_app() -> Flask:
    flask_app = Flask(__name__)
    flask_app.register_blueprint(dashboard_bp)
    return flask_app


app = create_app()

_scheduler_enabled = os.environ.get("ENABLE_SCHEDULER", "true").lower() not in ("false", "0", "no")
if _scheduler_enabled:
    start_scheduler()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
