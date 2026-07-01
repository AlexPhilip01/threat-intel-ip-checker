"""
Background scheduler: periodically re-checks every IP on the watchlist.

Kept intentionally simple — one job, one interval, no job store (job
store would need a database, which we're deliberately not using). If
the process restarts, the scheduler just starts fresh; nothing to
recover.
"""
import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler

from checker.engine import build_sources, check_ip

from . import alerts, state

logger = logging.getLogger(__name__)

_scheduler = None


def run_check_cycle() -> None:
    """Re-check every watched IP once, alerting on risk increases."""
    sources = build_sources()
    for ip in state.list_watchlist():
        previous = state.get_result(ip)
        new_result = check_ip(ip, sources)
        state.set_result(ip, new_result)

        if alerts.risk_increased(previous, new_result):
            try:
                alerts.send_alert(ip, previous, new_result)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to send alert email for %s", ip)


def start_scheduler() -> BackgroundScheduler:
    """Start the background scheduler (idempotent — safe to call once at boot)."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    interval_hours = float(os.environ.get("CHECK_INTERVAL_HOURS", "2"))

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        run_check_cycle,
        "interval",
        hours=interval_hours,
        id="watchlist_recheck",
        next_run_time=None,  # first run is scheduled `interval_hours` from now
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Scheduler started: re-checking watchlist every %s hour(s)", interval_hours)
    return _scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
