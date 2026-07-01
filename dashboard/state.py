"""
In-memory state for the dashboard.

Deliberately NOT a database. State lives in process memory and resets on
restart/redeploy — a conscious tradeoff for zero-setup free-tier hosting
(see README for the reasoning). If you outgrow this, swap this module for
a SQLite-backed version; the get/add/remove/update interface below is the
only thing anything else in the app talks to, so nothing else changes.

Thread-safety note: Flask (with threads=True / gunicorn --threads) can
serve requests concurrently, and the background scheduler runs on its own
thread too. All mutations go through a single lock.
"""
import threading
from typing import Any, Dict, List, Optional

_lock = threading.Lock()

# ip -> {"added_at": iso str}
_watchlist: Dict[str, Dict[str, Any]] = {}

# ip -> last check_ip() result dict (see checker.engine.check_ip)
_last_results: Dict[str, Dict[str, Any]] = {}


def add_ip(ip: str, added_at: str) -> bool:
    """Add an IP to the watchlist. Returns False if it was already present."""
    with _lock:
        if ip in _watchlist:
            return False
        _watchlist[ip] = {"added_at": added_at}
        return True


def remove_ip(ip: str) -> bool:
    """Remove an IP from the watchlist. Returns False if it wasn't present."""
    with _lock:
        existed = ip in _watchlist
        _watchlist.pop(ip, None)
        _last_results.pop(ip, None)
        return existed


def list_watchlist() -> List[str]:
    with _lock:
        return list(_watchlist.keys())


def get_added_at(ip: str) -> Optional[str]:
    with _lock:
        entry = _watchlist.get(ip)
        return entry["added_at"] if entry else None


def set_result(ip: str, result: Dict[str, Any]) -> None:
    with _lock:
        if ip in _watchlist:  # ignore results for IPs removed mid-check
            _last_results[ip] = result


def get_result(ip: str) -> Optional[Dict[str, Any]]:
    with _lock:
        return _last_results.get(ip)


def snapshot() -> List[Dict[str, Any]]:
    """Everything the dashboard needs to render, in one consistent read."""
    with _lock:
        rows = []
        for ip, meta in _watchlist.items():
            result = _last_results.get(ip)
            rows.append(
                {
                    "ip": ip,
                    "added_at": meta["added_at"],
                    "checked": result is not None,
                    "result": result,
                }
            )
        return rows


def clear() -> None:
    """Used by tests only."""
    with _lock:
        _watchlist.clear()
        _last_results.clear()
