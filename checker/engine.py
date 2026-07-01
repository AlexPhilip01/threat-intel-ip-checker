"""
Shared checking engine.

This is the ONE place that knows how to turn "an IP" into "a checked
result." Both checker.cli (one-off / bulk CLI runs) and dashboard.routes
(the live web app) import build_sources() and check_ip() from here —
no duplicated logic, no drift between the two front ends.
"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .sources.abuseipdb import AbuseIPDBSource
from .sources.base import ThreatSource
from .sources.shodan import ShodanSource
from .sources.virustotal import VirusTotalSource
from .validator import validate_ip

RISK_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def build_sources() -> List[ThreatSource]:
    """Instantiate every known source from environment variables."""
    return [
        VirusTotalSource(api_key=os.environ.get("VIRUSTOTAL_API_KEY")),
        AbuseIPDBSource(api_key=os.environ.get("ABUSEIPDB_API_KEY")),
        ShodanSource(api_key=os.environ.get("SHODAN_API_KEY")),
    ]


def _overall_risk(source_results: List[Dict[str, Any]]) -> str:
    """The overall risk for an IP is the highest risk any source reported."""
    if not source_results:
        return "UNKNOWN"
    return max(source_results, key=lambda r: RISK_ORDER.get(r["risk"], 0))["risk"]


def check_ip(ip: str, sources: Optional[List[ThreatSource]] = None) -> Dict[str, Any]:
    """
    Check a single IP against all configured sources, in parallel.

    Returns a dict that is JSON-serializable as-is, used directly by the
    CLI reporter and the dashboard's /api/watchlist endpoint.
    """
    is_valid, is_private, error = validate_ip(ip)
    if not is_valid:
        return {"ip": ip, "valid": False, "error": error}

    sources = sources if sources is not None else build_sources()

    results: List[Dict[str, Any]] = []
    if sources:
        with ThreadPoolExecutor(max_workers=len(sources)) as pool:
            futures = {pool.submit(source.safe_check, ip): source for source in sources}
            for future in as_completed(futures):
                results.append(future.result())

    return {
        "ip": ip,
        "valid": True,
        "is_private": is_private,
        "overall_risk": _overall_risk(results),
        "sources": results,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def check_ips(ips: List[str], sources: Optional[List[ThreatSource]] = None) -> List[Dict[str, Any]]:
    """Convenience helper for checking a batch of IPs (CLI bulk mode)."""
    sources = sources if sources is not None else build_sources()
    return [check_ip(ip, sources) for ip in ips]
