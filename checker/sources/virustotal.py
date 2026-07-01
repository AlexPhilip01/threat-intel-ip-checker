"""VirusTotal IP reputation lookup (API v3)."""
from typing import Any, Dict

import requests

from .base import ThreatSource


class VirusTotalSource(ThreatSource):
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def check(self, ip: str) -> Dict[str, Any]:
        resp = requests.get(
            self.BASE_URL.format(ip=ip),
            headers={"x-apikey": self.api_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def risk_level(self, raw_result: Dict[str, Any]) -> str:
        stats = (
            raw_result.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            return "HIGH"
        if malicious >= 1 or suspicious >= 2:
            return "MEDIUM"
        return "LOW"
