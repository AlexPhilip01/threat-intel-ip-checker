"""AbuseIPDB reputation lookup."""
from typing import Any, Dict

import requests

from .base import ThreatSource


class AbuseIPDBSource(ThreatSource):
    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def check(self, ip: str) -> Dict[str, Any]:
        resp = requests.get(
            self.BASE_URL,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def risk_level(self, raw_result: Dict[str, Any]) -> str:
        score = raw_result.get("data", {}).get("abuseConfidenceScore", 0)

        if score >= 75:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"
