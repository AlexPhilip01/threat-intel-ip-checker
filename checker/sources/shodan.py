"""Shodan host lookup — used for exposed-service / vulnerability signal."""
from typing import Any, Dict

import requests

from .base import ThreatSource


class ShodanSource(ThreatSource):
    name = "shodan"
    BASE_URL = "https://api.shodan.io/shodan/host/{ip}"

    def check(self, ip: str) -> Dict[str, Any]:
        resp = requests.get(
            self.BASE_URL.format(ip=ip),
            params={"key": self.api_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def risk_level(self, raw_result: Dict[str, Any]) -> str:
        vulns = raw_result.get("vulns") or []
        ports = raw_result.get("ports") or []

        if len(vulns) > 0:
            return "HIGH"
        if len(ports) > 5:
            return "MEDIUM"
        return "LOW"
