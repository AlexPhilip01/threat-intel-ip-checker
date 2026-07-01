"""
Base class for a threat intelligence source.

Adding a new provider (e.g. GreyNoise) means: create a new file in this
package that subclasses ThreatSource and implements check() + risk_level().
Nothing else in the app needs to change — engine.build_sources() is the
only place that needs a new line.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict

# Every source reports risk as one of these four levels so the rest of
# the app (dashboard, CLI, alerts) never has to know provider-specific
# scoring details.
RISK_LEVELS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH")


class ThreatSource(ABC):
    #: short machine-friendly name, e.g. "virustotal"
    name: str = "base"

    def __init__(self, api_key: str = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @abstractmethod
    def check(self, ip: str) -> Dict[str, Any]:
        """Call the provider's API for this IP. Raise on failure."""
        raise NotImplementedError

    @abstractmethod
    def risk_level(self, raw_result: Dict[str, Any]) -> str:
        """Translate a raw API response into one of RISK_LEVELS."""
        raise NotImplementedError

    def safe_check(self, ip: str) -> Dict[str, Any]:
        """
        Wraps check()/risk_level() so one failing or unconfigured source
        can never crash a run against multiple sources.
        """
        if not self.is_configured:
            return {
                "source": self.name,
                "status": "not_configured",
                "risk": "UNKNOWN",
                "detail": "No API key set for this source.",
            }

        try:
            raw = self.check(ip)
            risk = self.risk_level(raw)
            if risk not in RISK_LEVELS:
                risk = "UNKNOWN"
            return {"source": self.name, "status": "ok", "risk": risk, "detail": raw}
        except Exception as exc:  # noqa: BLE001 - intentionally broad, see docstring
            return {
                "source": self.name,
                "status": "error",
                "risk": "UNKNOWN",
                "detail": str(exc),
            }
