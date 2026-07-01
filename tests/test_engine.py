from checker.engine import build_sources, check_ip
from checker.sources.base import ThreatSource


class FakeSource(ThreatSource):
    """A source with a hard-coded risk, for testing aggregation logic
    without touching real HTTP calls."""

    def __init__(self, name, risk, configured=True):
        super().__init__(api_key="key" if configured else None)
        self.name = name
        self._risk = risk

    def check(self, ip):
        return {}

    def risk_level(self, raw_result):
        return self._risk


def test_check_ip_rejects_invalid_ip():
    result = check_ip("not-an-ip", sources=[])
    assert result["valid"] is False
    assert "error" in result


def test_check_ip_overall_risk_is_the_max_across_sources():
    sources = [FakeSource("a", "LOW"), FakeSource("b", "HIGH"), FakeSource("c", "MEDIUM")]
    result = check_ip("8.8.8.8", sources=sources)
    assert result["valid"] is True
    assert result["overall_risk"] == "HIGH"
    assert len(result["sources"]) == 3


def test_check_ip_with_no_sources_is_unknown():
    result = check_ip("8.8.8.8", sources=[])
    assert result["valid"] is True
    assert result["overall_risk"] == "UNKNOWN"
    assert result["sources"] == []


def test_check_ip_flags_private_addresses():
    result = check_ip("192.168.1.1", sources=[])
    assert result["is_private"] is True


def test_check_ip_flags_public_addresses():
    result = check_ip("8.8.8.8", sources=[])
    assert result["is_private"] is False


def test_check_ip_includes_checked_at_timestamp():
    result = check_ip("8.8.8.8", sources=[])
    assert result.get("checked_at")


def test_build_sources_returns_three_sources_unconfigured(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    sources = build_sources()
    assert len(sources) == 3
    assert all(not s.is_configured for s in sources)


def test_build_sources_picks_up_env_keys(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "abc123")
    sources = build_sources()
    virustotal_source = next(s for s in sources if s.name == "virustotal")
    assert virustotal_source.is_configured is True
