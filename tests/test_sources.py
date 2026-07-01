from unittest.mock import MagicMock, patch

from checker.sources.abuseipdb import AbuseIPDBSource
from checker.sources.base import ThreatSource
from checker.sources.shodan import ShodanSource
from checker.sources.virustotal import VirusTotalSource


class DummySource(ThreatSource):
    """Minimal concrete ThreatSource used to test safe_check() in isolation."""

    name = "dummy"

    def __init__(self, api_key=None, raise_error=False, raw_result=None):
        super().__init__(api_key=api_key)
        self.raise_error = raise_error
        self.raw_result = raw_result or {}

    def check(self, ip):
        if self.raise_error:
            raise RuntimeError("boom")
        return self.raw_result

    def risk_level(self, raw_result):
        return "HIGH"


def test_safe_check_reports_not_configured_without_api_key():
    source = DummySource(api_key=None)
    result = source.safe_check("8.8.8.8")
    assert result["status"] == "not_configured"
    assert result["risk"] == "UNKNOWN"


def test_safe_check_ok_path():
    source = DummySource(api_key="key", raw_result={"x": 1})
    result = source.safe_check("8.8.8.8")
    assert result["status"] == "ok"
    assert result["risk"] == "HIGH"
    assert result["detail"] == {"x": 1}


def test_safe_check_contains_exceptions():
    """A source that raises must never propagate — it degrades to UNKNOWN."""
    source = DummySource(api_key="key", raise_error=True)
    result = source.safe_check("8.8.8.8")
    assert result["status"] == "error"
    assert result["risk"] == "UNKNOWN"
    assert "boom" in result["detail"]


def _mock_response(json_data):
    mock_resp = MagicMock()
    mock_resp.json.return_value = json_data
    mock_resp.raise_for_status.return_value = None
    return mock_resp


@patch("checker.sources.virustotal.requests.get")
def test_virustotal_high_risk_on_multiple_malicious_votes(mock_get):
    mock_get.return_value = _mock_response(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}}
    )
    result = VirusTotalSource(api_key="key").safe_check("1.2.3.4")
    assert result["status"] == "ok"
    assert result["risk"] == "HIGH"


@patch("checker.sources.virustotal.requests.get")
def test_virustotal_low_risk_when_clean(mock_get):
    mock_get.return_value = _mock_response(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
    )
    result = VirusTotalSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "LOW"


@patch("checker.sources.virustotal.requests.get")
def test_virustotal_network_failure_is_contained(mock_get):
    mock_get.side_effect = Exception("connection refused")
    result = VirusTotalSource(api_key="key").safe_check("1.2.3.4")
    assert result["status"] == "error"
    assert result["risk"] == "UNKNOWN"


@patch("checker.sources.abuseipdb.requests.get")
def test_abuseipdb_medium_risk(mock_get):
    mock_get.return_value = _mock_response({"data": {"abuseConfidenceScore": 40}})
    result = AbuseIPDBSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "MEDIUM"


@patch("checker.sources.abuseipdb.requests.get")
def test_abuseipdb_high_risk(mock_get):
    mock_get.return_value = _mock_response({"data": {"abuseConfidenceScore": 90}})
    result = AbuseIPDBSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "HIGH"


@patch("checker.sources.abuseipdb.requests.get")
def test_abuseipdb_low_risk(mock_get):
    mock_get.return_value = _mock_response({"data": {"abuseConfidenceScore": 5}})
    result = AbuseIPDBSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "LOW"


@patch("checker.sources.shodan.requests.get")
def test_shodan_high_risk_with_vulns(mock_get):
    mock_get.return_value = _mock_response({"vulns": ["CVE-2024-0001"], "ports": [22, 80]})
    result = ShodanSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "HIGH"


@patch("checker.sources.shodan.requests.get")
def test_shodan_medium_risk_many_open_ports(mock_get):
    mock_get.return_value = _mock_response({"vulns": [], "ports": [21, 22, 23, 80, 443, 8080]})
    result = ShodanSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "MEDIUM"


@patch("checker.sources.shodan.requests.get")
def test_shodan_low_risk_no_vulns_few_ports(mock_get):
    mock_get.return_value = _mock_response({"vulns": [], "ports": [22]})
    result = ShodanSource(api_key="key").safe_check("1.2.3.4")
    assert result["risk"] == "LOW"


def test_sources_not_configured_never_call_network():
    """No API key set -> safe_check must short-circuit before any HTTP call."""
    with patch("checker.sources.virustotal.requests.get") as mock_get:
        result = VirusTotalSource(api_key=None).safe_check("1.2.3.4")
        assert result["status"] == "not_configured"
        mock_get.assert_not_called()
