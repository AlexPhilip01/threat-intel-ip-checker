from unittest.mock import MagicMock, patch

import pytest

from dashboard import scheduler, state
from dashboard.alerts import _is_configured, risk_increased, send_alert


@pytest.fixture(autouse=True)
def clean_state():
    state.clear()
    yield
    state.clear()


# --- state.py -----------------------------------------------------------

def test_add_ip_success():
    added = state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    assert added is True
    assert "8.8.8.8" in state.list_watchlist()


def test_add_duplicate_ip_returns_false():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    added_again = state.add_ip("8.8.8.8", "2026-01-01T00:00:01Z")
    assert added_again is False
    assert state.list_watchlist() == ["8.8.8.8"]


def test_remove_ip():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    assert state.remove_ip("8.8.8.8") is True
    assert state.list_watchlist() == []


def test_remove_nonexistent_ip_returns_false():
    assert state.remove_ip("1.2.3.4") is False


def test_set_and_get_result():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    state.set_result("8.8.8.8", {"overall_risk": "LOW"})
    assert state.get_result("8.8.8.8") == {"overall_risk": "LOW"}


def test_result_ignored_for_ip_no_longer_watched():
    """A slow background check finishing after removal shouldn't resurrect state."""
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    state.remove_ip("8.8.8.8")
    state.set_result("8.8.8.8", {"overall_risk": "HIGH"})
    assert state.get_result("8.8.8.8") is None


def test_snapshot_reflects_pending_then_checked():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")

    snap = state.snapshot()
    assert len(snap) == 1
    assert snap[0]["checked"] is False
    assert snap[0]["result"] is None

    state.set_result("8.8.8.8", {"overall_risk": "LOW"})
    snap = state.snapshot()
    assert snap[0]["checked"] is True
    assert snap[0]["result"]["overall_risk"] == "LOW"


# --- alerts.py: risk_increased -------------------------------------------

def test_risk_increased_true_when_risk_goes_up():
    prev = {"overall_risk": "LOW", "valid": True}
    new = {"overall_risk": "HIGH", "valid": True}
    assert risk_increased(prev, new) is True


def test_risk_increased_false_when_risk_stays_same():
    prev = {"overall_risk": "MEDIUM", "valid": True}
    new = {"overall_risk": "MEDIUM", "valid": True}
    assert risk_increased(prev, new) is False


def test_risk_increased_false_when_risk_decreases():
    prev = {"overall_risk": "HIGH", "valid": True}
    new = {"overall_risk": "LOW", "valid": True}
    assert risk_increased(prev, new) is False


def test_risk_increased_false_with_no_previous_result():
    new = {"overall_risk": "HIGH", "valid": True}
    assert risk_increased(None, new) is False


def test_risk_increased_false_for_invalid_new_result():
    prev = {"overall_risk": "LOW", "valid": True}
    new = {"valid": False, "error": "bad ip"}
    assert risk_increased(prev, new) is False


# --- alerts.py: configuration + sending ----------------------------------

def test_alerts_not_configured_without_env(monkeypatch):
    monkeypatch.delenv("GMAIL_ADDRESS", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("ALERT_EMAIL_TO", raising=False)
    assert _is_configured() is False


def test_alerts_configured_with_env(monkeypatch):
    monkeypatch.setenv("GMAIL_ADDRESS", "a@example.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "app-password")
    monkeypatch.setenv("ALERT_EMAIL_TO", "b@example.com")
    assert _is_configured() is True


def test_send_alert_returns_false_when_not_configured(monkeypatch):
    monkeypatch.delenv("GMAIL_ADDRESS", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.delenv("ALERT_EMAIL_TO", raising=False)
    sent = send_alert("8.8.8.8", {"overall_risk": "LOW"}, {"overall_risk": "HIGH", "sources": []})
    assert sent is False


@patch("dashboard.alerts.smtplib.SMTP")
def test_send_alert_sends_email_when_configured(mock_smtp_cls, monkeypatch):
    monkeypatch.setenv("GMAIL_ADDRESS", "a@example.com")
    monkeypatch.setenv("GMAIL_APP_PASSWORD", "app-password")
    monkeypatch.setenv("ALERT_EMAIL_TO", "b@example.com")

    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    new_result = {
        "overall_risk": "HIGH",
        "sources": [{"source": "virustotal", "risk": "HIGH", "status": "ok"}],
    }
    sent = send_alert("8.8.8.8", {"overall_risk": "LOW"}, new_result)

    assert sent is True
    mock_server.login.assert_called_once_with("a@example.com", "app-password")
    mock_server.send_message.assert_called_once()


# --- scheduler.py ---------------------------------------------------------

def test_run_check_cycle_updates_state_and_fires_alert():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    state.set_result("8.8.8.8", {"overall_risk": "LOW", "valid": True})

    def fake_check_ip(ip, sources):
        return {"overall_risk": "HIGH", "valid": True, "sources": []}

    with patch("dashboard.scheduler.check_ip", side_effect=fake_check_ip), \
         patch("dashboard.scheduler.alerts.send_alert") as mock_send_alert:
        scheduler.run_check_cycle()

    assert state.get_result("8.8.8.8")["overall_risk"] == "HIGH"
    mock_send_alert.assert_called_once()


def test_run_check_cycle_does_not_alert_when_risk_is_unchanged():
    state.add_ip("8.8.8.8", "2026-01-01T00:00:00Z")
    state.set_result("8.8.8.8", {"overall_risk": "LOW", "valid": True})

    def fake_check_ip(ip, sources):
        return {"overall_risk": "LOW", "valid": True, "sources": []}

    with patch("dashboard.scheduler.check_ip", side_effect=fake_check_ip), \
         patch("dashboard.scheduler.alerts.send_alert") as mock_send_alert:
        scheduler.run_check_cycle()

    mock_send_alert.assert_not_called()


def test_run_check_cycle_skips_empty_watchlist():
    with patch("dashboard.scheduler.check_ip") as mock_check_ip:
        scheduler.run_check_cycle()
    mock_check_ip.assert_not_called()
