"""
IP address validation.

Kept deliberately separate from anything network-related so it can be
unit tested with zero mocking and zero API calls.
"""
import ipaddress
from typing import List, Tuple


def validate_ip(ip_str: str) -> Tuple[bool, bool, str]:
    """
    Validate a single IP address string.

    Returns (is_valid, is_private, error_message).
    error_message is None when is_valid is True.
    """
    candidate = (ip_str or "").strip()
    if not candidate:
        return False, False, "empty value"

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return False, False, f"'{candidate}' is not a valid IPv4/IPv6 address"

    return True, ip_obj.is_private, None


def validate_ip_list(raw_text: str) -> Tuple[List[str], List[str]]:
    """
    Validate a newline-separated block of IPs (e.g. an uploaded file).

    Blank lines and lines starting with '#' are treated as comments and
    skipped. Returns (valid_ips, error_messages) — every invalid line is
    reported, rather than aborting the whole batch on the first bad line.
    """
    valid_ips: List[str] = []
    errors: List[str] = []

    for line_no, raw_line in enumerate((raw_text or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        is_valid, _is_private, error = validate_ip(line)
        if is_valid:
            valid_ips.append(line)
        else:
            errors.append(f"line {line_no}: {error}")

    return valid_ips, errors
