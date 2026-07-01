from checker.validator import validate_ip, validate_ip_list


def test_valid_public_ipv4():
    is_valid, is_private, error = validate_ip("8.8.8.8")
    assert is_valid is True
    assert is_private is False
    assert error is None


def test_valid_private_ipv4():
    is_valid, is_private, error = validate_ip("192.168.1.1")
    assert is_valid is True
    assert is_private is True
    assert error is None


def test_valid_ipv6():
    is_valid, is_private, error = validate_ip("2001:4860:4860::8888")
    assert is_valid is True
    assert is_private is False
    assert error is None


def test_invalid_ip_string():
    is_valid, is_private, error = validate_ip("not-an-ip")
    assert is_valid is False
    assert is_private is False
    assert error is not None


def test_invalid_ip_out_of_range():
    is_valid, _is_private, error = validate_ip("999.999.999.999")
    assert is_valid is False
    assert error is not None


def test_empty_string_is_invalid():
    is_valid, _is_private, error = validate_ip("")
    assert is_valid is False
    assert error == "empty value"


def test_whitespace_is_trimmed():
    is_valid, _is_private, _error = validate_ip("  8.8.8.8  ")
    assert is_valid is True


def test_validate_ip_list_mixed_input():
    raw = """
    # a comment line
    8.8.8.8
    not-an-ip
    1.1.1.1

    192.168.0.1
    """
    valid_ips, errors = validate_ip_list(raw)

    assert "8.8.8.8" in valid_ips
    assert "1.1.1.1" in valid_ips
    assert "192.168.0.1" in valid_ips
    assert "not-an-ip" not in valid_ips
    assert len(errors) == 1
    assert "not-an-ip" in errors[0]


def test_validate_ip_list_empty_input():
    valid_ips, errors = validate_ip_list("")
    assert valid_ips == []
    assert errors == []
