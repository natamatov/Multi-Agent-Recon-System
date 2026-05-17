import pytest

from core.config import validate_target_string


def test_validate_target_string_valid_ipv4():
    assert validate_target_string("192.168.1.1") == "192.168.1.1"
    assert validate_target_string("10.0.0.5") == "10.0.0.5"

def test_validate_target_string_valid_url():
    assert validate_target_string("https://example.com") == "https://example.com"
    assert validate_target_string("http://test.local/") == "http://test.local"
    assert validate_target_string("http://192.168.1.1:8080") == "http://192.168.1.1:8080"

def test_validate_target_string_valid_hostname():
    assert validate_target_string("example.com") == "example.com"
    assert validate_target_string("test.local") == "test.local"
    assert validate_target_string("localhost") == "localhost"

def test_validate_target_string_invalid():
    with pytest.raises(ValueError):
        validate_target_string("http://")

    with pytest.raises(ValueError):
        validate_target_string("invalid_host_name!")
