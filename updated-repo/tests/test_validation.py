import pytest

from cisco_driver.config import Settings
from cisco_driver.validation import (
    ValidationError,
    clean_text,
    validate_ip,
    validate_name,
    validate_ttl,
)


@pytest.mark.parametrize("value, expected", [
    ("203.0.113.7", "203.0.113.7"),
    ("  198.51.100.23 ", "198.51.100.23"),
    ("192.168.10.50", "192.168.10.50"),  # internal attackers can be blocked too
    ("10.20.30.40", "10.20.30.40"),
    ("172.16.5.9", "172.16.5.9"),
    ("8.8.8.8", "8.8.8.8"),              # ordinary public address
    # RFC 5737 documentation ranges: accepted ON PURPOSE as mock/test fixtures
    ("192.0.2.50", "192.0.2.50"),        # TEST-NET-1
    ("198.51.100.23", "198.51.100.23"),  # TEST-NET-2
    ("203.0.113.255", "203.0.113.255"),  # TEST-NET-3
])
def test_valid_ips(value, expected):
    assert validate_ip(value) == expected


@pytest.mark.parametrize("value", [
    "10.0.0.0/8",          # a whole network - never allowed
    "203.0.113.7/32",
    "abc",
    "999.1.1.1",
    "",
    "1.2.3.4; reload",     # command injection attempt
    "0.0.0.0",             # unspecified
    "127.0.0.1",           # loopback
    "127.255.0.9",
    "224.0.0.5",           # multicast
    "239.1.2.3",
    "240.0.0.1",           # reserved (Class E)
    "255.255.255.255",     # limited broadcast (inside 240.0.0.0/4)
    "169.254.1.1",         # link-local
    "2001:db8::1",         # IPv6 not supported by this ACL
    None,
    12345,
])
def test_invalid_ips_are_rejected(value):
    with pytest.raises(ValidationError):
        validate_ip(value)


def test_ttl_limits():
    assert validate_ttl(60, 60, 86400) == 60
    for bad in (59, 86401, -1, 0, "60", 60.5, True):
        with pytest.raises(ValidationError):
            validate_ttl(bad, 60, 86400)


@pytest.mark.parametrize("name", ["../etc", "R1/x", "R1?a=b", "", "1R", "a" * 65, "R 1"])
def test_unsafe_names_rejected(name):
    with pytest.raises(ValidationError):
        validate_name(name, "device")


def test_clean_text_removes_newlines_and_limits_length():
    assert clean_text("a\nb\rc") == "a b c"
    assert len(clean_text("x" * 500)) == 200
    assert clean_text(None) == ""


def test_settings_from_env_and_password_hidden():
    s = Settings.from_env({
        "RESTCONF_DEVICES": "R1=https://10.0.0.1:443, R2=https://10.0.0.2",
        "RESTCONF_PASSWORD": "secret-value",
        "RESTCONF_VERIFY": "false",
    })
    assert s.devices == {"R1": "https://10.0.0.1:443", "R2": "https://10.0.0.2"}
    assert s.verify_tls is False
    assert "secret-value" not in repr(s)


def test_settings_require_password_and_devices():
    with pytest.raises(ValueError):
        Settings.from_env({"RESTCONF_PASSWORD": "x"})
    with pytest.raises(ValueError):
        Settings.from_env({"RESTCONF_DEVICES": "R1=https://h"})
    with pytest.raises(ValueError):
        Settings.from_env({"RESTCONF_DEVICES": "R1", "RESTCONF_PASSWORD": "x"})
