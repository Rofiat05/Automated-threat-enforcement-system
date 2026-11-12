import pytest

from alert_sender import check_url, send_file


def test_https_address_is_allowed():
    check_url("https://localhost:8443/v1/alerts")


def test_https_in_capitals_is_allowed():
    check_url("HTTPS://localhost:8443/v1/alerts")


def test_plain_http_address_is_refused():
    with pytest.raises(ValueError):
        check_url("http://localhost:8000/v1/alerts")


def test_other_kinds_of_address_are_refused():
    with pytest.raises(ValueError):
        check_url("ftp://localhost/v1/alerts")


def test_address_with_no_host_is_refused():
    with pytest.raises(ValueError):
        check_url("https:///v1/alerts")


def test_address_with_a_password_is_refused():
    with pytest.raises(ValueError):
        check_url("https://user:secret@localhost:8443/v1/alerts")


def test_address_with_only_a_user_name_is_refused():
    with pytest.raises(ValueError):
        check_url("https://user@localhost:8443/v1/alerts")


def test_send_file_refuses_plain_http_before_reading_anything(tmp_path):
    missing = tmp_path / "nothing.jsonl"
    with pytest.raises(ValueError):
        send_file(missing, b"secret", "http://localhost:8000/v1/alerts")