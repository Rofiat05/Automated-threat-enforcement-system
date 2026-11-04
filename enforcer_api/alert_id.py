import hashlib


def make_alert_id(host, source_ip, window_start, window_seconds):
    text = f"{host}|{source_ip}|{window_start}|{window_seconds}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()