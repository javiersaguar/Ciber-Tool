"""Privacidad, retención, detección y agregación con SQLite real."""

import json
import os
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from atalaya.modules.ssh_honeypot import HoneypotInputs
from atalaya.services.state_lock import state_lock
from atalaya.services.storage import Pseudonymizer, Store, initialize_secrets, private_directory

NOW = datetime(2026, 9, 12, 12, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def store(tmp_path):
    inputs = HoneypotInputs(data_dir=tmp_path / "state", alert_threshold=3, max_events=100)
    private_directory(inputs.data_dir)
    value = Store(inputs)
    yield value
    value.close()


def attempt(password="real-leaked-secret", ip="8.8.8.8", at=NOW):
    return Pseudonymizer(b"k" * 32).attempt(
        ip, "private.person@example.org", password, "SSH-2.0-testbot", at
    )


def test_no_plaintext_credentials_in_events_disk_or_reports(store):
    event = attempt()
    store.record([event], NOW)
    data = json.dumps(store.dashboard(NOW))
    raw = (store.inputs.data_dir / "events.sqlite3").read_bytes()
    for secret in ("real-leaked-secret", "private.person@example.org"):
        assert secret not in data
        assert secret.encode() not in raw
    assert "8.8.8.8" in data
    assert "SSH-2.0-testbot" in data
    assert len(event["password_id"]) == 64


def test_hmac_domains_rotation_and_attempt_fingerprint():
    first = attempt()
    same = attempt(at=NOW + 1)
    assert first["id"] != same["id"]
    assert first["fingerprint"] == same["fingerprint"]
    assert first["password_id"] == same["password_id"]
    assert first["password_id"] != attempt(password="other")["password_id"]
    assert first["password_id"] != attempt(at=NOW + 86400)["password_id"]
    assert (
        first["password_id"]
        != Pseudonymizer(b"x" * 32).attempt(
            "8.8.8.8", "private.person@example.org", "real-leaked-secret", "SSH-2.0-testbot", NOW
        )["password_id"]
    )
    assert first["password_id"] == attempt(ip="1.1.1.1")["password_id"]
    assert first["fingerprint"] != attempt(ip="1.1.1.1")["fingerprint"]
    assert len({first[k] for k in ("username_id", "password_id", "credential_id")}) == 3


def test_ipv4_mapped_addresses_cannot_evade_identity():
    assert attempt(ip="::ffff:8.8.8.8")["fingerprint"] == attempt()["fingerprint"]


def test_client_version_is_bounded_and_controls_removed():
    event = Pseudonymizer(b"k" * 32).attempt("127.0.0.1", "a", "b", "bad\x1b\n" * 300, NOW)
    assert len(event["client_version"]) == 255
    assert "\x1b" not in event["client_version"]
    assert "\n" not in event["client_version"]


def test_detection_uses_distinct_passwords_and_deduplicates_window(store):
    events = [attempt("one", at=NOW + i) for i in range(10)]
    assert all(f is None for _, f in store.record(events, NOW + 10))
    assert store.record([attempt("two", at=NOW + 11)], NOW + 11)[0][1] is None
    finding = store.record([attempt("three", at=NOW + 12)], NOW + 12)[0][1]
    assert finding.severity.value == "high"
    assert "3 contraseñas" in finding.description
    assert store.record([attempt("four", at=NOW + 13)], NOW + 13)[0][1] is None
    assert len(store.restore_findings(NOW + 14)) == 1


def test_400_distinct_passwords_in_two_minutes(tmp_path):
    inputs = HoneypotInputs(data_dir=tmp_path / "state")
    private_directory(inputs.data_dir)
    store = Store(inputs)
    try:
        emitted = store.record([attempt(str(i), at=NOW + i / 4) for i in range(400)], NOW + 100)
        assert sum(f is not None for _, f in emitted) == 1
        assert "400 contraseñas" in emitted[-1][1].description
    finally:
        store.close()


def test_detection_excludes_old_attempts_and_other_ips(store):
    events = [attempt("a", at=NOW - 121), attempt("b"), attempt("c", ip="1.1.1.1")]
    assert all(f is None for _, f in store.record(events, NOW))
    assert store.record([attempt("d", at=NOW + 1)], NOW + 1)[0][1] is None


def test_midnight_rotation_does_not_double_count_a_password(store):
    midnight = NOW + 12 * 3600
    events = [
        attempt("a", at=midnight - 1),
        attempt("a", at=midnight),
        attempt("b", at=midnight + 1),
    ]
    assert all(f is None for _, f in store.record(events, midnight + 1))


def test_retention_and_row_cap_apply_while_idle(store):
    store.record([attempt(str(i), at=NOW + i) for i in range(150)], NOW + 150)
    snapshot = store.dashboard(NOW + 150)
    assert snapshot["total"] == 100
    assert len(snapshot["recent"]) == 50
    assert len(snapshot["timeline"]) == 60
    assert store.dashboard(NOW + 25 * 3600)["total"] == 0
    assert store.restore_findings(NOW + 25 * 3600) == []
    assert store.db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    assert store.db.execute("PRAGMA max_page_count").fetchone()[0] == 65536


def test_ranking_timeline_and_unknown_locations(store):
    store.record(
        [attempt("a", at=NOW), attempt("a", at=NOW + 1), attempt("b", at=NOW + 61)], NOW + 62
    )
    snapshot = store.dashboard(NOW + 62)
    assert snapshot["ranking"][0]["count"] == 2
    assert [point["count"] for point in snapshot["timeline"][-2:]] == [2, 1]
    assert snapshot["origins"][0]["location"] is None
    assert snapshot["geoip_enabled"] is False


def test_geoip_is_offline_and_private_ips_are_not_located(store):
    class Geo:
        def get(self, ip):
            assert ip == "8.8.8.8"
            return {
                "country": {"iso_code": "US"},
                "location": {"latitude": 38, "longitude": -97, "accuracy_radius": 1000},
            }

        def close(self):
            pass

    store.geo = Geo()
    assert store.location("8.8.8.8")["accuracy_km"] == 1000
    assert store.location("127.0.0.1") is None
    assert store.location("10.1.2.3") is None


def test_state_secrets_are_persistent_and_separate(tmp_path):
    path = tmp_path / "state"
    first, token, host = initialize_secrets(path)
    again, same_token, same_host = initialize_secrets(path)
    assert token == same_token and host == same_host
    assert (
        first.attempt("127.0.0.1", "a", "b", "c", NOW)["password_id"]
        == again.attempt("127.0.0.1", "a", "b", "c", NOW)["password_id"]
    )
    assert len((path / "hmac.key").read_bytes()) == 32
    assert len(token) >= 32
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
        assert (path / "hmac.key").stat().st_mode & 0o077 == 0


def test_state_lock_excludes_another_instance_and_releases(tmp_path):
    path = tmp_path / "state"
    with state_lock(path), pytest.raises(OSError), state_lock(path):
        pass
    with state_lock(path):
        pass


@pytest.mark.parametrize(
    "kwargs",
    [
        {"host": "example.org"},
        {"dashboard_host": "0.0.0.0"},
        {"dashboard_host": "::"},
        {"port": 22},
        {"max_connections": 0},
        {"max_connections": 1, "max_per_ip": 3},
        {"max_events": 100, "alert_threshold": 400},
        {"report_window": 10},
        {"login_timeout": 0},
        {"auth_delay": 0},
        {"retention_hours": 1, "report_window": 7200},
    ],
)
def test_unsafe_or_inconsistent_config_is_rejected(kwargs):
    with pytest.raises(ValidationError):
        HoneypotInputs(**kwargs)
