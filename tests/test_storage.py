from __future__ import annotations

import json

import pytest

from ons_backend.config import AppConfig
from ons_backend.models import AppState, DeviceRegistration, LoginCredentials
from ons_backend.storage import StateStore


def build_config(tmp_path):
    return AppConfig(
        host="127.0.0.1",
        port=8080,
        public_base_url="https://onsrooster.stefhermans.nl",
        data_dir=tmp_path,
        log_level="INFO",
        timezone="Europe/Amsterdam",
        default_login_url="https://example.invalid/login",
        sync_interval_minutes=0,
        sms_timeout_seconds=30,
        login_timeout_seconds=30,
        setup_secret="",
        debug_token="",
        admin_token="",
        storage_key="",
        fcm_project_id="",
        fcm_service_account_file=None,
        fcm_service_account_json="",
        playwright_headless=True,
        post_login_url="",
        roster_url="",
    )


def test_state_store_encrypts_credentials(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)
    credentials = LoginCredentials(
        login_url="https://example.invalid/login",
        username="alice@example.invalid",
        password="super-secret",
    )
    state = AppState()

    store.save(state, credentials)
    raw = config.state_file.read_text(encoding="utf-8")

    assert "alice@example.invalid" not in raw
    assert "super-secret" not in raw

    loaded_state, loaded_credentials = store.load()
    assert loaded_state.to_dict() == state.to_dict()
    assert loaded_credentials == credentials


def test_state_store_persists_sync_enabled_flag(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)
    state = AppState()
    state.sync.sync_enabled = False

    store.save(state, None)
    loaded_state, loaded_credentials = store.load()

    assert loaded_credentials is None
    assert loaded_state.sync.sync_enabled is False


def test_state_store_round_trips_credentials_export(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)
    credentials = LoginCredentials(
        login_url="https://example.invalid/login",
        username="alice@example.invalid",
        password="super-secret",
    )

    bundle = store.build_credentials_export(credentials, "correct horse battery staple")
    raw_bundle = json.dumps(bundle, ensure_ascii=True)

    assert "alice@example.invalid" not in raw_bundle
    assert "super-secret" not in raw_bundle

    decrypted = StateStore.decrypt_credentials_export(bundle, "correct horse battery staple")
    assert decrypted == credentials


def test_state_store_credentials_export_rejects_wrong_passphrase(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)
    bundle = store.build_credentials_export(
        LoginCredentials(
            login_url="https://example.invalid/login",
            username="alice@example.invalid",
            password="super-secret",
        ),
        "correct horse battery staple",
    )

    with pytest.raises(RuntimeError, match="export-passphrase"):
        StateStore.decrypt_credentials_export(bundle, "wrong passphrase")


def test_state_store_persists_snapshot_and_ics(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)

    store.write_snapshot("<html>snapshot</html>")
    store.write_ics(b"BEGIN:VCALENDAR\nEND:VCALENDAR\n")

    assert config.snapshot_file.read_text(encoding="utf-8") == "<html>snapshot</html>"
    assert store.read_ics() == b"BEGIN:VCALENDAR\nEND:VCALENDAR\n"
    assert not config.state_file.exists()


def test_state_store_persists_multiple_devices(tmp_path):
    config = build_config(tmp_path)
    store = StateStore(config)
    state = AppState(
        devices=[
            DeviceRegistration(
                device_id="device-1",
                device_label="Pixel",
                fcm_token="token-1",
                api_token_hash="hash-1",
                created_at="2026-05-25T12:00:00Z",
                updated_at="2026-05-25T12:00:00Z",
                last_seen_at="2026-05-25T12:00:00Z",
            ),
            DeviceRegistration(
                device_id="device-2",
                device_label="Tablet",
                fcm_token="token-2",
                api_token_hash="hash-2",
                created_at="2026-05-25T12:05:00Z",
                updated_at="2026-05-25T12:05:00Z",
                last_seen_at="2026-05-25T12:05:00Z",
            ),
        ],
        active_device_id="device-2",
    )

    store.save(state, None)
    loaded_state, loaded_credentials = store.load()

    assert loaded_credentials is None
    assert loaded_state.active_device_id == "device-2"
    assert [device.device_id for device in loaded_state.devices] == ["device-1", "device-2"]
    assert [device.device_label for device in loaded_state.devices] == ["Pixel", "Tablet"]
