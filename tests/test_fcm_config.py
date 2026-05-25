from __future__ import annotations

import json

from ons_backend.clients import FcmPushClient
from ons_backend.config import AppConfig
from ons_backend.storage import StateStore


def build_config(tmp_path, *, project_id: str = "", service_account_file=None, service_account_json: str = ""):
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
        fcm_project_id=project_id,
        fcm_service_account_file=service_account_file,
        fcm_service_account_json=service_account_json,
        playwright_headless=True,
        post_login_url="",
        roster_url="",
    )


def test_project_id_is_derived_from_service_account_file(tmp_path):
    service_account_file = tmp_path / "firebase_key.json"
    service_account_file.write_text(
        json.dumps(
            {
                "type": "service_account",
                "project_id": "onsrooster-2bfb9",
                "private_key": "dummy",
                "client_email": "firebase@example.invalid",
            }
        ),
        encoding="utf-8",
    )

    client = FcmPushClient(
        build_config(
            tmp_path,
            service_account_file=service_account_file,
        )
    )

    assert client.project_id() == "onsrooster-2bfb9"
    assert client.is_configured() is True


def test_diagnostics_reports_missing_file(tmp_path):
    client = FcmPushClient(
        build_config(
            tmp_path,
            service_account_file=tmp_path / "missing.json",
        )
    )

    diagnostics = client.diagnostics()
    assert diagnostics["configured"] is False
    assert diagnostics["service_account_file_exists"] is False
    assert diagnostics["config_error"]


def test_project_id_is_derived_from_uploaded_encrypted_key(tmp_path):
    config = build_config(
        tmp_path,
        project_id="",
        service_account_json="",
    )
    store = StateStore(config)
    store.write_managed_fcm_service_account(
        json.dumps(
            {
                "type": "service_account",
                "project_id": "onsrooster-2bfb9",
                "private_key": "dummy",
                "client_email": "firebase@example.invalid",
            }
        )
    )

    client = FcmPushClient(config)

    assert client.project_id() == "onsrooster-2bfb9"
    diagnostics = client.diagnostics()
    assert diagnostics["configured"] is True
    assert diagnostics["service_account_source"] == "uploaded_file"