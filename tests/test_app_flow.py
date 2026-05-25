from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import FormData

from ons_backend.app import create_app
from ons_backend.clients import FcmPushClient
from ons_backend.config import AppConfig
from ons_backend.models import AuthenticationResult, RosterItem
from ons_backend.service import BackendService
from ons_backend.storage import StateStore


class FakePushClient:
    def __init__(self) -> None:
        self.listen_requests: list[str] = []
        self.auth_notifications: list[tuple[bool, str]] = []

    def is_configured(self) -> bool:
        return True

    async def send_listen_sms(self, device, challenge_id: str, timeout_seconds: int) -> None:
        self.listen_requests.append(challenge_id)

    async def send_auth_result(self, device, success: bool, message: str) -> None:
        self.auth_notifications.append((success, message))


class FakeAutomationClient:
    def __init__(self) -> None:
        self.received_codes: list[str] = []

    async def authenticate_and_scrape(self, credentials, request_sms_code, snapshot_path, config):
        code = await request_sms_code()
        self.received_codes.append(code)
        snapshot_path.write_text("<html>ok</html>", encoding="utf-8")
        return AuthenticationResult(
            final_url="https://example.invalid/rooster",
            page_title="Rooster",
            roster_items=[
                RosterItem(
                    date="24-05-2026",
                    start="08:00",
                    end="16:00",
                    description="Vroege dienst",
                )
            ],
            debug_notes=["Authentication completed in the fake client."],
            auth_ready=True,
        )


async def wait_for(condition, timeout: float = 1.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("Timed out while waiting for the expected condition.")


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
        setup_secret="setup-code",
        debug_token="debug-code",
        admin_token="admin-code",
        storage_key="",
        fcm_project_id="test-project",
        fcm_service_account_file=None,
        fcm_service_account_json=json.dumps(
            {
                "type": "service_account",
                "project_id": "test-project",
                "private_key": "dummy",
                "client_email": "firebase@example.invalid",
            }
        ),
        playwright_headless=True,
        post_login_url="",
        roster_url="",
    )


@pytest.fixture
async def test_context(tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    automation_client = FakeAutomationClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=automation_client,
    )
    app = create_app(config=config, service=service)
    yield app, service, push_client, automation_client


@pytest.mark.asyncio
async def test_mobile_setup_and_sms_roundtrip(aiohttp_client, test_context):
    app, service, push_client, automation_client = test_context
    client = await aiohttp_client(app)

    response = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-1",
            "device_label": "Pixel",
        },
    )
    assert response.status == 200
    payload = await response.json()
    api_token = payload["api_token"]
    assert api_token

    await wait_for(lambda: len(push_client.listen_requests) == 1)
    assert len(push_client.listen_requests) == 1
    challenge_id = push_client.listen_requests[0]

    sms_response = await client.post(
        f"/api/v1/mobile/challenges/{challenge_id}/sms-code",
        headers={"Authorization": f"Bearer {api_token}"},
        json={"code": "123456", "sender": "ONS"},
    )
    assert sms_response.status == 200

    await asyncio.sleep(0)
    await service.trigger_refresh(reason="assert-state", wait=True)

    assert automation_client.received_codes == ["123456"]
    status = service.mobile_status_payload()
    assert status["sync"]["status"] == "success"
    assert push_client.auth_notifications[-1][0] is True


@pytest.mark.asyncio
async def test_debug_endpoint_requires_token(aiohttp_client, test_context):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)

    unauthorized = await client.get("/debug")
    assert unauthorized.status == 401

    authorized = await client.get("/debug?token=debug-code")
    assert authorized.status == 200


@pytest.mark.asyncio
async def test_admin_fcm_status_and_test_endpoint(aiohttp_client, test_context):
    app, _, push_client, _ = test_context
    client = await aiohttp_client(app)

    setup_response = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-1",
            "device_label": "Pixel",
        },
    )
    assert setup_response.status == 200

    status_response = await client.get("/api/v1/admin/fcm?token=admin-code")
    assert status_response.status == 200
    status_payload = await status_response.json()
    assert status_payload["configured"] is True
    assert status_payload["device_registered"] is True
    assert status_payload["device_has_token"] is True
    assert status_payload["project_id"] == "test-project"

    test_response = await client.post(
        "/api/v1/admin/fcm/test?token=admin-code",
        json={"message": "FCM testbericht"},
    )
    assert test_response.status == 200
    assert push_client.auth_notifications[-1] == (True, "FCM testbericht")


@pytest.mark.asyncio
async def test_install_page_uploads_encrypted_firebase_key(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    config = AppConfig(
        host=config.host,
        port=config.port,
        public_base_url=config.public_base_url,
        data_dir=config.data_dir,
        log_level=config.log_level,
        timezone=config.timezone,
        default_login_url=config.default_login_url,
        sync_interval_minutes=config.sync_interval_minutes,
        sms_timeout_seconds=config.sms_timeout_seconds,
        login_timeout_seconds=config.login_timeout_seconds,
        setup_secret=config.setup_secret,
        debug_token=config.debug_token,
        admin_token=config.admin_token,
        storage_key=config.storage_key,
        fcm_project_id="",
        fcm_service_account_file=None,
        fcm_service_account_json="",
        playwright_headless=config.playwright_headless,
        post_login_url=config.post_login_url,
        roster_url=config.roster_url,
    )
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=FcmPushClient(config),
        automation_client=FakeAutomationClient(),
    )
    app = create_app(config=config, service=service)
    client = await aiohttp_client(app)

    form = FormData()
    form.add_field("admin_token", "admin-code")
    form.add_field(
        "firebase_key",
        json.dumps(
            {
                "type": "service_account",
                "project_id": "onsrooster-2bfb9",
                "private_key": "dummy",
                "client_email": "firebase@example.invalid",
            }
        ),
        filename="firebase_key.json",
        content_type="application/json",
    )

    response = await client.post("/install", data=form)
    assert response.status == 200
    body = await response.text()
    assert "De Firebase-sleutel is opgeslagen" in body
    assert config.managed_fcm_service_account_file.exists()
    assert "private_key" not in config.managed_fcm_service_account_file.read_text(encoding="utf-8")

    status_response = await client.get("/api/v1/admin/fcm?token=admin-code")
    assert status_response.status == 200
    payload = await status_response.json()
    assert payload["configured"] is True
    assert payload["project_id"] == "onsrooster-2bfb9"
    assert payload["service_account_source"] == "uploaded_file"