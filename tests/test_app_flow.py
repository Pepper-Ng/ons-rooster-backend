from __future__ import annotations

import asyncio
import json
import re
from datetime import date

import pytest
import requests
from aiohttp import FormData

from ons_backend.app import create_app
from ons_backend.clients import FcmPushClient, HttpLoginAutomationClient
from ons_backend.config import AppConfig
from ons_backend.models import AuthenticationResult, LoginCredentials, RosterItem
from ons_backend.service import BackendService
from ons_backend.storage import StateStore


class FakePushClient:
    def __init__(self) -> None:
        self.listen_requests: list[str] = []
        self.auth_notifications: list[tuple[bool, str]] = []
        self.auth_targets: list[str] = []

    def is_configured(self) -> bool:
        return True

    async def send_listen_sms(self, device, challenge_id: str, timeout_seconds: int) -> None:
        self.listen_requests.append(challenge_id)

    async def send_auth_result(self, device, success: bool, message: str) -> None:
        self.auth_targets.append(device.device_id)
        self.auth_notifications.append((success, message))


class FakeAutomationClient:
    def __init__(self) -> None:
        self.received_codes: list[str] = []

    async def authenticate_and_scrape(
        self,
        credentials,
        request_sms_code,
        snapshot_path,
        config,
        report_progress=None,
        session_checkpoint=None,
        prepare_sms_relay=None,
        wait_for_sms_code=None,
    ):
        del session_checkpoint, prepare_sms_relay, wait_for_sms_code
        if report_progress is not None:
            await report_progress(
                {
                    "entry_id": "step-001",
                    "created_at": "2026-05-30T00:00:00Z",
                    "label": "Fake auth start",
                    "message": "De fake client is gestart.",
                    "phase": "fake_start",
                    "url": credentials.login_url,
                    "page_title": "Fake Login",
                    "snapshot_name": "001-fake-auth-start.html",
                }
            )
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


class FakeCheckpointAutomationClient:
    async def authenticate_and_scrape(
        self,
        credentials,
        request_sms_code,
        snapshot_path,
        config,
        report_progress=None,
        session_checkpoint=None,
        prepare_sms_relay=None,
        wait_for_sms_code=None,
    ):
        del credentials, request_sms_code, config, session_checkpoint, prepare_sms_relay, wait_for_sms_code
        if report_progress is not None:
            await report_progress(
                {
                    "entry_id": "step-001",
                    "created_at": "2026-05-30T00:00:00Z",
                    "label": "OTP challenge detected",
                    "message": "De fake checkpoint client heeft een OTP-pagina gevonden.",
                    "phase": "otp_detected",
                    "url": "https://example.invalid/two_factor",
                    "page_title": "OTP",
                    "snapshot_name": "001-otp-challenge-detected.html",
                }
            )
        snapshot_path.write_text(
            "<html><head><title>OTP</title></head><body><form action='/verify_token' method='post'><input type='hidden' name='_csrf_token' value='otp-csrf'><input type='text' name='token'></form></body></html>",
            encoding="utf-8",
        )
        return AuthenticationResult(
            final_url="https://example.invalid/two_factor",
            page_title="OTP",
            roster_items=[],
            debug_notes=["OTP checkpoint saved."],
            auth_ready=False,
            session_checkpoint={
                "version": 1,
                "current_url": "https://example.invalid/two_factor",
                "challenge": {
                    "challenge_kind": "otp",
                    "action_url": "https://example.invalid/verify_token",
                    "method": "post",
                    "otp_input_name": "token",
                    "hidden_fields": {"_csrf_token": "otp-csrf"},
                },
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie",
                        "domain": "example.invalid",
                        "path": "/",
                        "secure": True,
                        "expires": None,
                    }
                ],
            },
        )


class FakeMfaSelectionAutomationClient:
    async def authenticate_and_scrape(
        self,
        credentials,
        request_sms_code,
        snapshot_path,
        config,
        report_progress=None,
        session_checkpoint=None,
        prepare_sms_relay=None,
        wait_for_sms_code=None,
    ):
        del credentials, request_sms_code, config, session_checkpoint, prepare_sms_relay, wait_for_sms_code
        if report_progress is not None:
            await report_progress(
                {
                    "entry_id": "step-001",
                    "created_at": "2026-05-30T00:00:00Z",
                    "label": "MFA selection detected",
                    "message": "De fake SSO-client heeft de Microsoft verificatiekeuze bereikt.",
                    "phase": "mfa_selection_detected",
                    "url": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
                    "page_title": "Aanmelden bij uw account",
                    "snapshot_name": "001-mfa-selection-detected.html",
                }
            )
        snapshot_path.write_text(
            "<html><head><title>Aanmelden bij uw account</title></head><body><div id='idDiv_SAOTCS_Title'>Bevestig uw identiteit</div></body></html>",
            encoding="utf-8",
        )
        return AuthenticationResult(
            final_url="https://login.microsoftonline.com/common/SAS/ProcessAuth",
            page_title="Aanmelden bij uw account",
            roster_items=[],
            debug_notes=["Microsoft proof selection checkpoint saved."],
            auth_ready=False,
            session_checkpoint={
                "version": 1,
                "current_url": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
                "challenge": {
                    "challenge_kind": "microsoft_proof_selection",
                    "action_url": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
                    "method": "post",
                    "proof_input_name": "mfaAuthMethod",
                    "sms_proof_value": "OneWaySMS",
                    "sms_proof": {
                        "auth_method_id": "OneWaySMS",
                        "data": "OneWaySMS",
                        "display": "+XX XXXXXXX32",
                        "phone_number_suffix": "32",
                    },
                    "proofs": [
                        {
                            "auth_method_id": "OneWaySMS",
                            "data": "OneWaySMS",
                            "display": "+XX XXXXXXX32",
                            "phone_number_suffix": "32",
                        }
                    ],
                    "hidden_fields": {"flowToken": "flow-token", "ctx": "ctx-token"},
                },
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie",
                        "domain": "login.microsoftonline.com",
                        "path": "/",
                        "secure": True,
                        "expires": None,
                    }
                ],
            },
        )


class FakeResumeAutomationClient:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    async def authenticate_and_scrape(
        self,
        credentials,
        request_sms_code,
        snapshot_path,
        config,
        report_progress=None,
        session_checkpoint=None,
        prepare_sms_relay=None,
        wait_for_sms_code=None,
    ):
        del credentials, request_sms_code, config, report_progress
        assert session_checkpoint is not None
        assert prepare_sms_relay is not None
        assert wait_for_sms_code is not None
        assert session_checkpoint["challenge"]["challenge_kind"] == "microsoft_proof_selection"

        challenge_id = await prepare_sms_relay()
        self.events.append(("armed", challenge_id))
        self.events.append(("clicked_sms_button", challenge_id))
        sms_code = await wait_for_sms_code(challenge_id)
        self.events.append(("received_code", sms_code))

        snapshot_path.write_text("<html><head><title>Na OTP</title></head><body>Welkom terug in de portal.</body></html>", encoding="utf-8")
        return AuthenticationResult(
            final_url="https://example.invalid/post-otp",
            page_title="Na OTP",
            roster_items=[],
            debug_notes=["Resumed from the stored Microsoft proof selection and submitted the OTP."],
            auth_ready=False,
            session_checkpoint={
                "version": 1,
                "current_url": "https://example.invalid/post-otp",
                "challenge": {
                    "challenge_kind": "post_otp_result_page",
                    "page_summary": "Welkom terug in de portal.",
                    "source": "microsoft_sso",
                },
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie",
                        "domain": "example.invalid",
                        "path": "/",
                        "secure": True,
                        "expires": None,
                    }
                ],
            },
        )


class CountingAutomationClient:
    def __init__(self) -> None:
        self.call_count = 0

    async def authenticate_and_scrape(
        self,
        credentials,
        request_sms_code,
        snapshot_path,
        config,
        report_progress=None,
        session_checkpoint=None,
        prepare_sms_relay=None,
        wait_for_sms_code=None,
    ):
        del request_sms_code, config, report_progress, session_checkpoint, prepare_sms_relay, wait_for_sms_code
        self.call_count += 1
        snapshot_path.write_text("<html>ok</html>", encoding="utf-8")
        return AuthenticationResult(
            final_url=credentials.login_url,
            page_title="Rooster",
            roster_items=[],
            debug_notes=[f"Counting attempt {self.call_count}."],
            auth_ready=True,
        )


async def wait_for(condition, timeout: float = 1.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("Timed out while waiting for the expected condition.")


async def unexpected_sms_request() -> str:
    raise AssertionError("SMS should not be requested during the first login stage.")


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
        sms_timeout_seconds=1,
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
async def test_mobile_device_delete_unpairs_backend_device(aiohttp_client, test_context):
    app, service, _, _ = test_context
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
    api_token = (await response.json())["api_token"]
    assert service.device_count() == 1

    delete_response = await client.delete(
        "/api/v1/mobile/device",
        headers={"Authorization": f"Bearer {api_token}"},
    )
    assert delete_response.status == 200
    delete_payload = await delete_response.json()
    assert delete_payload["message"] == "Pixel is ontkoppeld."
    assert service.device_count() == 0

    status_response = await client.get(
        "/api/v1/mobile/status",
        headers={"Authorization": f"Bearer {api_token}"},
    )
    assert status_response.status == 401


@pytest.mark.asyncio
async def test_mobile_config_and_admin_portals_support_portal_id_setup(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
    client = await aiohttp_client(app)

    config_response = await client.get("/api/v1/mobile/config")
    assert config_response.status == 200
    config_payload = await config_response.json()
    assert config_payload["default_portal_id"] == "land-van-horne"
    assert config_payload["portals"][0]["name"] == "Land van Horne"

    portal_response = await client.post(
        "/api/v1/admin/portals?token=admin-code",
        json={
            "name": "Demo Portaal",
            "login_url": "demo.example.invalid/login",
            "logo_url": "https://example.invalid/logo.png",
        },
    )
    assert portal_response.status == 200
    portal_payload = await portal_response.json()
    portal_id = portal_payload["portal"]["portal_id"]

    setup_response = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "portal_id": portal_id,
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-portal",
            "device_label": "Pixel",
        },
    )
    assert setup_response.status == 200
    assert service.credentials is not None
    assert service.credentials.portal_id == portal_id
    assert service.mobile_status_payload()["login_url"] == "https://demo.example.invalid/login"


@pytest.mark.asyncio
async def test_status_page_embeds_parseable_initial_snapshot_json(aiohttp_client, test_context):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)

    response = await client.get("/status?token=admin-code")
    assert response.status == 200
    html = await response.text()

    match = re.search(r'<script id="initial-status-json" type="application/json">(.*?)</script>', html, re.S)
    assert match is not None
    raw_payload = match.group(1)
    assert "&quot;" not in raw_payload

    payload = json.loads(raw_payload)
    assert set(["status", "devices", "portals"]).issubset(payload.keys())


@pytest.mark.asyncio
async def test_status_query_token_bootstraps_cookie_for_followup_actions(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
    client = await aiohttp_client(app)

    page_response = await client.get("/status?token=admin-code")
    assert page_response.status == 200
    assert page_response.cookies.get("ons_status_session") is not None

    refresh_response = await client.post("/api/v1/admin/refresh")
    assert refresh_response.status == 200
    refresh_payload = await refresh_response.json()
    assert refresh_payload["message"] == "De handmatige synchronisatie is gestart."
    assert set(["status", "devices", "portals"]).issubset(refresh_payload["status"].keys())

    websocket = await client.ws_connect("/status/live")
    initial_message = await websocket.receive(timeout=1.0)
    initial_payload = json.loads(initial_message.data)
    assert set(["status", "devices", "portals"]).issubset(initial_payload.keys())
    await websocket.close()


@pytest.mark.asyncio
async def test_sync_toggle_blocks_setup_autosync_and_manual_refresh(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    automation_client = CountingAutomationClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=automation_client,
    )
    app = create_app(config=config, service=service)
    client = await aiohttp_client(app)

    disable_response = await client.post(
        "/api/v1/admin/sync?token=admin-code",
        json={"enabled": False},
    )
    assert disable_response.status == 200
    disable_payload = await disable_response.json()
    assert disable_payload["status"]["status"]["sync"]["sync_enabled"] is False

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
    setup_payload = await setup_response.json()
    assert "Synchronisatie is uitgeschakeld" in setup_payload["message"]
    assert setup_payload["status"]["sync"]["sync_enabled"] is False

    await asyncio.sleep(0)
    assert automation_client.call_count == 0

    refresh_blocked = await client.post("/api/v1/admin/refresh?token=admin-code")
    assert refresh_blocked.status == 400
    assert "Schakel synchronisatie eerst weer in" in await refresh_blocked.text()

    enable_response = await client.post(
        "/api/v1/admin/sync?token=admin-code",
        json={"enabled": True},
    )
    assert enable_response.status == 200
    enable_payload = await enable_response.json()
    assert enable_payload["status"]["status"]["sync"]["sync_enabled"] is True

    refresh_response = await client.post("/api/v1/admin/refresh?token=admin-code")
    assert refresh_response.status == 200
    await wait_for(lambda: automation_client.call_count == 1)


@pytest.mark.asyncio
async def test_admin_device_actions_return_updated_status_snapshot(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
    client = await aiohttp_client(app)

    first_setup = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-1",
            "device_label": "Pixel A",
        },
    )
    assert first_setup.status == 200
    first_device_id = (await first_setup.json())["status"]["device_id"]

    second_setup = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-2",
            "device_label": "Pixel B",
        },
    )
    assert second_setup.status == 200
    second_device_id = (await second_setup.json())["status"]["device_id"]

    activate_response = await client.post(f"/api/v1/admin/devices/{first_device_id}/activate?token=admin-code")
    assert activate_response.status == 200
    activate_payload = await activate_response.json()
    devices_by_id = {item["device_id"]: item for item in activate_payload["status"]["devices"]}
    assert devices_by_id[first_device_id]["is_active"] is True
    assert devices_by_id[second_device_id]["is_active"] is False

    remove_response = await client.delete(f"/api/v1/admin/devices/{second_device_id}?token=admin-code")
    assert remove_response.status == 200
    remove_payload = await remove_response.json()
    assert remove_payload["device_id"] == second_device_id
    assert [item["device_id"] for item in remove_payload["status"]["devices"]] == [first_device_id]


@pytest.mark.asyncio
async def test_status_live_websocket_receives_device_updates(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
    client = await aiohttp_client(app)

    first_setup = await client.post(
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
    assert first_setup.status == 200

    websocket = await client.ws_connect("/status/live?token=admin-code")
    initial_message = await websocket.receive(timeout=1.0)
    initial_payload = json.loads(initial_message.data)
    assert initial_payload["status"]["device_count"] == 1
    assert initial_payload["devices"][0]["device_label"] == "Pixel"

    second_setup = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-2",
            "device_label": "Tablet",
        },
    )
    assert second_setup.status == 200

    update_message = await websocket.receive(timeout=1.0)
    update_payload = json.loads(update_message.data)
    assert update_payload["status"]["device_count"] == 2
    assert any(device["device_label"] == "Tablet" for device in update_payload["devices"])

    await websocket.close()


@pytest.mark.asyncio
async def test_debug_endpoint_requires_token(aiohttp_client, test_context):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)

    unauthorized = await client.get("/debug")
    assert unauthorized.status == 401

    authorized = await client.get("/debug?token=debug-code")
    assert authorized.status == 200


@pytest.mark.asyncio
async def test_http_login_automation_client_captures_otp_checkpoint(aiohttp_client, test_context, tmp_path):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)
    automation_client = HttpLoginAutomationClient()
    snapshot_path = tmp_path / "otp-snapshot.html"
    progress_events: list[dict[str, object]] = []

    result = await automation_client.authenticate_and_scrape(
        credentials=LoginCredentials(
            login_url=str(client.make_url("/sandbox/hasmoves/login?mode=sms")),
            username="fcm-test",
            password="secret",
        ),
        request_sms_code=unexpected_sms_request,
        snapshot_path=snapshot_path,
        config=build_config(tmp_path),
        report_progress=lambda event: asyncio.sleep(0, result=progress_events.append(event)),
    )

    assert result.auth_ready is False
    assert result.session_checkpoint is not None
    assert result.session_checkpoint["challenge"]["otp_input_name"] == "code"
    assert result.session_checkpoint["challenge"]["action_url"].endswith(
        "/sandbox/hasmoves/challenge?mode=sms"
    )
    assert "Mock HasMoves OTP" in snapshot_path.read_text(encoding="utf-8")
    assert any(event["phase"] == "credential_response" for event in progress_events)
    assert any(event["phase"] == "otp_detected" for event in progress_events)
    assert sorted(path.name for path in (tmp_path / "auth-trace").glob("*.html"))


@pytest.mark.asyncio
async def test_http_login_automation_client_scrapes_basic_roster(aiohttp_client, test_context, tmp_path):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)
    automation_client = HttpLoginAutomationClient()
    snapshot_path = tmp_path / "basic-roster.html"
    progress_events: list[dict[str, object]] = []

    result = await automation_client.authenticate_and_scrape(
        credentials=LoginCredentials(
            login_url=str(client.make_url("/sandbox/hasmoves/login?mode=basic")),
            username="bob@example.invalid",
            password="secret",
        ),
        request_sms_code=unexpected_sms_request,
        snapshot_path=snapshot_path,
        config=build_config(tmp_path),
        report_progress=lambda event: asyncio.sleep(0, result=progress_events.append(event)),
    )

    assert result.auth_ready is True
    assert result.session_checkpoint is None
    assert any("bob@example.invalid" in item.description for item in result.roster_items)
    assert "Mock HasMoves Rooster" in snapshot_path.read_text(encoding="utf-8")
    assert any(event["phase"] == "ready" for event in progress_events)


def test_http_login_automation_client_reads_bootstrap_flash_error():
        automation_client = HttpLoginAutomationClient()
        response = requests.Response()
        response.status_code = 200
        html = """
<!doctype html>
<html lang="nl">
    <head>
        <script type="text/javascript">
            window.flash_error = {"debug":"","error":"incorrect_credentials"};
        </script>
    </head>
    <body><div id="main"></div></body>
</html>
"""

        error_message = automation_client._extract_login_error(response, html)

        assert error_message == "De ONS-site meldt dat de gebruikersnaam of het wachtwoord onjuist is."


def test_http_login_automation_client_extracts_microsoft_otp_inline_error():
        automation_client = HttpLoginAutomationClient()
        html = """
<!doctype html>
<html lang="en">
    <body>
        <div id="idDiv_SAOTCC_ErrorMsg_OTC">That code didn't work. Please enter a valid code.</div>
    </body>
</html>
"""

        error_message = automation_client._extract_microsoft_otp_error(html)

        assert "Microsoft rejected the OTP code" in error_message
        assert "That code didn't work" in error_message


def test_http_login_automation_client_ignores_non_otp_inline_messages():
        automation_client = HttpLoginAutomationClient()
        html = """
<!doctype html>
<html lang="en">
    <body>
        <div id="idDiv_SAOTCC_ErrorMsg_OTC">Please complete this step to continue.</div>
    </body>
</html>
"""

        error_message = automation_client._extract_microsoft_otp_error(html)

        assert error_message == ""


def test_http_login_automation_client_extracts_sso_provider_from_bootstrap_script():
        automation_client = HttpLoginAutomationClient()
        html = """
<!doctype html>
<html lang="nl">
    <head>
        <script type="text/javascript">
            window.sso_enabled = true;
            window.sso_providers = [{"id":"mock-microsoft","title":"Microsoft SSO","button_text":"Aanmelden met SSO","jump_url":"/auth/oidc/mock-microsoft","ready":true,"default":true,"hidden":false}];
        </script>
    </head>
    <body><div id="main"></div></body>
</html>
"""

        providers = automation_client._extract_sso_providers("https://example.invalid/login", html)

        assert providers == [
            {
                "id": "mock-microsoft",
                "title": "Microsoft SSO",
                "button_text": "Aanmelden met SSO",
                "jump_url": "https://example.invalid/auth/oidc/mock-microsoft",
                "ready": True,
                "default": True,
                "hidden": False,
            }
        ]


def test_http_login_automation_client_extracts_microsoft_proof_selection():
        automation_client = HttpLoginAutomationClient()
        html = """
<!doctype html>
<html lang="nl">
    <head>
        <title>Aanmelden bij uw account</title>
        <script type="text/javascript">
            $Config={"arrUserProofs":[{"authMethodId":"OneWaySMS","data":"OneWaySMS","display":"+XX XXXXXXX32","isDefault":false,"isLocationAware":false},{"authMethodId":"TwoWayVoiceMobile","data":"TwoWayVoiceMobile","display":"+XX XXXXXXX32","isDefault":false,"isLocationAware":false}],"urlPost":"https://login.microsoftonline.com/common/SAS/ProcessAuth","sFT":"flow-token","sFTName":"flowToken","sCtx":"ctx-token","sAuthMethodInputFieldName":"mfaAuthMethod"};
        </script>
    </head>
    <body>
        <form method="post" action="https://login.microsoftonline.com/common/SAS/ProcessAuth">
            <div id="idDiv_SAOTCS_Title">Bevestig uw identiteit</div>
            <div data-value="OneWaySMS"><div>Sms verzenden naar +XX XXXXXXX32</div></div>
        </form>
    </body>
</html>
"""

        challenge = automation_client._extract_microsoft_proof_selection(
            "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            html,
        )

        assert challenge is not None
        assert challenge["challenge_kind"] == "microsoft_proof_selection"
        assert challenge["proof_input_name"] == "mfaAuthMethod"
        assert challenge["sms_proof_value"] == "OneWaySMS"
        assert challenge["sms_proof"]["display"] == "+XX XXXXXXX32"
        assert challenge["sms_proof"]["phone_number_suffix"] == "32"
        assert challenge["hidden_fields"]["flowToken"] == "flow-token"
        assert challenge["hidden_fields"]["ctx"] == "ctx-token"


def test_http_login_automation_client_extracts_meta_refresh_redirect():
        automation_client = HttpLoginAutomationClient()
        html = """
<!doctype html>
<html>
    <head>
        <meta http-equiv="refresh" content="0;url=https://landvanhorne.mijnio.nl?hub_ticket=abc123">
    </head>
    <body></body>
</html>
"""

        redirect_url = automation_client._extract_meta_refresh_redirect(
            "https://landvanhorne.startmetons.nl/sso",
            html,
        )

        assert redirect_url == "https://landvanhorne.mijnio.nl?hub_ticket=abc123"


@pytest.mark.asyncio
async def test_http_login_automation_client_stabilizes_post_otp_meta_refresh():
        automation_client = HttpLoginAutomationClient()
        debug_notes: list[str] = []

        class FakePage:
            def __init__(self) -> None:
                self.url = "https://landvanhorne.startmetons.nl/sso"
                self.goto_calls: list[str] = []
                self._html = (
                    '<html><head><meta http-equiv="refresh" '
                    'content="0;url=https://landvanhorne.mijnio.nl?hub_ticket=abc123"></head><body></body></html>'
                )
                self._title = "Aanmelden bij uw account"

            async def content(self):
                return self._html

            async def title(self):
                return self._title

            async def goto(self, url, wait_until="domcontentloaded"):
                del wait_until
                self.goto_calls.append(url)
                self.url = url
                self._html = "<html><head><title>Rooster</title></head><body>Welkom</body></html>"
                self._title = "Rooster"

            async def wait_for_timeout(self, timeout_ms):
                del timeout_ms
                return None

        fake_page = FakePage()

        html, page_title = await automation_client._stabilize_post_otp_page(
            fake_page,
            debug_notes=debug_notes,
        )

        assert fake_page.goto_calls == ["https://landvanhorne.mijnio.nl?hub_ticket=abc123"]
        assert "Following post-OTP meta refresh to https://landvanhorne.mijnio.nl?hub_ticket=abc123." in debug_notes
        assert "Welkom" in html
        assert page_title == "Rooster"


@pytest.mark.asyncio
async def test_http_login_automation_client_reuses_existing_microsoft_otp_stage():
        automation_client = HttpLoginAutomationClient()

        class FakePage:
            url = "https://login.microsoftonline.com/common/SAS/ProcessAuth"

            async def title(self):
                return "Aanmelden bij uw account"

        recorded_events: list[dict[str, str]] = []
        debug_notes: list[str] = []

        def fake_report_progress(event: dict[str, str]) -> None:
            recorded_events.append(event)

        async def fake_has_visible_selector(page, selectors):
            del page, selectors
            return False

        async def fake_click_microsoft_sms_proof(page, *, proof_selection, timeout_seconds):
            del page, proof_selection, timeout_seconds
            raise RuntimeError("No matching selector was found for proof selection.")

        async def fake_wait_for_microsoft_otp_page(page, timeout_seconds):
            del page, timeout_seconds
            return None

        automation_client._has_visible_selector = fake_has_visible_selector  # type: ignore[method-assign]
        automation_client._click_microsoft_sms_proof = fake_click_microsoft_sms_proof  # type: ignore[method-assign]
        automation_client._wait_for_microsoft_otp_page = fake_wait_for_microsoft_otp_page  # type: ignore[method-assign]

        trace_index = await automation_client._trigger_microsoft_sms_or_resume_otp(
            FakePage(),
            proof_selection={"sms_proof_value": "OneWaySMS"},
            timeout_seconds=30,
            report_progress=fake_report_progress,
            trace_index=7,
            debug_notes=debug_notes,
            relay_mode_label="two-phase",
        )

        assert trace_index == 8
        assert debug_notes == ["Microsoft skipped the proof-selection click and opened the OTP page directly."]
        assert len(recorded_events) == 1
        assert recorded_events[0]["label"] == "Reuse Microsoft OTP stage"
        assert recorded_events[0]["message"] == "Microsoft moved directly to the OTP page; no SMS-proof click was needed."
        assert recorded_events[0]["phase"] == "sms_requested"
        assert recorded_events[0]["page_title"] == "Aanmelden bij uw account"
        assert recorded_events[0]["url"] == "https://login.microsoftonline.com/common/SAS/ProcessAuth"


@pytest.mark.asyncio
async def test_status_page_renders_auth_console(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=FakeCheckpointAutomationClient(),
    )
    app = create_app(config=config, service=service)
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

    await wait_for(lambda: service.mobile_status_payload()["sync"]["current_phase"] == "otp_required")

    status_page = await client.post(
        "/status/login",
        data={"admin_token": "admin-code"},
    )
    assert status_page.status == 200
    body = await status_page.text()
    assert "Authenticatieconsole" in body
    assert "Bekijk HTML" in body
    assert "Credentialexport" in body
    assert "Bevestig export-passphrase" not in body
    assert "python -m ons_backend.credential_export" in body
    assert body.index("Portalen beheren") < body.index("Credentialexport") < body.index("Mock HasMoves testflow")


@pytest.mark.asyncio
async def test_status_credential_export_requires_session_and_returns_encrypted_bundle(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
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

    unauthorized = await client.post(
        "/status/credentials/export?token=admin-code",
        data={
            "export_passphrase": "correct horse battery staple",
        },
    )
    assert unauthorized.status == 401

    login_response = await client.post(
        "/status/login",
        data={"admin_token": "admin-code"},
    )
    assert login_response.status == 200

    export_response = await client.post(
        "/status/credentials/export",
        data={
            "export_passphrase": "correct horse battery staple",
        },
    )
    assert export_response.status == 200
    assert export_response.headers["Content-Type"].startswith("application/json")
    assert "attachment; filename=" in export_response.headers["Content-Disposition"]
    assert export_response.headers["Cache-Control"] == "no-store, max-age=0"

    raw_bundle = await export_response.text()
    assert "alice@example.invalid" not in raw_bundle
    assert "super-secret" not in raw_bundle

    bundle = json.loads(raw_bundle)
    decrypted = StateStore.decrypt_credentials_export(bundle, "correct horse battery staple")
    assert decrypted.username == "alice@example.invalid"
    assert decrypted.password == "super-secret"


@pytest.mark.asyncio
async def test_status_credential_export_rejects_admin_token_as_passphrase(aiohttp_client, test_context):
    app, service, _, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
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

    login_response = await client.post(
        "/status/login",
        data={"admin_token": "admin-code"},
    )
    assert login_response.status == 200

    export_response = await client.post(
        "/status/credentials/export",
        data={
            "export_passphrase": "admin-code",
        },
    )
    assert export_response.status == 200
    body = await export_response.text()
    assert "Kies een andere export-passphrase dan het admin-token." in body


@pytest.mark.asyncio
async def test_partial_login_stage_persists_otp_checkpoint(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=FakeCheckpointAutomationClient(),
    )
    app = create_app(config=config, service=service)
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

    await wait_for(lambda: service.mobile_status_payload()["sync"]["current_phase"] == "otp_required")
    status = service.mobile_status_payload()
    assert status["sync"]["status"] == "partial"
    assert status["sync"]["auth_ready"] is False
    assert "OTP-pagina" in status["sync"]["last_message"]

    checkpoint = service.store.read_auth_session()
    assert checkpoint is not None
    assert checkpoint["challenge"]["otp_input_name"] == "token"
    raw = config.auth_session_file.read_text(encoding="utf-8")
    assert "secret-cookie" not in raw
    assert push_client.auth_notifications == []


@pytest.mark.asyncio
async def test_partial_login_stage_persists_microsoft_proof_selection_checkpoint(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=FakeMfaSelectionAutomationClient(),
    )
    app = create_app(config=config, service=service)
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

    await wait_for(lambda: service.mobile_status_payload()["sync"]["current_phase"] == "mfa_required")
    status = service.mobile_status_payload()
    assert status["sync"]["status"] == "partial"
    assert status["sync"]["auth_ready"] is False
    assert "SMS not sent yet" in status["sync"]["last_message"]
    assert "+XX XXXXXXX32" in status["sync"]["last_message"]

    checkpoint = service.store.read_auth_session()
    assert checkpoint is not None
    assert checkpoint["challenge"]["challenge_kind"] == "microsoft_proof_selection"
    assert checkpoint["challenge"]["sms_proof"]["phone_number_suffix"] == "32"
    raw = config.auth_session_file.read_text(encoding="utf-8")
    assert "secret-cookie" not in raw
    assert push_client.auth_notifications == []


@pytest.mark.asyncio
async def test_service_resumes_microsoft_proof_selection_and_arms_sms_before_waiting(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    automation_client = FakeResumeAutomationClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=automation_client,
    )
    await service.set_sync_enabled(False)
    app = create_app(config=config, service=service)
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
    api_token = (await setup_response.json())["api_token"]

    await asyncio.to_thread(
        service.store.write_auth_session,
        {
            "version": 1,
            "current_url": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
            "challenge": {
                "challenge_kind": "microsoft_proof_selection",
                "action_url": "https://login.microsoftonline.com/common/SAS/ProcessAuth",
                "method": "post",
                "proof_input_name": "mfaAuthMethod",
                "sms_proof_value": "OneWaySMS",
                "sms_proof": {
                    "auth_method_id": "OneWaySMS",
                    "data": "OneWaySMS",
                    "display": "+XX XXXXXXX32",
                    "phone_number_suffix": "32",
                },
                "hidden_fields": {},
            },
            "cookies": [],
        },
    )

    await service.set_sync_enabled(True)
    await service.trigger_refresh(reason="resume-test", wait=False)

    await wait_for(lambda: len(push_client.listen_requests) == 1)
    challenge_id = push_client.listen_requests[0]
    assert automation_client.events[:2] == [
        ("armed", challenge_id),
        ("clicked_sms_button", challenge_id),
    ]

    sms_response = await client.post(
        f"/api/v1/mobile/challenges/{challenge_id}/sms-code",
        headers={"Authorization": f"Bearer {api_token}"},
        json={"code": "123456", "sender": "ONS"},
    )
    assert sms_response.status == 200

    await wait_for(lambda: service.mobile_status_payload()["sync"]["current_phase"] == "post_otp_page")
    assert automation_client.events[2] == ("received_code", "123456")
    status = service.mobile_status_payload()
    assert status["sync"]["status"] == "partial"
    assert status["sync"]["last_message"].startswith("OTP submitted")
    sms_received_entries = [
        entry for entry in status["sync"]["auth_trace"] if entry.get("phase") == "sms_received"
    ]
    assert sms_received_entries
    assert sms_received_entries[-1]["message"] == "OTP 123456 received from Android."
    assert push_client.auth_notifications == []


@pytest.mark.asyncio
async def test_service_resumes_post_otp_checkpoint_with_automation(aiohttp_client, tmp_path):
    config = build_config(tmp_path)
    push_client = FakePushClient()
    automation_client = CountingAutomationClient()
    service = BackendService(
        config=config,
        store=StateStore(config),
        push_client=push_client,
        automation_client=automation_client,
    )
    await service.set_sync_enabled(False)
    app = create_app(config=config, service=service)
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

    await asyncio.to_thread(
        service.store.write_auth_session,
        {
            "version": 1,
            "current_url": "https://example.invalid/post-otp",
            "page_title": "Na OTP",
            "challenge": {
                "challenge_kind": "post_otp_result_page",
                "page_summary": "Welkom terug in de portal.",
                "source": "microsoft_sso",
            },
            "cookies": [],
        },
    )

    await service.set_sync_enabled(True)
    await service.trigger_refresh(reason="post-otp-test", wait=True)

    status = service.mobile_status_payload()
    assert automation_client.call_count == 1
    assert status["sync"]["status"] == "success"
    assert status["sync"]["current_phase"] == "ready"
    assert status["sync"]["last_error"] is None


def test_http_login_automation_client_extracts_month_roster_export():
    automation_client = HttpLoginAutomationClient()
    html = """
<html>
    <body>
        <div class="publication-status">Vanaf 01 augustus kan je al je diensten inplannen.</div>
        <table>
            <tr>
                <td class="week-content">
                    <div class="roster_slot shiftassignment">
                        <span class="slot_header">27 jun</span>
                        <h3 class="title">Vroege dienst</h3>
                        <span class="timepair"><span class="start">06:00</span><span class="stop">14:00</span></span>
                    </div>
                    <div class="roster_slot unavailability">
                        <span class="slot_header">28 jun</span>
                        <h3 class="title">Niet beschikbaar</h3>
                    </div>
                </td>
            </tr>
        </table>
    </body>
</html>
"""

    export_payload, planned_items, notes, publication_stop = automation_client._extract_month_roster_export(
    html,
    month_start=date(2026, 6, 1),
    source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
    page_title="Rooster juni 2026",
    )

    assert export_payload["month"] == "2026-06"
    assert len(export_payload["items"]) == 2
    assert planned_items[0].date == "2026-06-27"
    assert planned_items[0].start == "06:00"
    assert planned_items[0].end == "14:00"
    assert publication_stop == (2026, 8)
    assert any("Publication notice detected" in note for note in notes)


def test_http_login_automation_client_resolves_month_targets_from_jump_url():
    automation_client = HttpLoginAutomationClient()
    targets = automation_client._resolve_month_targets(
    "https://landvanhorne.startmetons.nl/?jump=https%3A%2F%2Flandvanhorne.hasmoves.com%2Fonsdraaiboek%2Froster%2F2026-06-01%2Fmonth",
    "https://landvanhorne.startmetons.nl/",
    "",
    )

    assert targets[0][0].isoformat() == "2026-06-01"
    assert targets[0][1] == "https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month"
    assert targets[1][0].isoformat() == "2026-07-01"
    assert targets[1][1] == "https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-07-01/month"


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
async def test_status_page_lists_devices_and_supports_actions(aiohttp_client, test_context):
    app, service, push_client, _ = test_context

    async def fake_trigger_refresh(reason: str, wait: bool = False):
        return service.mobile_status_payload()

    service.trigger_refresh = fake_trigger_refresh  # type: ignore[method-assign]
    client = await aiohttp_client(app)

    first_setup = await client.post(
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
    assert first_setup.status == 200

    second_setup = await client.post(
        "/api/v1/mobile/setup",
        json={
            "setup_secret": "setup-code",
            "login_url": "https://example.invalid/login",
            "username": "alice@example.invalid",
            "password": "super-secret",
            "fcm_token": "token-2",
            "device_label": "Tablet",
        },
    )
    assert second_setup.status == 200
    assert service.device_count() == 2

    unauthorized = await client.get("/status")
    assert unauthorized.status == 200
    assert "Admin-token" in await unauthorized.text()

    status_page = await client.post(
        "/status/login",
        data={"admin_token": "admin-code"},
    )
    assert status_page.status == 200
    status_body = await status_page.text()
    assert "ONS Rooster Operatorstatus" in status_body
    assert "Pixel" in status_body
    assert "Tablet" in status_body
    assert "/sandbox/hasmoves/login?mode=sms" in status_body

    devices = service.paired_devices_payload()
    pixel_id = next(device["device_id"] for device in devices if device["device_label"] == "Pixel")

    ping_response = await client.post(f"/status/devices/{pixel_id}/ping")
    assert ping_response.status == 200
    assert push_client.auth_targets[-1] == pixel_id

    activate_response = await client.post(f"/status/devices/{pixel_id}/activate")
    assert activate_response.status == 200
    assert service.state.active_device_id == pixel_id

    remove_response = await client.post(f"/status/devices/{pixel_id}/remove")
    assert remove_response.status == 200
    assert service.device_count() == 1
    assert service.device_by_id(pixel_id) is None
    assert service.active_device() is not None
    assert service.active_device().device_label == "Tablet"


@pytest.mark.asyncio
async def test_mock_hasmoves_pages_cover_basic_and_sms_flow(aiohttp_client, test_context):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)

    login_page = await client.get("/sandbox/hasmoves/login?mode=sms")
    assert login_page.status == 200
    login_body = await login_page.text()
    assert 'type="text" name="username"' in login_body
    assert 'name="password"' in login_body

    challenge_page = await client.post(
        "/sandbox/hasmoves/login?mode=sms",
        data={"username": "fcm-test", "password": "secret"},
    )
    assert challenge_page.status == 200
    challenge_body = await challenge_page.text()
    assert 'name="code"' in challenge_body
    assert "123456" in challenge_body

    invalid_code = await client.post(
        "/sandbox/hasmoves/challenge?mode=sms",
        data={"username": "fcm-test", "code": "000000"},
    )
    assert invalid_code.status == 400

    sms_roster = await client.post(
        "/sandbox/hasmoves/challenge?mode=sms",
        data={"username": "fcm-test", "code": "123456"},
    )
    assert sms_roster.status == 200
    sms_roster_body = await sms_roster.text()
    assert "Mock HasMoves Rooster" in sms_roster_body
    assert "26-05-2026" in sms_roster_body

    basic_roster = await client.post(
        "/sandbox/hasmoves/login?mode=basic",
        data={"username": "bob@example.invalid", "password": "secret"},
    )
    assert basic_roster.status == 200
    basic_roster_body = await basic_roster.text()
    assert "Mock vroege dienst voor bob@example.invalid" in basic_roster_body


@pytest.mark.asyncio
async def test_http_login_automation_client_switches_to_sso_and_captures_otp_checkpoint(aiohttp_client, test_context, tmp_path):
    app, _, _, _ = test_context
    client = await aiohttp_client(app)
    automation_client = HttpLoginAutomationClient()
    snapshot_path = tmp_path / "sso-snapshot.html"
    progress_events: list[dict[str, object]] = []

    try:
        result = await automation_client.authenticate_and_scrape(
            credentials=LoginCredentials(
                login_url=str(client.make_url("/sandbox/hasmoves/login?mode=sso")),
                username="alice@example.invalid",
                password="secret",
            ),
            request_sms_code=unexpected_sms_request,
            snapshot_path=snapshot_path,
            config=build_config(tmp_path),
            report_progress=lambda event: asyncio.sleep(0, result=progress_events.append(event)),
        )
    except RuntimeError as exc:
        if "Executable doesn't exist" in str(exc):
            pytest.skip("Playwright browser binaries are not installed in this environment.")
        raise

    assert result.auth_ready is False
    assert result.session_checkpoint is not None
    assert result.session_checkpoint["challenge"]["otp_input_name"] == "code"
    assert result.session_checkpoint["challenge"]["action_url"].endswith(
        "/sandbox/hasmoves/challenge?mode=sso"
    )
    assert "Mock HasMoves OTP" in snapshot_path.read_text(encoding="utf-8")
    assert any(event["phase"] == "sso_selected" for event in progress_events)
    assert any(event["phase"] == "sso_opened" for event in progress_events)
    assert any(event["phase"] == "otp_detected" for event in progress_events)


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