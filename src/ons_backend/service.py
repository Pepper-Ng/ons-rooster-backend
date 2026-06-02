from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import secrets
import shutil
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from icalendar import Calendar, Event

from .calendar_export import build_icalendar, parse_local_datetime, timezone_or_utc
from .clients import AutomationClient, FcmPushClient, PushClient
from .config import AppConfig
from .google_calendar import CalendarSyncSummary, GoogleCalendarSyncClient
from .models import AppState, AuthenticationResult, DeviceRegistration, GoogleCalendarSettings, LoginCredentials, PortalDefinition, RosterItem
from .storage import StateStore

log = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PendingChallenge:
    challenge_id: str
    device_id: str
    created_at: str
    event: threading.Event
    sender: str | None = None
    code: str | None = None


class CalendarSyncClient(Protocol):
    def is_configured(self) -> bool:
        ...

    def sync_exports(self, month_exports: list[dict[str, Any]]) -> CalendarSyncSummary:
        ...


DEFAULT_PORTAL_ID = "land-van-horne"
DEFAULT_PORTAL_NAME = "Land van Horne"
DEFAULT_PORTAL_LOGO_URL = "https://aanmelden.ons-diensten.nl/api/images/a2d1a875-feed-4cc0-91d5-149c4f129db8.png"
SYNC_DISABLED_MESSAGE = "Synchronisatie is uitgeschakeld. Schakel synchronisatie eerst weer in."


class BackendService:
    def __init__(
        self,
        config: AppConfig,
        store: StateStore,
        push_client: PushClient,
        automation_client: AutomationClient,
        calendar_sync_client: CalendarSyncClient | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.push_client = push_client
        self.automation_client = automation_client
        self.state, self.credentials = self.store.load()
        self._ensure_default_portals()
        self._calendar_sync_client_override = calendar_sync_client
        self._calendar_feed_token = self._resolve_calendar_feed_token()
        self._pending_challenges: dict[str, PendingChallenge] = {}
        self._pending_challenges_lock = threading.Lock()
        self._state_lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()
        self._live_condition = asyncio.Condition()
        self._live_version = 0
        self._connected_device_counts: dict[str, int] = {}
        self._scheduler_wakeup = asyncio.Event()
        self._scheduler_task: asyncio.Task[None] | None = None
        self._current_sync_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._scheduler_task is None:
            self._scheduler_task = asyncio.create_task(self._scheduler_loop())

    async def stop(self) -> None:
        if self._scheduler_task is not None:
            self._scheduler_task.cancel()
            await asyncio.gather(self._scheduler_task, return_exceptions=True)
        if self._current_sync_task is not None:
            await asyncio.gather(self._current_sync_task, return_exceptions=True)

    def has_credentials(self) -> bool:
        return self.credentials is not None

    def has_device(self) -> bool:
        return bool(self.state.devices)

    def device_count(self) -> int:
        return len(self.state.devices)

    def active_device(self) -> DeviceRegistration | None:
        if not self.state.devices:
            return None
        if self.state.active_device_id:
            for device in self.state.devices:
                if device.device_id == self.state.active_device_id:
                    return device
        self.state.active_device_id = self.state.devices[-1].device_id
        return self.state.devices[-1]

    def device_for_mobile_token(self, token: str | None) -> DeviceRegistration | None:
        if not token:
            return None
        actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for device in self.state.devices:
            if device.api_token_hash and hmac.compare_digest(device.api_token_hash, actual):
                return device
        return None

    def device_by_id(self, device_id: str) -> DeviceRegistration | None:
        for device in self.state.devices:
            if device.device_id == device_id:
                return device
        return None

    def default_portal(self) -> PortalDefinition | None:
        if not self.state.portals:
            return None
        return self.state.portals[0]

    def portal_by_id(self, portal_id: str | None) -> PortalDefinition | None:
        if not portal_id:
            return None
        for portal in self.state.portals:
            if portal.portal_id == portal_id:
                return portal
        return None

    def selected_portal(self) -> PortalDefinition | None:
        if self.credentials is not None:
            selected = self.portal_by_id(self.credentials.portal_id)
            if selected is not None:
                return selected
            normalized_login_url = self._normalize_external_url(self.credentials.login_url)
            for portal in self.state.portals:
                if self._normalize_external_url(portal.login_url) == normalized_login_url:
                    return portal
        return self.default_portal()

    def portal_catalog_payload(self) -> list[dict[str, Any]]:
        selected_portal = self.selected_portal()
        selected_portal_id = selected_portal.portal_id if selected_portal else None
        return [
            {
                "portal_id": portal.portal_id,
                "name": portal.name,
                "login_url": portal.login_url,
                "logo_url": portal.logo_url,
                "created_at": portal.created_at,
                "updated_at": portal.updated_at,
                "is_selected": portal.portal_id == selected_portal_id,
            }
            for portal in self.state.portals
        ]

    def device_is_connected(self, device_id: str) -> bool:
        return self._connected_device_counts.get(device_id, 0) > 0

    def paired_devices_payload(self) -> list[dict[str, Any]]:
        active_device = self.active_device()
        active_device_id = active_device.device_id if active_device else None
        return [
            {
                "device_id": device.device_id,
                "device_label": device.device_label,
                "created_at": device.created_at,
                "updated_at": device.updated_at,
                "last_seen_at": device.last_seen_at,
                "fcm_token_suffix": self._suffix(device.fcm_token),
                "is_active": device.device_id == active_device_id,
                "is_connected": self.device_is_connected(device.device_id),
            }
            for device in sorted(self.state.devices, key=lambda item: (item.updated_at, item.created_at))
        ]

    def mobile_token_is_valid(self, token: str | None) -> bool:
        return self.device_for_mobile_token(token) is not None

    def setup_secret_is_valid(self, secret: str | None) -> bool:
        if not self.config.setup_secret:
            return True
        if secret is None:
            return False
        return hmac.compare_digest(secret, self.config.setup_secret)

    def admin_token_is_valid(self, token: str | None) -> bool:
        if not self.config.admin_token:
            return True
        if token is None:
            return False
        return hmac.compare_digest(token, self.config.admin_token)

    def debug_token_is_valid(self, token: str | None) -> bool:
        if not self.config.debug_token:
            return True
        if token is None:
            return False
        return hmac.compare_digest(token, self.config.debug_token)

    def sync_enabled(self) -> bool:
        return self.state.sync.sync_enabled

    def sync_interval_minutes(self) -> int:
        interval = self.state.sync.sync_interval_minutes
        if interval is None:
            interval = self.config.sync_interval_minutes
        return max(0, int(interval))

    def _next_scheduled_sync_timestamp(self) -> str | None:
        if not self.sync_enabled():
            return None
        interval_minutes = self.sync_interval_minutes()
        if interval_minutes <= 0:
            return None
        next_run = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=interval_minutes)
        return next_run.isoformat().replace("+00:00", "Z")

    def _set_next_scheduled_sync_locked(self) -> None:
        self.state.sync.next_scheduled_sync_at = self._next_scheduled_sync_timestamp()

    @staticmethod
    def _roster_item_date_in_month(item: dict[str, Any], month_key: str) -> bool:
        date_value = str(item.get("date", "")).strip()
        return bool(month_key and date_value.startswith(f"{month_key}-"))

    @staticmethod
    def _roster_item_identity(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
        return (
            str(item.get("date", "")).strip(),
            str(item.get("start", "")).strip(),
            str(item.get("end", "")).strip(),
            str(item.get("category", "")).strip(),
            re.sub(r"\s+", " ", str(item.get("description", "")).strip()),
        )

    @staticmethod
    def _planned_block_identity(item: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(item.get("date", "")).strip(),
            str(item.get("start", "")).strip(),
            str(item.get("end", "")).strip(),
        )

    @staticmethod
    def _has_roster_break(item: dict[str, Any]) -> bool:
        text = " ".join(
            str(item.get(field_name, ""))
            for field_name in ("description", "title")
        )
        return re.search(r"\(?\s*30\s*m\s+pauze\s*\)?", text, flags=re.IGNORECASE) is not None

    def _planned_work_minutes(self, item: dict[str, Any]) -> int:
        timezone = timezone_or_utc(self.config.google_calendar_timezone or self.config.timezone)
        start = parse_local_datetime(
            str(item.get("date", "")).strip(),
            str(item.get("start", "")).strip(),
            timezone,
        )
        end = parse_local_datetime(
            str(item.get("date", "")).strip(),
            str(item.get("end", "")).strip(),
            timezone,
        )
        if start is None or end is None:
            return 0
        if end <= start:
            end = end + timedelta(days=1)
        minutes = int((end - start).total_seconds() // 60)
        if self._has_roster_break(item):
            minutes -= 30
        return max(0, minutes)

    @staticmethod
    def _format_hours(minutes: int) -> str:
        hours = minutes / 60
        formatted = f"{hours:.2f}".rstrip("0").rstrip(".")
        return formatted or "0"

    def _summarize_roster_export(self, export_payload: dict[str, Any], *, account_key: str) -> dict[str, Any]:
        month_key = str(export_payload.get("month", "")).strip()
        items = export_payload.get("items", [])
        if not isinstance(items, list):
            items = []

        unique_month_items: list[dict[str, Any]] = []
        seen_items: set[tuple[str, str, str, str, str]] = set()
        for item in items:
            if not isinstance(item, dict) or not self._roster_item_date_in_month(item, month_key):
                continue
            identity = self._roster_item_identity(item)
            if identity in seen_items:
                continue
            seen_items.add(identity)
            unique_month_items.append(item)

        planned_items: list[dict[str, Any]] = []
        seen_planned_blocks: set[tuple[str, str, str]] = set()
        for item in unique_month_items:
            if not bool(item.get("is_planned_hours")):
                continue
            planned_identity = self._planned_block_identity(item)
            if planned_identity in seen_planned_blocks:
                continue
            seen_planned_blocks.add(planned_identity)
            planned_items.append(item)

        planned_minutes = sum(self._planned_work_minutes(item) for item in planned_items)
        return {
            "account_key": account_key,
            "month": month_key,
            "item_count": len(unique_month_items),
            "planned_hours_count": len(planned_items),
            "planned_slot_count": len(planned_items),
            "planned_work_minutes": planned_minutes,
            "planned_hours": round(planned_minutes / 60, 2),
            "planned_hours_label": self._format_hours(planned_minutes),
            "notice": str(export_payload.get("notice", "")).strip(),
            "download_path": f"/status/roster/{month_key}.json?account_key={account_key}",
        }

    def calendar_sync_enabled(self) -> bool:
        return bool(self._effective_google_calendar_settings()["enabled"])

    def calendar_sync_configured(self) -> bool:
        return self._calendar_sync_client_for_current_account().is_configured()

    def current_account_key(self) -> str:
        resolved_credentials = self._resolved_credentials()
        username = resolved_credentials.username if resolved_credentials else "default"
        return self._account_key(username)

    def current_account_label(self) -> str:
        resolved_credentials = self._resolved_credentials()
        if resolved_credentials is None or not resolved_credentials.username:
            return "Default"
        return self._mask_value(resolved_credentials.username)

    def google_calendar_settings_for_current_account(self) -> GoogleCalendarSettings | None:
        return self._google_calendar_settings_for_account(self.current_account_key())

    async def configure_google_calendar_account(
        self,
        *,
        calendar_id: str,
        timezone: str,
        enabled: bool,
        service_account_json: str | None,
    ) -> dict[str, Any]:
        resolved_credentials = self._resolved_credentials()
        if resolved_credentials is None or not resolved_credentials.username.strip():
            raise RuntimeError("Sla eerst ONS-inloggegevens op voordat je Google Calendar voor dit account configureert.")

        account_key = self._account_key(resolved_credentials.username)
        account_label = self._mask_value(resolved_credentials.username)
        normalized_calendar_id = calendar_id.strip()
        normalized_timezone = timezone_or_utc(timezone.strip() or self.config.google_calendar_timezone or self.config.timezone).key
        existing = self._google_calendar_settings_for_account(account_key)
        now = utc_now()
        service_account_email = existing.service_account_email if existing else ""
        has_uploaded_secret = self.store.google_calendar_service_account_exists(account_key)

        if service_account_json is not None:
            info = GoogleCalendarSyncClient.validate_service_account_json(service_account_json)
            service_account_email = str(info.get("client_email", "")).strip()
            normalized_payload = json.dumps(info, indent=2, ensure_ascii=True)
            await asyncio.to_thread(
                self.store.write_google_calendar_service_account,
                account_key,
                normalized_payload,
            )
            has_uploaded_secret = True

        if enabled:
            if not normalized_calendar_id:
                raise RuntimeError("Vul een Google Calendar-ID in om synchronisatie in te schakelen.")
            if not has_uploaded_secret:
                raise RuntimeError("Upload eerst een Google service-account JSON voor dit account.")

        settings = GoogleCalendarSettings(
            account_key=account_key,
            account_label=account_label,
            enabled=enabled,
            calendar_id=normalized_calendar_id,
            timezone=normalized_timezone,
            service_account_email=service_account_email,
            credential_source="browser_upload" if has_uploaded_secret else "none",
            created_at=existing.created_at if existing else now,
            updated_at=now,
        )

        async with self._state_lock:
            self._save_google_calendar_settings(settings)
            self._remember_note(f"Google Calendar-instellingen zijn bijgewerkt voor {account_label}.")
            await self._persist_state()

        return self.operator_status_payload()

    def calendar_feed_url(self) -> str:
        return f"{self.config.public_base_url}/calendar/{self._calendar_feed_token}/rooster.ics"

    def calendar_feed_query_url(self) -> str:
        return f"{self.config.public_base_url}/rooster.ics?token={self._calendar_feed_token}"

    def calendar_feed_token_is_valid(self, token: str | None) -> bool:
        if not token:
            return False
        return hmac.compare_digest(token, self._calendar_feed_token)

    def calendar_feed_token_is_env_managed(self) -> bool:
        return bool(self.config.calendar_feed_token)

    async def rotate_calendar_feed_token(self) -> str:
        if self.calendar_feed_token_is_env_managed():
            raise RuntimeError(
                "De kalenderfeed-token wordt via CALENDAR_FEED_TOKEN beheerd. Pas die omgevingsvariabele aan om de URL te wijzigen."
            )

        new_token = secrets.token_urlsafe(32)
        async with self._state_lock:
            await asyncio.to_thread(self.store.write_calendar_feed_token, new_token)
            self._calendar_feed_token = new_token
            self._remember_note("De geheime ICS-feed URL is vernieuwd vanaf de statuspagina.")
            await self._persist_state()
        return self.calendar_feed_url()

    async def set_sync_enabled(self, enabled: bool) -> str:
        return await self.set_sync_settings(enabled=enabled, interval_minutes=None)

    async def set_sync_settings(self, *, enabled: bool, interval_minutes: int | None) -> str:
        async with self._state_lock:
            interval_changed = False
            if interval_minutes is not None:
                if interval_minutes < 1 or interval_minutes > 10080:
                    raise RuntimeError("Kies een sync-interval tussen 1 minuut en 7 dagen.")
                interval_changed = self.state.sync.sync_interval_minutes != interval_minutes
                self.state.sync.sync_interval_minutes = interval_minutes

            enabled_changed = self.state.sync.sync_enabled != enabled
            if not enabled_changed and not interval_changed:
                return "Synchronisatie staat al ingeschakeld." if enabled else "Synchronisatie staat al uitgeschakeld."

            self.state.sync.sync_enabled = enabled
            self.state.sync.last_message = (
                "Synchronisatie-instellingen zijn opgeslagen."
                if enabled
                else "Synchronisatie is uitgeschakeld. Er worden geen nieuwe aanmeldpogingen gestart."
            )
            if enabled:
                if self.state.sync.current_phase == "disabled":
                    self.state.sync.current_phase = "idle"
                self._remember_note("Synchronisatie-instellingen zijn bijgewerkt vanaf de statuspagina.")
            else:
                self.state.sync.current_phase = "disabled"
                self.state.sync.current_challenge_id = None
                self.state.sync.challenge_created_at = None
                self._clear_pending_challenges()
                self._remember_note("Synchronisatie is uitgeschakeld vanaf de statuspagina.")
            self._set_next_scheduled_sync_locked()
            await self._persist_state()
            self._scheduler_wakeup.set()

        return self.state.sync.last_message or ""

    async def upsert_mobile_setup(
        self,
        *,
        login_url: str,
        portal_id: str | None,
        username: str,
        password: str,
        fcm_token: str,
        device_label: str,
        rotate_api_token: bool,
        auth_token: str | None,
    ) -> dict[str, Any]:
        issued_token: str | None = None
        now = utc_now()
        normalized_fcm_token = fcm_token.strip()

        async with self._state_lock:
            # The backend issues its own bearer token so later updates do not need to resend the setup secret.
            device = self.device_for_mobile_token(auth_token)
            if device is None:
                device = self._device_for_fcm_token(normalized_fcm_token)

            created = device is None
            if device is None:
                device = DeviceRegistration(
                    device_id=secrets.token_urlsafe(10),
                    device_label=device_label.strip() or "Android-telefoon",
                    fcm_token=normalized_fcm_token,
                    api_token_hash="",
                    created_at=now,
                    updated_at=now,
                    last_seen_at=now,
                )

            if created or rotate_api_token or not device.api_token_hash:
                issued_token = self._issue_mobile_token()
                api_token_hash = hashlib.sha256(issued_token.encode("utf-8")).hexdigest()
            else:
                api_token_hash = device.api_token_hash

            updated_device = replace(
                device,
                device_label=device_label.strip() or device.device_label or "Android-telefoon",
                fcm_token=normalized_fcm_token,
                api_token_hash=api_token_hash,
                updated_at=now,
                last_seen_at=now,
            )
            self._save_device(updated_device)
            self.state.active_device_id = updated_device.device_id
            self.credentials = LoginCredentials(
                login_url=self._normalize_external_url(login_url.strip() or self.config.default_login_url),
                username=username.strip(),
                password=password,
                portal_id=portal_id,
            )
            self.state.credentials_updated_at = now
            self._remember_note(
                "De Android-app heeft de verbindingsgegevens bijgewerkt.",
            )
            await self._persist_state()

        await asyncio.to_thread(self.store.clear_auth_session)

        message = "De gegevens zijn opgeslagen. De eerste aanmelding is gestart."
        if self.sync_enabled():
            await self.trigger_refresh(reason="setup", wait=False)
        else:
            async with self._state_lock:
                self.state.sync.current_phase = "disabled"
                self.state.sync.current_challenge_id = None
                self.state.sync.challenge_created_at = None
                self.state.sync.last_message = (
                    "Synchronisatie is uitgeschakeld. De nieuwe gegevens zijn wel opgeslagen."
                )
                self._remember_note(
                    "De Android-app heeft nieuwe verbindingsgegevens opgeslagen terwijl synchronisatie is uitgeschakeld."
                )
                await self._persist_state()
            message = (
                "De gegevens zijn opgeslagen. Synchronisatie is uitgeschakeld; schakel die eerst in om een aanmeldpoging te starten."
            )

        return {
            "created": created,
            "api_token": issued_token,
            "status": self.mobile_status_payload(),
            "message": message,
        }

    async def update_fcm_token(self, token: str, device_label: str | None = None) -> None:
        raise RuntimeError("Gebruik update_fcm_token_for_device met een geldig app-token.")

    async def update_fcm_token_for_device(
        self,
        auth_token: str | None,
        token: str,
        device_label: str | None = None,
    ) -> None:
        async with self._state_lock:
            device = self.device_for_mobile_token(auth_token)
            if device is None:
                raise RuntimeError("Er is nog geen apparaat gekoppeld.")
            updated_at = utc_now()
            updated_device = replace(
                device,
                fcm_token=token.strip(),
                updated_at=updated_at,
                last_seen_at=updated_at,
                device_label=device_label.strip() if device_label else device.device_label,
            )
            self._save_device(updated_device)
            self.state.active_device_id = updated_device.device_id
            if device_label:
                self._remember_note(
                    f"Het FCM-token van {updated_device.device_label} is bijgewerkt.",
                )
            else:
                self._remember_note("De Android-app heeft het FCM-token bijgewerkt.")
            await self._persist_state()

    async def remove_device(self, device_id: str) -> DeviceRegistration:
        async with self._state_lock:
            device = self.device_by_id(device_id)
            if device is None:
                raise RuntimeError("Het opgegeven apparaat bestaat niet meer.")

            return await self._remove_device_locked(device)

    async def remove_device_for_mobile_token(self, auth_token: str | None) -> DeviceRegistration:
        async with self._state_lock:
            device = self.device_for_mobile_token(auth_token)
            if device is None:
                raise RuntimeError("Het gekoppelde apparaat bestaat niet meer of de app-token is ongeldig.")

            return await self._remove_device_locked(device)

    async def submit_sms_code(
        self,
        auth_token: str | None,
        challenge_id: str,
        code: str,
        sender: str,
    ) -> None:
        device = self.device_for_mobile_token(auth_token)
        if device is None:
            raise RuntimeError("De app-token hoort niet bij een gekoppeld apparaat.")

        pending = self._get_pending_challenge(challenge_id)
        if pending is None:
            raise RuntimeError("De aangeleverde SMS-uitdaging is niet meer actief.")
        if pending.device_id != device.device_id:
            raise RuntimeError("Deze SMS-uitdaging hoort bij een ander gekoppeld apparaat.")

        await self._accept_sms_code(
            pending=pending,
            code=code,
            sender=sender,
        )

    async def trigger_refresh(self, reason: str, wait: bool = False) -> dict[str, Any]:
        if not self.sync_enabled():
            raise RuntimeError(SYNC_DISABLED_MESSAGE)
        if self._current_sync_task is None or self._current_sync_task.done():
            self._current_sync_task = asyncio.create_task(self._run_sync(reason))
        if wait:
            await self._current_sync_task
        return self.mobile_status_payload()

    async def rebuild_calendar_from_persisted_exports(self) -> dict[str, Any]:
        exports = await self._load_persisted_roster_exports()
        if not exports:
            raise RuntimeError("Er zijn nog geen roosterexports beschikbaar om de kalender uit JSON op te bouwen.")

        account_key = self.current_account_key()
        recomputed_summaries = [
            self._summarize_roster_export(export_payload, account_key=account_key)
            for export_payload in exports
        ]
        calendar_sync_completed = await self._sync_calendar_exports(exports)
        await asyncio.to_thread(self.store.write_ics, self._generate_ical(exports))
        async with self._state_lock:
            self.state.sync.roster_month_exports = self._replace_roster_month_exports_for_account(
                account_key,
                recomputed_summaries,
            )
            self.state.sync.last_message = "Opgeslagen roosterexports zijn opnieuw verwerkt."
            if calendar_sync_completed:
                self.state.sync.last_completed_sync_at = utc_now()
            await self._persist_state()
        return {
            "ics_updated": True,
            "google_calendar_enabled": self.calendar_sync_enabled(),
            "google_calendar_completed": calendar_sync_completed,
            "export_count": len(exports),
            "status": self.mobile_status_payload(),
        }

    async def sync_calendar_from_persisted_exports(self) -> dict[str, Any]:
        return await self.rebuild_calendar_from_persisted_exports()

    async def send_test_notification(self, message: str, device_id: str | None = None) -> None:
        device = self.active_device() if device_id is None else self.device_by_id(device_id)
        if device is None:
            raise RuntimeError("Er is nog geen Android-apparaat gekoppeld aan de backend.")
        if not device.fcm_token:
            raise RuntimeError("Er is nog geen FCM-token van de Android-app opgeslagen.")
        if not self.push_client.is_configured():
            raise RuntimeError("Firebase Cloud Messaging is nog niet correct geconfigureerd in de backend.")

        await self.push_client.send_auth_result(
            device,
            True,
            message,
        )

    async def activate_device(self, device_id: str) -> DeviceRegistration:
        async with self._state_lock:
            device = self.device_by_id(device_id)
            if device is None:
                raise RuntimeError("Het gevraagde apparaat bestaat niet meer.")
            self.state.active_device_id = device.device_id
            self._remember_note(f"{device.device_label} is als actief apparaat gemarkeerd.")
            await self._persist_state()
            return device

    async def submit_mock_sms_code(self, code: str = "123456", sender: str = "Mock ONS") -> None:
        challenge_id = self.state.sync.current_challenge_id
        if not challenge_id:
            raise RuntimeError("Er is momenteel geen actieve SMS-uitdaging.")
        pending = self._get_pending_challenge(challenge_id)
        if pending is None:
            raise RuntimeError("De actieve SMS-uitdaging is al verlopen.")
        await self._accept_sms_code(
            pending=pending,
            code=code,
            sender=sender,
        )

    async def install_fcm_service_account(self, raw_payload: str) -> dict[str, Any]:
        if not self.config.managed_fcm_upload_enabled:
            raise RuntimeError(
                "De uploadpagina is uitgeschakeld omdat Firebase al via de stack-configuratie wordt beheerd."
            )

        info = FcmPushClient.validate_service_account_json(raw_payload)
        normalized_payload = json.dumps(info, indent=2, ensure_ascii=True)

        async with self._state_lock:
            await asyncio.to_thread(self.store.write_managed_fcm_service_account, normalized_payload)
            self._remember_note("De Firebase-beheersleutel is via de installatiepagina bijgewerkt.")
            await self._persist_state()

        return FcmPushClient(self.config).diagnostics()

    def export_credentials_bundle(self, passphrase: str) -> dict[str, Any]:
        if not self.config.admin_token:
            raise RuntimeError(
                "Credentialexport is uitgeschakeld zolang er geen admin-token is geconfigureerd."
            )
        if hmac.compare_digest(passphrase, self.config.admin_token):
            raise RuntimeError("Kies een andere export-passphrase dan het admin-token.")
        if len(passphrase) < 12:
            raise RuntimeError("Kies een export-passphrase van minimaal 12 tekens.")

        resolved_credentials = self._resolved_credentials()
        if resolved_credentials is None:
            raise RuntimeError("Er zijn nog geen ONS-inloggegevens opgeslagen.")

        bundle = self.store.build_credentials_export(resolved_credentials, passphrase)
        bundle["created_at"] = utc_now()
        return bundle

    def mobile_config_payload(self) -> dict[str, Any]:
        default_portal = self.default_portal()
        return {
            "public_base_url": self.config.public_base_url,
            "default_portal_id": default_portal.portal_id if default_portal else "",
            "portals": self.portal_catalog_payload(),
        }

    def mobile_status_payload(self, auth_token: str | None = None) -> dict[str, Any]:
        resolved_credentials = self._resolved_credentials()
        username = resolved_credentials.username if resolved_credentials else ""
        masked_username = self._mask_value(username)
        active_device = self.active_device()
        current_device = self.device_for_mobile_token(auth_token) if auth_token is not None else active_device
        selected_portal = self.selected_portal()
        calendar_settings = self._effective_google_calendar_settings()
        return {
            "public_base_url": self.config.public_base_url,
            "device_registered": self.has_device(),
            "device_count": self.device_count(),
            "active_device_label": active_device.device_label if active_device else "",
            "credentials_present": resolved_credentials is not None,
            "login_url": resolved_credentials.login_url if resolved_credentials else self._normalize_external_url(self.config.default_login_url),
            "username": masked_username,
            "fcm_configured": self.push_client.is_configured(),
            "portal_id": selected_portal.portal_id if selected_portal else "",
            "portal_name": selected_portal.name if selected_portal else "",
            "portal_logo_url": selected_portal.logo_url if selected_portal else "",
            "portals": self.portal_catalog_payload(),
            "calendar_feed": {
                "url": self.calendar_feed_url(),
                "query_url": self.calendar_feed_query_url(),
                "token_env_managed": self.calendar_feed_token_is_env_managed(),
                "has_payload": self.config.ics_file.exists(),
            },
            "paired": current_device is not None,
            "connected": bool(current_device and self.device_is_connected(current_device.device_id)),
            "device_id": current_device.device_id if current_device else "",
            "sync": {
                "sync_enabled": self.state.sync.sync_enabled,
                "sync_interval_minutes": self.sync_interval_minutes(),
                "next_scheduled_sync_at": self.state.sync.next_scheduled_sync_at,
                "status": self.state.sync.status,
                "current_phase": self.state.sync.current_phase,
                "auth_ready": self.state.sync.auth_ready,
                "last_reason": self.state.sync.last_reason,
                "last_attempt_at": self.state.sync.last_attempt_at,
                "last_success_at": self.state.sync.last_success_at,
                "last_completed_sync_at": self.state.sync.last_completed_sync_at,
                "last_failure_at": self.state.sync.last_failure_at,
                "last_error": self.state.sync.last_error,
                "last_message": self.state.sync.last_message,
                "current_challenge_id": self.state.sync.current_challenge_id,
                "challenge_created_at": self.state.sync.challenge_created_at,
                "last_sms_received_at": self.state.sync.last_sms_received_at,
                "last_sms_code_suffix": self.state.sync.last_sms_code_suffix,
                "last_final_url": self.state.sync.last_final_url,
                "last_page_title": self.state.sync.last_page_title,
                "html_snapshot_path": self.state.sync.html_snapshot_path,
                "post_otp_screenshot_path": self.state.sync.post_otp_screenshot_path,
                "roster_count": len(self.state.sync.roster_items),
                "roster_month_exports": self.roster_month_exports(),
                "debug_notes": list(self.state.sync.debug_notes),
                "auth_trace_run_id": self.state.sync.auth_trace_run_id,
                "auth_trace": self.auth_trace_payload(),
                "debug_screenshots": self.state.sync.debug_screenshots,
                "calendar": {
                    "enabled": self.calendar_sync_enabled(),
                    "configured": self.calendar_sync_configured(),
                    "account_key": calendar_settings["account_key"],
                    "account_label": calendar_settings["account_label"],
                    "calendar_id": calendar_settings["calendar_id"],
                    "timezone": calendar_settings["timezone"],
                    "service_account_email": calendar_settings["service_account_email"],
                    "credential_source": calendar_settings["credential_source"],
                    "dry_run": self.config.google_calendar_dry_run,
                    "last_attempt_at": self.state.sync.calendar_last_attempt_at,
                    "last_success_at": self.state.sync.calendar_last_success_at,
                    "last_failure_at": self.state.sync.calendar_last_failure_at,
                    "last_error": self.state.sync.calendar_last_error,
                    "last_summary": dict(self.state.sync.calendar_last_summary),
                },
            },
        }

    def operator_status_payload(self) -> dict[str, Any]:
        return {
            "public_base_url": self.config.public_base_url,
            "fcm_configured": self.push_client.is_configured(),
            "status": self.mobile_status_payload(),
            "devices": self.paired_devices_payload(),
            "portals": self.portal_catalog_payload(),
        }

    def live_version(self) -> int:
        return self._live_version

    async def wait_for_live_update(self, current_version: int, timeout_seconds: float | None = None) -> int:
        async with self._live_condition:
            if self._live_version != current_version:
                return self._live_version

            waiter = self._live_condition.wait_for(lambda: self._live_version != current_version)
            if timeout_seconds is None:
                await waiter
            else:
                await asyncio.wait_for(waiter, timeout=timeout_seconds)
            return self._live_version

    async def register_mobile_live_connection(self, auth_token: str | None) -> DeviceRegistration:
        async with self._state_lock:
            device = self.device_for_mobile_token(auth_token)
            if device is None:
                raise RuntimeError("De app-token hoort niet bij een gekoppeld apparaat.")

            updated_device = replace(device, last_seen_at=utc_now())
            self._save_device(updated_device)
            self._connected_device_counts[device.device_id] = self._connected_device_counts.get(device.device_id, 0) + 1
            await self._persist_state()
            return updated_device

    async def unregister_mobile_live_connection(self, device_id: str) -> None:
        current_count = self._connected_device_counts.get(device_id, 0)
        if current_count <= 1:
            self._connected_device_counts.pop(device_id, None)
        else:
            self._connected_device_counts[device_id] = current_count - 1
        await self._publish_live_update()

    async def upsert_portal(
        self,
        *,
        portal_id: str | None,
        name: str,
        login_url: str,
        logo_url: str,
    ) -> PortalDefinition:
        normalized_name = name.strip()
        normalized_login_url = self._normalize_external_url(login_url)
        normalized_logo_url = logo_url.strip()
        if not normalized_name or not normalized_login_url:
            raise RuntimeError("Naam en login-URL zijn verplicht.")

        async with self._state_lock:
            existing = self.portal_by_id(portal_id)
            now = utc_now()
            if existing is None:
                portal = PortalDefinition(
                    portal_id=self._unique_portal_id(normalized_name),
                    name=normalized_name,
                    login_url=normalized_login_url,
                    logo_url=normalized_logo_url,
                    created_at=now,
                    updated_at=now,
                )
                self.state.portals.append(portal)
                self._remember_note(f"Portal {portal.name} is toegevoegd.")
            else:
                portal = replace(
                    existing,
                    name=normalized_name,
                    login_url=normalized_login_url,
                    logo_url=normalized_logo_url,
                    updated_at=now,
                )
                self._save_portal(portal)
                self._remember_note(f"Portal {portal.name} is bijgewerkt.")

            await self._persist_state()
            return portal

    async def remove_portal(self, portal_id: str) -> PortalDefinition:
        async with self._state_lock:
            portal = self.portal_by_id(portal_id)
            if portal is None:
                raise RuntimeError("Het gevraagde portal bestaat niet meer.")
            if len(self.state.portals) <= 1:
                raise RuntimeError("Er moet minimaal één portal beschikbaar blijven.")

            self.state.portals = [item for item in self.state.portals if item.portal_id != portal_id]
            if self.credentials is not None and self.credentials.portal_id == portal_id:
                self.credentials = replace(self.credentials, portal_id=None)
            self._remember_note(f"Portal {portal.name} is verwijderd.")
            await self._persist_state()
            return portal

    def roster_items(self) -> list[RosterItem]:
        return list(self.state.sync.roster_items)

    def roster_month_exports(self) -> list[dict[str, Any]]:
        return self._roster_month_exports_for_account(self.current_account_key())

    async def ics_payload(self) -> bytes | None:
        return await asyncio.to_thread(self.store.read_ics)

    async def debug_snapshot_html(self) -> str | None:
        if not self.config.snapshot_file.exists():
            return None
        return await asyncio.to_thread(self.config.snapshot_file.read_text, encoding="utf-8")

    async def post_otp_screenshot(self) -> bytes | None:
        return await asyncio.to_thread(self.store.read_post_otp_screenshot)

    async def screenshot_content(self, filename: str) -> bytes | None:
        """Return raw PNG bytes for a debug trace screenshot by filename."""
        if not filename or "/" in filename or ".." in filename or not filename.endswith(".png"):
            return None
        screenshot_path = self.config.auth_trace_dir / filename
        if not await asyncio.to_thread(screenshot_path.exists):
            return None
        return await asyncio.to_thread(screenshot_path.read_bytes)

    async def toggle_debug_screenshots(self) -> bool:
        """Toggle debug screenshots on/off and persist the new value. Returns the new state."""
        async with self._state_lock:
            self.state.sync.debug_screenshots = not self.state.sync.debug_screenshots
            new_value = self.state.sync.debug_screenshots
            await self._persist_state()
        return new_value

    async def roster_month_export(self, month_key: str, account_key: str | None = None) -> dict[str, Any] | None:
        return await asyncio.to_thread(
            self.store.read_roster_month_export,
            month_key,
            account_key or self.current_account_key(),
        )

    async def auth_trace_snapshot_html(self, entry_id: str) -> str | None:
        entry = next((item for item in self.state.sync.auth_trace if item.get("entry_id") == entry_id), None)
        if entry is None:
            return None
        snapshot_name = str(entry.get("snapshot_name", "")).strip()
        if not snapshot_name:
            return None
        snapshot_path = self.config.auth_trace_dir / snapshot_name
        if not snapshot_path.exists():
            return None
        return await asyncio.to_thread(snapshot_path.read_text, encoding="utf-8")

    def auth_trace_payload(self) -> list[dict[str, Any]]:
        payload: list[dict[str, Any]] = []
        for item in self.state.sync.auth_trace:
            payload.append(
                {
                    "entry_id": item.get("entry_id", ""),
                    "created_at": item.get("created_at", ""),
                    "label": item.get("label", ""),
                    "message": item.get("message", ""),
                    "phase": item.get("phase", ""),
                    "url": item.get("url", ""),
                    "page_title": item.get("page_title", ""),
                    "status_code": item.get("status_code"),
                    "has_snapshot": bool(item.get("snapshot_name")),
                    "snapshot_path": f"/status/auth-trace/{item.get('entry_id', '')}" if item.get("snapshot_name") else "",
                    "debug_snapshot_path": f"/debug/auth-trace/{item.get('entry_id', '')}" if item.get("snapshot_name") else "",
                    "has_screenshot": bool(item.get("screenshot_name")),
                    "screenshot_path": f"/status/screenshot/{item.get('screenshot_name', '')}" if item.get("screenshot_name") else "",
                }
            )
        return payload

    async def _run_sync(self, reason: str) -> None:
        async with self._sync_lock:
            try:
                if not self.sync_enabled():
                    async with self._state_lock:
                        self.state.sync.current_phase = "disabled"
                        self.state.sync.current_challenge_id = None
                        self.state.sync.challenge_created_at = None
                        self.state.sync.last_message = SYNC_DISABLED_MESSAGE
                        await self._persist_state()
                    return

                async with self._state_lock:
                    # The sync state is mirrored to disk before work starts so the debug page always shows progress.
                    self.state.sync.status = "running"
                    self.state.sync.current_phase = "starting"
                    self.state.sync.last_reason = reason
                    self.state.sync.last_attempt_at = utc_now()
                    self.state.sync.last_error = None
                    self.state.sync.last_message = "De backend is gestart met een nieuwe aanmeldpoging."
                    self.state.sync.auth_trace_run_id = secrets.token_urlsafe(8)
                    self.state.sync.auth_trace = []
                    self._remember_note("Er is een nieuwe backend-synchronisatie gestart.")
                    await self._persist_state()

                await asyncio.to_thread(self._reset_auth_trace_dir)

                if self.credentials is None:
                    raise RuntimeError("Er zijn nog geen ONS-inloggegevens opgeslagen.")
                resolved_credentials = self._resolved_credentials()
                assert resolved_credentials is not None
                active_device = self.active_device()
                if active_device is None:
                    raise RuntimeError("Er is nog geen Android-apparaat gekoppeld.")
                if not active_device.fcm_token:
                    raise RuntimeError("Er is nog geen FCM-token van de Android-app bekend.")
                if not self.push_client.is_configured():
                    raise RuntimeError(
                        "Firebase Cloud Messaging is nog niet geconfigureerd in de backend-stack."
                    )

                session_checkpoint = await asyncio.to_thread(self.store.read_auth_session)

                result = await self.automation_client.authenticate_and_scrape(
                    credentials=resolved_credentials,
                    request_sms_code=self._request_sms_code,
                    snapshot_path=self.config.snapshot_file,
                    config=self.config,
                    report_progress=self._record_auth_trace_event,
                    session_checkpoint=session_checkpoint,
                    prepare_sms_relay=self._prepare_sms_relay,
                    wait_for_sms_code=self._wait_for_sms_code,
                    debug_screenshots=self.state.sync.debug_screenshots,
                )
                await self._finalize_success(result)
            except Exception as exc:
                await self._finalize_failure(exc)

    async def _record_auth_trace_event(self, event: dict[str, Any]) -> None:
        entry = {
            "entry_id": str(event.get("entry_id", "")).strip(),
            "created_at": str(event.get("created_at", utc_now())),
            "label": str(event.get("label", "")).strip(),
            "message": str(event.get("message", "")).strip(),
            "phase": str(event.get("phase", "")).strip(),
            "url": str(event.get("url", "")).strip(),
            "page_title": str(event.get("page_title", "")).strip(),
            "snapshot_name": str(event.get("snapshot_name", "")).strip(),
            "screenshot_name": str(event.get("screenshot_name", "")).strip(),
            "status_code": event.get("status_code"),
        }

        async with self._state_lock:
            self.state.sync.auth_trace.append(entry)
            self.state.sync.auth_trace = self.state.sync.auth_trace[-80:]
            if entry["message"]:
                self.state.sync.last_message = entry["message"]
            if entry["phase"]:
                self.state.sync.current_phase = entry["phase"]
            if entry["url"]:
                self.state.sync.last_final_url = entry["url"]
            if entry["page_title"]:
                self.state.sync.last_page_title = entry["page_title"]
            await self._persist_state()

    async def _prepare_sms_relay(self) -> str:
        if not self.sync_enabled():
            raise RuntimeError(SYNC_DISABLED_MESSAGE)

        active_device = self.active_device()
        if active_device is None:
            raise RuntimeError("Er is geen Android-apparaat gekoppeld voor SMS-verificatie.")

        # Each SMS challenge gets its own correlation identifier so retries never reuse stale codes.
        challenge_id = secrets.token_urlsafe(16)
        pending = PendingChallenge(
            challenge_id=challenge_id,
            device_id=active_device.device_id,
            created_at=utc_now(),
            event=threading.Event(),
        )
        self._set_pending_challenge(challenge_id, pending)

        async with self._state_lock:
            self.state.sync.current_phase = "waiting_for_sms"
            self.state.sync.current_challenge_id = challenge_id
            self.state.sync.challenge_created_at = pending.created_at
            self.state.sync.last_message = "Waiting for OTP from Android."
            self._remember_note("SMS relay request sent to Android.")
            await self._persist_state()

        try:
            await self.push_client.send_listen_sms(
                active_device,
                challenge_id,
                self.config.sms_timeout_seconds,
            )
        except Exception:
            self._pop_pending_challenge(challenge_id)
            raise

        return challenge_id

    async def _wait_for_sms_code(self, challenge_id: str) -> str:
        pending = self._get_pending_challenge(challenge_id)
        if pending is None:
            raise RuntimeError("De gevraagde SMS-uitdaging is niet meer actief.")

        try:
            received = await asyncio.to_thread(pending.event.wait, self.config.sms_timeout_seconds)
            if not received:
                raise TimeoutError("Timed out waiting for OTP from Android.")
        except Exception:
            self._pop_pending_challenge(challenge_id)
            raise

        self._pop_pending_challenge(challenge_id)
        assert pending.code is not None
        return pending.code

    async def _request_sms_code(self) -> str:
        challenge_id = await self._prepare_sms_relay()
        return await self._wait_for_sms_code(challenge_id)

    async def _finalize_success(self, result: AuthenticationResult) -> None:
        partial_phase = "otp_required"
        partial_message = "Gebruikersnaam en wachtwoord zijn geaccepteerd. De OTP-pagina is vastgelegd voor de vervolgstap."
        partial_note = "De backend heeft de eerste ONS-loginstap afgerond en wacht op OTP-afhandeling."
        if not result.auth_ready and result.session_checkpoint is not None:
            challenge = result.session_checkpoint.get("challenge", {})
            if isinstance(challenge, dict) and challenge.get("challenge_kind") == "microsoft_proof_selection":
                partial_phase = "mfa_required"
                sms_proof = challenge.get("sms_proof")
                sms_display = ""
                if isinstance(sms_proof, dict):
                    sms_display = str(sms_proof.get("display", "")).strip()
                partial_message = "Username/password accepted. Microsoft verification choice reached; SMS not sent yet."
                if sms_display:
                    partial_message = (
                        "Username/password accepted. "
                        f"Microsoft verification choice reached for {sms_display}; SMS not sent yet."
                    )
                partial_note = (
                    "Microsoft verification choice reached; waiting for explicit SMS send."
                )
            elif isinstance(challenge, dict) and challenge.get("challenge_kind") == "post_otp_result_page":
                partial_phase = "post_otp_page"
                page_summary = str(challenge.get("page_summary", "")).strip()
                partial_message = "OTP submitted and first follow-up page captured."
                if result.page_title:
                    partial_message = (
                        f"OTP submitted and page '{result.page_title}' captured for inspection."
                    )
                if page_summary:
                    partial_message = f"{partial_message} Inhoud: {page_summary}"
                partial_note = (
                    "OTP submitted; waiting for follow-up page handling."
                )

        calendar_sync_completed = False
        if result.auth_ready:
            await asyncio.to_thread(self.store.clear_auth_session)
            account_key = self.current_account_key()
            await asyncio.to_thread(self.store.clear_roster_month_exports, account_key)
            roster_export_summaries: list[dict[str, Any]] = []
            for export_payload in result.roster_exports:
                month_key = str(export_payload.get("month", "")).strip()
                if not month_key:
                    continue
                export_payload["account_key"] = account_key
                await asyncio.to_thread(self.store.write_roster_month_export, month_key, export_payload, account_key)
                roster_export_summaries.append(
                    self._summarize_roster_export(export_payload, account_key=account_key)
                )
            calendar_sync_completed = await self._sync_calendar_exports(result.roster_exports)
        else:
            if result.session_checkpoint is None:
                raise RuntimeError(
                    "De OTP-pagina is bereikt, maar de vervolgsessie kon niet worden opgeslagen."
                )
            await asyncio.to_thread(self.store.write_auth_session, result.session_checkpoint)
            roster_export_summaries = list(self.state.sync.roster_month_exports)
        self._clear_pending_challenges()

        persisted_export_summaries = (
            self._replace_roster_month_exports_for_account(account_key, roster_export_summaries)
            if result.auth_ready
            else roster_export_summaries
        )

        async with self._state_lock:
            # The latest successful page snapshot and roster payload become the operator-facing debug baseline.
            self.state.sync.status = "success" if result.auth_ready else "partial"
            self.state.sync.current_phase = "ready" if result.auth_ready else partial_phase
            self.state.sync.auth_ready = result.auth_ready
            self.state.sync.last_success_at = utc_now()
            self.state.sync.last_error = None
            self.state.sync.last_message = (
                "Authentication complete. Ready to sync."
                if result.auth_ready
                else partial_message
            )
            self.state.sync.current_challenge_id = None
            self.state.sync.challenge_created_at = None
            self.state.sync.last_final_url = result.final_url
            self.state.sync.last_page_title = result.page_title
            self.state.sync.html_snapshot_path = str(self.config.snapshot_file)
            self.state.sync.post_otp_screenshot_path = (
                "/status/post-otp-screenshot"
                if result.post_otp_screenshot_path
                else None
            )
            self.state.sync.roster_items = result.roster_items
            self.state.sync.roster_month_exports = persisted_export_summaries
            self.state.sync.debug_notes = list(result.debug_notes[-25:])
            self._remember_note(
                "ONS authentication completed."
                if result.auth_ready
                else partial_note
            )
            await self._persist_state()
            if result.auth_ready:
                await asyncio.to_thread(self.store.write_ics, self._generate_ical(result.roster_exports))
                if calendar_sync_completed:
                    self.state.sync.last_completed_sync_at = utc_now()
                    self._set_next_scheduled_sync_locked()
                    await self._persist_state()

        if result.auth_ready:
            await self._notify_auth_result(
                True,
                "De backend is aangemeld en klaar voor synchronisatie.",
            )

    async def _sync_calendar_exports(self, month_exports: list[dict[str, Any]]) -> bool:
        attempt_at = utc_now()
        async with self._state_lock:
            self.state.sync.calendar_last_attempt_at = attempt_at
            self.state.sync.calendar_last_error = None
            await self._persist_state()

        if not self.calendar_sync_enabled():
            async with self._state_lock:
                self.state.sync.calendar_last_summary = {}
                await self._persist_state()
            return True

        if not self.calendar_sync_configured():
            message = "Google Calendar synchronisatie is niet volledig geconfigureerd."
            async with self._state_lock:
                self.state.sync.calendar_last_failure_at = utc_now()
                self.state.sync.calendar_last_error = message
                await self._persist_state()
            if self.config.google_calendar_fail_on_error:
                raise RuntimeError(message)
            return False

        try:
            calendar_sync_client = self._calendar_sync_client_for_current_account()
            summary = await asyncio.to_thread(calendar_sync_client.sync_exports, month_exports)
        except Exception as exc:
            async with self._state_lock:
                self.state.sync.calendar_last_failure_at = utc_now()
                self.state.sync.calendar_last_error = str(exc)
                await self._persist_state()
            if self.config.google_calendar_fail_on_error:
                raise RuntimeError(str(exc)) from exc
            return False

        async with self._state_lock:
            self.state.sync.calendar_last_success_at = utc_now()
            self.state.sync.calendar_last_error = None
            self.state.sync.calendar_last_summary = summary.to_dict()
            await self._persist_state()
        return True

    async def _load_persisted_roster_exports(self) -> list[dict[str, Any]]:
        exports: list[dict[str, Any]] = []
        account_key = self.current_account_key()
        for summary in self.state.sync.roster_month_exports:
            summary_account_key = str(summary.get("account_key", account_key)).strip() or account_key
            if summary_account_key != account_key:
                continue
            month_key = str(summary.get("month", "")).strip()
            if not month_key:
                continue
            export_payload = await asyncio.to_thread(self.store.read_roster_month_export, month_key, account_key)
            if export_payload is not None:
                exports.append(export_payload)
        return exports

    async def _finalize_failure(self, exc: Exception) -> None:
        log.exception("Backend sync failed.", exc_info=exc)
        await asyncio.to_thread(self.store.clear_auth_session)
        self._clear_pending_challenges()
        async with self._state_lock:
            self.state.sync.status = "error"
            self.state.sync.current_phase = "error"
            self.state.sync.last_failure_at = utc_now()
            self.state.sync.last_error = str(exc)
            self.state.sync.last_message = "De backend kon de aanmelding niet afronden."
            self.state.sync.current_challenge_id = None
            self.state.sync.challenge_created_at = None
            self._remember_note(f"De backend-synchronisatie is mislukt: {exc}")
            await self._persist_state()

        await self._notify_auth_result(
            False,
            f"Authentication failed: {exc}",
        )

    async def _scheduler_loop(self) -> None:
        while True:
            interval_minutes = self.sync_interval_minutes()
            if not self.sync_enabled() or interval_minutes <= 0:
                async with self._state_lock:
                    if self.state.sync.next_scheduled_sync_at is not None:
                        self.state.sync.next_scheduled_sync_at = None
                        await self._persist_state()
                await self._wait_for_scheduler_wakeup(60)
                continue

            async with self._state_lock:
                self._set_next_scheduled_sync_locked()
                await self._persist_state()

            if await self._wait_for_scheduler_wakeup(interval_minutes * 60):
                continue

            try:
                if self.sync_enabled() and self.credentials is not None and self.active_device() is not None:
                    await self.trigger_refresh(reason="scheduled", wait=True)
            except Exception:
                log.exception("Scheduled sync failed.")

    async def _wait_for_scheduler_wakeup(self, timeout_seconds: float) -> bool:
        try:
            await asyncio.wait_for(self._scheduler_wakeup.wait(), timeout=timeout_seconds)
        except TimeoutError:
            return False
        finally:
            self._scheduler_wakeup.clear()
        return True

    def _generate_ical(self, month_exports: list[dict[str, Any]] | None = None) -> bytes:
        if month_exports:
            return build_icalendar(
                month_exports,
                timezone_name=self.config.google_calendar_timezone or self.config.timezone,
            )

        timezone = timezone_or_utc(self.config.timezone)
        generated_at = datetime.now(UTC).replace(microsecond=0)
        calendar = Calendar()
        calendar.add("prodid", "-//ONS Rooster Backend//NL")
        calendar.add("version", "2.0")
        calendar.add("x-wr-calname", "ONS Rooster")
        calendar.add("x-wr-timezone", timezone.key)
        calendar.add("method", "PUBLISH")

        for item in self.state.sync.roster_items:
            start = parse_local_datetime(item.date, item.start, timezone)
            end = parse_local_datetime(item.date, item.end, timezone)
            if start is None or end is None:
                continue
            if end <= start:
                end = end + timedelta(days=1)
            event = Event()
            event.add("uid", self._fallback_ical_uid(item))
            event.add("summary", item.description)
            event.add("dtstart", start)
            event.add("dtend", end)
            event.add("dtstamp", generated_at)
            event.add("last-modified", generated_at)
            event.add("categories", ["ONS Rooster"])
            calendar.add_component(event)

        return calendar.to_ical()

    @staticmethod
    def _fallback_ical_uid(item: RosterItem) -> str:
        payload = json.dumps(item.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"ons-rooster-{digest}@ons-rooster-backend"

    def _resolve_calendar_feed_token(self) -> str:
        if self.config.calendar_feed_token:
            return self.config.calendar_feed_token

        stored_token = self.store.read_calendar_feed_token()
        if stored_token:
            return stored_token

        token = secrets.token_urlsafe(32)
        self.store.write_calendar_feed_token(token)
        return token

    def _remember_note(self, message: str) -> None:
        timestamped = f"{utc_now()} {message}"
        self.state.sync.debug_notes.append(timestamped)
        self.state.sync.debug_notes = self.state.sync.debug_notes[-25:]

    def _issue_mobile_token(self) -> str:
        return secrets.token_urlsafe(32)

    async def _notify_auth_result(self, success: bool, message: str) -> None:
        active_device = self.active_device()
        if active_device is None:
            return
        if not self.push_client.is_configured():
            log.info("Skipping auth notification because Firebase Cloud Messaging is not configured.")
            return

        try:
            await self.push_client.send_auth_result(
                active_device,
                success,
                message,
            )
        except Exception:
            log.exception("Failed to send an auth status notification.")

    async def _accept_sms_code(
        self,
        *,
        pending: PendingChallenge,
        code: str,
        sender: str,
    ) -> None:
        if not self.sync_enabled():
            raise RuntimeError(SYNC_DISABLED_MESSAGE)

        normalized_code = code.strip()
        received_at = utc_now()
        pending.sender = sender
        pending.code = normalized_code

        auth_trace_entry: dict[str, Any] | None = None
        receipt_message = (
            f"OTP {normalized_code} received from Android."
            if normalized_code
            else "Empty OTP received from Android."
        )

        async with self._state_lock:
            self.state.sync.last_sms_received_at = received_at
            self.state.sync.last_sms_code_suffix = normalized_code[-2:] if normalized_code else None
            self.state.sync.current_phase = "sms_received"
            self.state.sync.last_message = receipt_message
            self._remember_note(receipt_message)
            auth_trace_entry = {
                "entry_id": f"step-{len(self.state.sync.auth_trace) + 1:03d}",
                "created_at": received_at,
                "label": "OTP received",
                "message": receipt_message,
                "phase": "sms_received",
                "url": self.state.sync.last_final_url,
                "page_title": self.state.sync.last_page_title,
            }
            await self._persist_state()

        pending.event.set()
        if auth_trace_entry is not None:
            await self._record_auth_trace_event(auth_trace_entry)

    def _device_for_fcm_token(self, fcm_token: str) -> DeviceRegistration | None:
        for device in self.state.devices:
            if device.fcm_token == fcm_token:
                return device
        return None

    def _save_device(self, updated_device: DeviceRegistration) -> None:
        for index, device in enumerate(self.state.devices):
            if device.device_id == updated_device.device_id:
                self.state.devices[index] = updated_device
                return
        self.state.devices.append(updated_device)

    def _save_portal(self, updated_portal: PortalDefinition) -> None:
        for index, portal in enumerate(self.state.portals):
            if portal.portal_id == updated_portal.portal_id:
                self.state.portals[index] = updated_portal
                return
        self.state.portals.append(updated_portal)

    def _save_google_calendar_settings(self, updated_settings: GoogleCalendarSettings) -> None:
        for index, settings in enumerate(self.state.google_calendar_settings):
            if settings.account_key == updated_settings.account_key:
                self.state.google_calendar_settings[index] = updated_settings
                return
        self.state.google_calendar_settings.append(updated_settings)

    def _google_calendar_settings_for_account(self, account_key: str) -> GoogleCalendarSettings | None:
        for settings in self.state.google_calendar_settings:
            if settings.account_key == account_key:
                return settings
        return None

    def _roster_month_exports_for_account(self, account_key: str) -> list[dict[str, Any]]:
        return [
            summary
            for summary in self.state.sync.roster_month_exports
            if self._summary_account_key(summary, account_key) == account_key
        ]

    def _replace_roster_month_exports_for_account(
        self,
        account_key: str,
        replacement_summaries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        retained_summaries = [
            summary
            for summary in self.state.sync.roster_month_exports
            if self._summary_account_key(summary, account_key) != account_key
        ]
        return retained_summaries + replacement_summaries

    @staticmethod
    def _summary_account_key(summary: dict[str, Any], fallback_account_key: str) -> str:
        return str(summary.get("account_key", fallback_account_key)).strip() or fallback_account_key

    def _effective_google_calendar_settings(self, account_key: str | None = None) -> dict[str, Any]:
        resolved_account_key = account_key or self.current_account_key()
        account_settings = self._google_calendar_settings_for_account(resolved_account_key)
        if account_settings is not None:
            service_account_json = self.store.read_google_calendar_service_account(resolved_account_key) or ""
            return {
                "enabled": account_settings.enabled,
                "account_key": resolved_account_key,
                "account_label": account_settings.account_label,
                "calendar_id": account_settings.calendar_id,
                "timezone": account_settings.timezone,
                "service_account_file": "",
                "service_account_json": service_account_json,
                "service_account_email": account_settings.service_account_email,
                "credential_source": account_settings.credential_source,
            }

        service_account_email = ""
        if self.config.google_calendar_service_account_json:
            try:
                info = GoogleCalendarSyncClient.validate_service_account_json(
                    self.config.google_calendar_service_account_json,
                )
                service_account_email = str(info.get("client_email", "")).strip()
            except RuntimeError:
                service_account_email = ""

        return {
            "enabled": self.config.google_calendar_sync_enabled,
            "account_key": resolved_account_key,
            "account_label": self.current_account_label(),
            "calendar_id": self.config.google_calendar_id,
            "timezone": timezone_or_utc(self.config.google_calendar_timezone or self.config.timezone).key,
            "service_account_file": (
                str(self.config.google_calendar_service_account_file)
                if self.config.google_calendar_service_account_file
                else ""
            ),
            "service_account_json": self.config.google_calendar_service_account_json,
            "service_account_email": service_account_email,
            "credential_source": "environment" if (
                self.config.google_calendar_service_account_file
                or self.config.google_calendar_service_account_json
            ) else "none",
        }

    def _build_google_calendar_sync_client(self, account_key: str | None = None) -> GoogleCalendarSyncClient:
        settings = self._effective_google_calendar_settings(account_key)
        return GoogleCalendarSyncClient(
            calendar_id=str(settings["calendar_id"]),
            timezone=str(settings["timezone"]),
            service_account_file=str(settings["service_account_file"]),
            service_account_json=str(settings["service_account_json"]),
            dry_run=self.config.google_calendar_dry_run,
        )

    def _calendar_sync_client_for_current_account(self) -> CalendarSyncClient:
        if self._calendar_sync_client_override is not None:
            return self._calendar_sync_client_override
        return self._build_google_calendar_sync_client(self.current_account_key())

    async def _remove_device_locked(self, device: DeviceRegistration) -> DeviceRegistration:
        self.state.devices = [item for item in self.state.devices if item.device_id != device.device_id]
        self._connected_device_counts.pop(device.device_id, None)
        if self.state.active_device_id == device.device_id:
            self.state.active_device_id = self.state.devices[-1].device_id if self.state.devices else None

        if not self.state.devices:
            self._clear_pending_challenges()

        self._remember_note(f"Het gekoppelde apparaat {device.device_label} is verwijderd.")
        await self._persist_state()
        return device

    async def _persist_state(self) -> None:
        await asyncio.to_thread(self.store.save, self.state, self.credentials)
        await self._publish_live_update()

    def _get_pending_challenge(self, challenge_id: str) -> PendingChallenge | None:
        with self._pending_challenges_lock:
            return self._pending_challenges.get(challenge_id)

    def _set_pending_challenge(self, challenge_id: str, pending: PendingChallenge) -> None:
        with self._pending_challenges_lock:
            self._pending_challenges[challenge_id] = pending

    def _pop_pending_challenge(self, challenge_id: str) -> PendingChallenge | None:
        with self._pending_challenges_lock:
            return self._pending_challenges.pop(challenge_id, None)

    def _clear_pending_challenges(self) -> None:
        with self._pending_challenges_lock:
            self._pending_challenges.clear()

    def _reset_auth_trace_dir(self) -> None:
        if self.config.auth_trace_dir.exists():
            shutil.rmtree(self.config.auth_trace_dir)
        self.config.auth_trace_dir.mkdir(parents=True, exist_ok=True)

    async def _publish_live_update(self) -> None:
        async with self._live_condition:
            self._live_version += 1
            self._live_condition.notify_all()

    def _resolved_credentials(self) -> LoginCredentials | None:
        if self.credentials is None:
            return None

        selected_portal = self.selected_portal()
        if selected_portal is not None and (
            self.credentials.portal_id == selected_portal.portal_id
            or self._normalize_external_url(self.credentials.login_url) == self._normalize_external_url(selected_portal.login_url)
        ):
            return replace(self.credentials, login_url=selected_portal.login_url, portal_id=selected_portal.portal_id)

        return replace(self.credentials, login_url=self._normalize_external_url(self.credentials.login_url))

    def _ensure_default_portals(self) -> None:
        if self.state.portals:
            return

        now = utc_now()
        self.state.portals = [
            PortalDefinition(
                portal_id=DEFAULT_PORTAL_ID,
                name=DEFAULT_PORTAL_NAME,
                login_url=self._normalize_external_url(self.config.default_login_url),
                logo_url=DEFAULT_PORTAL_LOGO_URL,
                created_at=now,
                updated_at=now,
            )
        ]

    def _unique_portal_id(self, name: str) -> str:
        base = self._slugify(name)
        candidate = base
        suffix = 2
        existing_ids = {portal.portal_id for portal in self.state.portals}
        while candidate in existing_ids:
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate

    @staticmethod
    def _normalize_external_url(url: str) -> str:
        trimmed = url.strip().rstrip("/")
        if not trimmed:
            return ""
        if trimmed.startswith("https://") or trimmed.startswith("http://"):
            return trimmed
        return f"https://{trimmed}"

    @staticmethod
    def _slugify(value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
        return normalized.strip("-") or "portal"

    @staticmethod
    def _suffix(value: str, size: int = 12) -> str:
        if not value:
            return ""
        if len(value) <= size:
            return value
        return value[-size:]

    @staticmethod
    def _mask_value(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

    @staticmethod
    def _account_key(username: str) -> str:
        normalized = username.strip().lower() or "default"
        if normalized == "default":
            return "default"
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
