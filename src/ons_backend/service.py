from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from icalendar import Calendar, Event

from .clients import AutomationClient, FcmPushClient, PushClient
from .config import AppConfig
from .models import AppState, AuthenticationResult, DeviceRegistration, LoginCredentials, RosterItem
from .storage import StateStore

log = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PendingChallenge:
    challenge_id: str
    device_id: str
    created_at: str
    event: asyncio.Event
    sender: str | None = None
    code: str | None = None


class BackendService:
    def __init__(
        self,
        config: AppConfig,
        store: StateStore,
        push_client: PushClient,
        automation_client: AutomationClient,
    ) -> None:
        self.config = config
        self.store = store
        self.push_client = push_client
        self.automation_client = automation_client
        self.state, self.credentials = self.store.load()
        self._pending_challenges: dict[str, PendingChallenge] = {}
        self._state_lock = asyncio.Lock()
        self._sync_lock = asyncio.Lock()
        self._scheduler_task: asyncio.Task[None] | None = None
        self._current_sync_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self.config.sync_interval_minutes > 0:
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

    async def upsert_mobile_setup(
        self,
        *,
        login_url: str,
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
                login_url=login_url.strip() or self.config.default_login_url,
                username=username.strip(),
                password=password,
            )
            self.state.credentials_updated_at = now
            self._remember_note(
                "De Android-app heeft de verbindingsgegevens bijgewerkt.",
            )
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

        await self.trigger_refresh(reason="setup", wait=False)

        return {
            "created": created,
            "api_token": issued_token,
            "status": self.mobile_status_payload(),
            "message": "De gegevens zijn opgeslagen. De eerste aanmelding is gestart.",
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
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

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

        pending = self._pending_challenges.get(challenge_id)
        if pending is None:
            raise RuntimeError("De aangeleverde SMS-uitdaging is niet meer actief.")
        if pending.device_id != device.device_id:
            raise RuntimeError("Deze SMS-uitdaging hoort bij een ander gekoppeld apparaat.")

        await self._accept_sms_code(
            pending=pending,
            code=code,
            sender=sender,
            note="De backend heeft een SMS-code van de Android-app ontvangen.",
        )

    async def trigger_refresh(self, reason: str, wait: bool = False) -> dict[str, Any]:
        if self._current_sync_task is None or self._current_sync_task.done():
            self._current_sync_task = asyncio.create_task(self._run_sync(reason))
        if wait:
            await self._current_sync_task
        return self.mobile_status_payload()

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
            await asyncio.to_thread(self.store.save, self.state, self.credentials)
            return device

    async def submit_mock_sms_code(self, code: str = "123456", sender: str = "Mock ONS") -> None:
        challenge_id = self.state.sync.current_challenge_id
        if not challenge_id:
            raise RuntimeError("Er is momenteel geen actieve SMS-uitdaging.")
        pending = self._pending_challenges.get(challenge_id)
        if pending is None:
            raise RuntimeError("De actieve SMS-uitdaging is al verlopen.")
        await self._accept_sms_code(
            pending=pending,
            code=code,
            sender=sender,
            note="De backend heeft een mock SMS-code ontvangen vanaf de statuspagina.",
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
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

        return FcmPushClient(self.config).diagnostics()

    def mobile_status_payload(self) -> dict[str, Any]:
        username = self.credentials.username if self.credentials else ""
        masked_username = self._mask_value(username)
        active_device = self.active_device()
        return {
            "public_base_url": self.config.public_base_url,
            "device_registered": self.has_device(),
            "device_count": self.device_count(),
            "active_device_label": active_device.device_label if active_device else "",
            "credentials_present": self.credentials is not None,
            "login_url": self.credentials.login_url if self.credentials else self.config.default_login_url,
            "username": masked_username,
            "fcm_configured": self.push_client.is_configured(),
            "sync": {
                "status": self.state.sync.status,
                "current_phase": self.state.sync.current_phase,
                "auth_ready": self.state.sync.auth_ready,
                "last_reason": self.state.sync.last_reason,
                "last_attempt_at": self.state.sync.last_attempt_at,
                "last_success_at": self.state.sync.last_success_at,
                "last_failure_at": self.state.sync.last_failure_at,
                "last_error": self.state.sync.last_error,
                "last_message": self.state.sync.last_message,
                "current_challenge_id": self.state.sync.current_challenge_id,
                "challenge_created_at": self.state.sync.challenge_created_at,
                "last_sms_received_at": self.state.sync.last_sms_received_at,
                "last_sms_code_suffix": self.state.sync.last_sms_code_suffix,
                "last_final_url": self.state.sync.last_final_url,
                "last_page_title": self.state.sync.last_page_title,
                "roster_count": len(self.state.sync.roster_items),
                "debug_notes": list(self.state.sync.debug_notes),
            },
        }

    def roster_items(self) -> list[RosterItem]:
        return list(self.state.sync.roster_items)

    async def ics_payload(self) -> bytes | None:
        return await asyncio.to_thread(self.store.read_ics)

    async def debug_snapshot_html(self) -> str | None:
        if not self.config.snapshot_file.exists():
            return None
        return await asyncio.to_thread(self.config.snapshot_file.read_text, encoding="utf-8")

    async def _run_sync(self, reason: str) -> None:
        async with self._sync_lock:
            try:
                async with self._state_lock:
                    # The sync state is mirrored to disk before work starts so the debug page always shows progress.
                    self.state.sync.status = "running"
                    self.state.sync.current_phase = "starting"
                    self.state.sync.last_reason = reason
                    self.state.sync.last_attempt_at = utc_now()
                    self.state.sync.last_error = None
                    self.state.sync.last_message = "De backend is gestart met een nieuwe aanmeldpoging."
                    self._remember_note("Er is een nieuwe backend-synchronisatie gestart.")
                    await asyncio.to_thread(self.store.save, self.state, self.credentials)

                if self.credentials is None:
                    raise RuntimeError("Er zijn nog geen ONS-inloggegevens opgeslagen.")
                active_device = self.active_device()
                if active_device is None:
                    raise RuntimeError("Er is nog geen Android-apparaat gekoppeld.")
                if not active_device.fcm_token:
                    raise RuntimeError("Er is nog geen FCM-token van de Android-app bekend.")
                if not self.push_client.is_configured():
                    raise RuntimeError(
                        "Firebase Cloud Messaging is nog niet geconfigureerd in de backend-stack."
                    )

                result = await self.automation_client.authenticate_and_scrape(
                    credentials=self.credentials,
                    request_sms_code=self._request_sms_code,
                    snapshot_path=self.config.snapshot_file,
                    config=self.config,
                )
                await self._finalize_success(result)
            except Exception as exc:
                await self._finalize_failure(exc)

    async def _request_sms_code(self) -> str:
        active_device = self.active_device()
        if active_device is None:
            raise RuntimeError("Er is geen Android-apparaat gekoppeld voor SMS-verificatie.")

        # Each SMS challenge gets its own correlation identifier so retries never reuse stale codes.
        challenge_id = secrets.token_urlsafe(16)
        pending = PendingChallenge(
            challenge_id=challenge_id,
            device_id=active_device.device_id,
            created_at=utc_now(),
            event=asyncio.Event(),
        )
        self._pending_challenges[challenge_id] = pending

        async with self._state_lock:
            self.state.sync.current_phase = "waiting_for_sms"
            self.state.sync.current_challenge_id = challenge_id
            self.state.sync.challenge_created_at = pending.created_at
            self.state.sync.last_message = "De backend wacht op de SMS-code van de Android-app."
            self._remember_note("De backend heeft een SMS-luisterverzoek naar de Android-app verstuurd.")
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

        try:
            await self.push_client.send_listen_sms(
                active_device,
                challenge_id,
                self.config.sms_timeout_seconds,
            )
            await asyncio.wait_for(pending.event.wait(), timeout=self.config.sms_timeout_seconds)
        except Exception:
            self._pending_challenges.pop(challenge_id, None)
            raise

        self._pending_challenges.pop(challenge_id, None)
        assert pending.code is not None
        return pending.code

    async def _finalize_success(self, result: AuthenticationResult) -> None:
        async with self._state_lock:
            # The latest successful page snapshot and roster payload become the operator-facing debug baseline.
            self.state.sync.status = "success"
            self.state.sync.current_phase = "ready"
            self.state.sync.auth_ready = result.auth_ready
            self.state.sync.last_success_at = utc_now()
            self.state.sync.last_error = None
            self.state.sync.last_message = "De backend is succesvol aangemeld en klaar om te synchroniseren."
            self.state.sync.current_challenge_id = None
            self.state.sync.challenge_created_at = None
            self.state.sync.last_final_url = result.final_url
            self.state.sync.last_page_title = result.page_title
            self.state.sync.html_snapshot_path = str(self.config.snapshot_file)
            self.state.sync.roster_items = result.roster_items
            self.state.sync.debug_notes = list(result.debug_notes[-25:])
            self._remember_note("De backend heeft de ONS-aanmelding succesvol afgerond.")
            await asyncio.to_thread(self.store.save, self.state, self.credentials)
            await asyncio.to_thread(self.store.write_ics, self._generate_ical())

        await self._notify_auth_result(
            True,
            "De backend is aangemeld en klaar voor synchronisatie.",
        )

    async def _finalize_failure(self, exc: Exception) -> None:
        log.exception("Backend sync failed.", exc_info=exc)
        async with self._state_lock:
            self.state.sync.status = "error"
            self.state.sync.current_phase = "error"
            self.state.sync.last_failure_at = utc_now()
            self.state.sync.last_error = str(exc)
            self.state.sync.last_message = "De backend kon de aanmelding niet afronden."
            self.state.sync.current_challenge_id = None
            self.state.sync.challenge_created_at = None
            self._remember_note(f"De backend-synchronisatie is mislukt: {exc}")
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

        await self._notify_auth_result(
            False,
            f"De backend kon de aanmelding niet afronden: {exc}",
        )

    async def _scheduler_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.sync_interval_minutes * 60)
            try:
                if self.credentials is not None and self.active_device() is not None:
                    await self.trigger_refresh(reason="scheduled", wait=True)
            except Exception:
                log.exception("Scheduled sync failed.")

    def _generate_ical(self) -> bytes:
        calendar = Calendar()
        calendar.add("prodid", "-//ONS Rooster Backend//NL")
        calendar.add("version", "2.0")
        calendar.add("x-wr-calname", "ONS Rooster")

        for item in self.state.sync.roster_items:
            start = self._parse_datetime(item.date, item.start)
            end = self._parse_datetime(item.date, item.end)
            if start is None or end is None:
                continue
            event = Event()
            event.add("summary", item.description)
            event.add("dtstart", start)
            event.add("dtend", end)
            event.add("dtstamp", datetime.now(UTC))
            calendar.add_component(event)

        return calendar.to_ical()

    def _parse_datetime(self, date_value: str, time_value: str):
        if not date_value or not time_value:
            return None
        normalized = date_value.replace("/", "-")
        for fmt in ("%d-%m-%Y %H:%M", "%d-%m-%y %H:%M"):
            try:
                return datetime.strptime(f"{normalized} {time_value}", fmt)
            except ValueError:
                continue
        return None

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
        note: str,
    ) -> None:
        pending.sender = sender
        pending.code = code.strip()
        pending.event.set()

        async with self._state_lock:
            self.state.sync.last_sms_received_at = utc_now()
            self.state.sync.last_sms_code_suffix = code.strip()[-2:] if code.strip() else None
            self.state.sync.current_phase = "sms_received"
            self.state.sync.last_message = "De SMS-code is ontvangen door de backend."
            self._remember_note(note)
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

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
