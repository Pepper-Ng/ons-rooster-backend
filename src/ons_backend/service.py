from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from icalendar import Calendar, Event

from .clients import AutomationClient, PushClient
from .config import AppConfig
from .models import AppState, AuthenticationResult, DeviceRegistration, LoginCredentials, RosterItem
from .storage import StateStore

log = logging.getLogger(__name__)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PendingChallenge:
    challenge_id: str
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
        return self.state.device is not None

    def mobile_token_is_valid(self, token: str | None) -> bool:
        if not token or not self.state.device or not self.state.device.api_token_hash:
            return False
        expected = self.state.device.api_token_hash
        actual = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return hmac.compare_digest(expected, actual)

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
    ) -> dict[str, Any]:
        issued_token: str | None = None
        now = utc_now()

        async with self._state_lock:
            # The backend issues its own bearer token so later updates do not need to resend the setup secret.
            created = self.state.device is None
            if created or rotate_api_token or not self.state.device or not self.state.device.api_token_hash:
                issued_token = self._issue_mobile_token()
                api_token_hash = hashlib.sha256(issued_token.encode("utf-8")).hexdigest()
            else:
                api_token_hash = self.state.device.api_token_hash

            self.state.device = DeviceRegistration(
                device_label=device_label.strip() or "Android-telefoon",
                fcm_token=fcm_token.strip(),
                api_token_hash=api_token_hash,
                created_at=self.state.device.created_at if self.state.device else now,
                updated_at=now,
                last_seen_at=now,
            )
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
        async with self._state_lock:
            if self.state.device is None:
                raise RuntimeError("Er is nog geen apparaat gekoppeld.")
            self.state.device.fcm_token = token.strip()
            self.state.device.updated_at = utc_now()
            self.state.device.last_seen_at = self.state.device.updated_at
            if device_label:
                self.state.device.device_label = device_label.strip()
            self._remember_note("De Android-app heeft het FCM-token bijgewerkt.")
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

    async def submit_sms_code(self, challenge_id: str, code: str, sender: str) -> None:
        pending = self._pending_challenges.get(challenge_id)
        if pending is None:
            raise RuntimeError("De aangeleverde SMS-uitdaging is niet meer actief.")

        pending.sender = sender
        pending.code = code.strip()
        pending.event.set()

        async with self._state_lock:
            self.state.sync.last_sms_received_at = utc_now()
            self.state.sync.last_sms_code_suffix = code.strip()[-2:] if code.strip() else None
            self.state.sync.current_phase = "sms_received"
            self.state.sync.last_message = "De SMS-code is ontvangen door de backend."
            self._remember_note("De backend heeft een SMS-code van de Android-app ontvangen.")
            await asyncio.to_thread(self.store.save, self.state, self.credentials)

    async def trigger_refresh(self, reason: str, wait: bool = False) -> dict[str, Any]:
        if self._current_sync_task is None or self._current_sync_task.done():
            self._current_sync_task = asyncio.create_task(self._run_sync(reason))
        if wait:
            await self._current_sync_task
        return self.mobile_status_payload()

    def mobile_status_payload(self) -> dict[str, Any]:
        username = self.credentials.username if self.credentials else ""
        masked_username = self._mask_value(username)
        return {
            "public_base_url": self.config.public_base_url,
            "device_registered": self.state.device is not None,
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
                if self.state.device is None:
                    raise RuntimeError("Er is nog geen Android-apparaat gekoppeld.")
                if not self.state.device.fcm_token:
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
        if self.state.device is None:
            raise RuntimeError("Er is geen Android-apparaat gekoppeld voor SMS-verificatie.")

        # Each SMS challenge gets its own correlation identifier so retries never reuse stale codes.
        challenge_id = secrets.token_urlsafe(16)
        pending = PendingChallenge(
            challenge_id=challenge_id,
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
                self.state.device,
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

        if self.state.device is not None:
            await self.push_client.send_auth_result(
                self.state.device,
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

        if self.state.device is not None:
            await self.push_client.send_auth_result(
                self.state.device,
                False,
                f"De backend kon de aanmelding niet afronden: {exc}",
            )

    async def _scheduler_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.sync_interval_minutes * 60)
            try:
                if self.credentials is not None and self.state.device is not None:
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

    @staticmethod
    def _mask_value(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
