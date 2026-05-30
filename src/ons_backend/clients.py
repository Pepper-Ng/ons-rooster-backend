from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlparse

import google.auth.transport.requests
import google.oauth2.service_account
import requests
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet, InvalidToken
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from .config import AppConfig
from .models import AuthenticationResult, DeviceRegistration, LoginCredentials, RosterItem

log = logging.getLogger(__name__)

SmsRelayPrimer = Callable[[], Awaitable[str]]
SmsCodeAwaiter = Callable[[str], Awaitable[str]]


class PushClient(Protocol):
    async def send_listen_sms(
        self,
        device: DeviceRegistration,
        challenge_id: str,
        timeout_seconds: int,
    ) -> None:
        ...

    async def send_auth_result(
        self,
        device: DeviceRegistration,
        success: bool,
        message: str,
    ) -> None:
        ...

    def is_configured(self) -> bool:
        ...


class AutomationClient(Protocol):
    async def authenticate_and_scrape(
        self,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        session_checkpoint: dict[str, Any] | None = None,
        prepare_sms_relay: SmsRelayPrimer | None = None,
        wait_for_sms_code: SmsCodeAwaiter | None = None,
    ) -> AuthenticationResult:
        ...


class FcmPushClient:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    @staticmethod
    def validate_service_account_json(raw_payload: str) -> dict[str, Any]:
        try:
            info = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Het geuploade Firebase-bestand is geen geldige JSON.") from exc

        if not isinstance(info, dict):
            raise RuntimeError("Het geuploade Firebase-bestand moet een JSON-object bevatten.")

        if str(info.get("type", "")).strip() != "service_account":
            raise RuntimeError("Het geuploade bestand is geen Firebase service-account JSON.")

        missing = [
            field_name
            for field_name in ("project_id", "client_email", "private_key")
            if not str(info.get(field_name, "")).strip()
        ]
        if missing:
            raise RuntimeError(
                "De Firebase-sleutel mist verplichte velden: " + ", ".join(missing)
            )

        return info

    def diagnostics(self) -> dict[str, Any]:
        service_account_path = self._diagnostic_service_account_path()
        file_exists = bool(
            self.config.fcm_service_account_file and self.config.fcm_service_account_file.exists()
        )
        if not file_exists and self.config.managed_fcm_upload_enabled:
            file_exists = self.config.managed_fcm_service_account_file.exists()
        using_inline_json = bool(self.config.fcm_service_account_json)

        try:
            project_id = self.project_id()
            config_error = ""
        except Exception as exc:
            project_id = ""
            config_error = str(exc)

        return {
            "configured": self.is_configured(),
            "project_id": project_id,
            "service_account_path": service_account_path,
            "service_account_file_exists": file_exists,
            "service_account_source": self._service_account_source(),
            "using_inline_json": using_inline_json,
            "installer_available": self.config.managed_fcm_upload_enabled,
            "config_error": config_error,
        }

    def project_id(self) -> str:
        if self.config.fcm_project_id:
            return self.config.fcm_project_id

        info = self._load_service_account_info()
        project_id = str(info.get("project_id", "")).strip()
        if not project_id:
            raise RuntimeError("The Firebase service account does not contain a project_id.")
        return project_id

    def is_configured(self) -> bool:
        try:
            return bool(self.project_id() and self._has_service_account_source())
        except Exception:
            return False

    async def send_listen_sms(
        self,
        device: DeviceRegistration,
        challenge_id: str,
        timeout_seconds: int,
    ) -> None:
        payload = {
            "message": {
                "token": device.fcm_token,
                "data": {
                    "type": "listen_sms",
                    "challenge_id": challenge_id,
                    "callback_path": f"/api/v1/mobile/challenges/{challenge_id}/sms-code",
                    "expires_in_seconds": str(timeout_seconds),
                },
                "android": {"priority": "high"},
            }
        }
        await self._send(payload)

    async def send_auth_result(
        self,
        device: DeviceRegistration,
        success: bool,
        message: str,
    ) -> None:
        payload = {
            "message": {
                "token": device.fcm_token,
                "data": {
                    "type": "auth_result",
                    "status": "success" if success else "failure",
                    "message": message,
                },
                "android": {"priority": "high"},
            }
        }
        await self._send(payload)

    async def _send(self, payload: dict[str, object]) -> None:
        if not self.is_configured():
            raise RuntimeError("Firebase Cloud Messaging is not configured.")

        await asyncio.to_thread(self._send_sync, payload)

    def _send_sync(self, payload: dict[str, object]) -> None:
        # The backend talks to the FCM HTTP v1 API directly so Portainer deployments stay self-contained.
        credentials = self._load_credentials()
        credentials.refresh(google.auth.transport.requests.Request())
        response = requests.post(
            f"https://fcm.googleapis.com/v1/projects/{self.project_id()}/messages:send",
            headers={
                "Authorization": f"Bearer {credentials.token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=15,
        )
        response.raise_for_status()

    def _load_credentials(self) -> google.oauth2.service_account.Credentials:
        scopes = ["https://www.googleapis.com/auth/firebase.messaging"]
        return google.oauth2.service_account.Credentials.from_service_account_info(
            self._load_service_account_info(),
            scopes=scopes,
        )

    def _has_service_account_source(self) -> bool:
        return bool(
            self.config.fcm_service_account_json
            or (self.config.fcm_service_account_file and self.config.fcm_service_account_file.exists())
            or self.config.managed_fcm_service_account_file.exists()
        )

    def _load_service_account_info(self) -> dict[str, Any]:
        if self.config.fcm_service_account_json:
            return self.validate_service_account_json(self.config.fcm_service_account_json)

        if self.config.fcm_service_account_file:
            if not self.config.fcm_service_account_file.exists():
                raise RuntimeError("Het geconfigureerde Firebase service-account bestand bestaat niet.")
            return self.validate_service_account_json(
                self.config.fcm_service_account_file.read_text(encoding="utf-8")
            )

        if self.config.managed_fcm_service_account_file.exists():
            encrypted_payload = self.config.managed_fcm_service_account_file.read_text(encoding="utf-8")
            try:
                raw_payload = Fernet(self._resolve_storage_key()).decrypt(
                    encrypted_payload.encode("utf-8")
                ).decode("utf-8")
            except InvalidToken as exc:
                raise RuntimeError("De opgeslagen Firebase-sleutel kon niet worden ontsleuteld.") from exc
            return self.validate_service_account_json(raw_payload)

        raise RuntimeError("Er is nog geen Firebase service-account bron geconfigureerd.")

    def _diagnostic_service_account_path(self) -> str:
        if self.config.fcm_service_account_json:
            return ""
        if self.config.fcm_service_account_file:
            return str(self.config.fcm_service_account_file)
        return str(self.config.managed_fcm_service_account_file)

    def _service_account_source(self) -> str:
        if self.config.fcm_service_account_json:
            return "inline_json"
        if self.config.fcm_service_account_file is not None:
            return "configured_file"
        if self.config.managed_fcm_service_account_file.exists():
            return "uploaded_file"
        return "none"

    def _resolve_storage_key(self) -> bytes:
        if self.config.storage_key:
            return self.config.storage_key.encode("utf-8")
        if self.config.secret_key_file.exists():
            return self.config.secret_key_file.read_bytes().strip()
        raise RuntimeError("De opslagcode voor de Firebase-sleutel ontbreekt.")


class NoopPushClient:
    def is_configured(self) -> bool:
        return False

    async def send_listen_sms(
        self,
        device: DeviceRegistration,
        challenge_id: str,
        timeout_seconds: int,
    ) -> None:
        raise RuntimeError("Firebase Cloud Messaging is not configured.")

    async def send_auth_result(
        self,
        device: DeviceRegistration,
        success: bool,
        message: str,
    ) -> None:
        log.info("Skipping auth notification because Firebase Cloud Messaging is not configured.")


class PlaywrightAutomationClient:
    USERNAME_SELECTORS = (
        'input[name="username"]',
        'input[type="email"]',
        'input[autocomplete="username"]',
    )
    PASSWORD_SELECTORS = (
        'input[name="password"]',
        'input[type="password"]',
        'input[autocomplete="current-password"]',
    )
    OTP_SELECTORS = (
        'input[name="code"]',
        'input[name="otp"]',
        'input[name="token"]',
        'input[autocomplete="one-time-code"]',
    )
    SUBMIT_SELECTORS = (
        'button[type="submit"]',
        'button:has-text("Inloggen")',
        'button:has-text("Login")',
        'input[type="submit"]',
    )

    async def authenticate_and_scrape(
        self,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        session_checkpoint: dict[str, Any] | None = None,
        prepare_sms_relay: SmsRelayPrimer | None = None,
        wait_for_sms_code: SmsCodeAwaiter | None = None,
    ) -> AuthenticationResult:
        del report_progress, session_checkpoint, prepare_sms_relay, wait_for_sms_code
        debug_notes: list[str] = []
        login_url = credentials.login_url or config.default_login_url

        # The login flow stays selector-based so the backend can be adapted without changing the Android app.
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=config.playwright_headless)
            page = await browser.new_page()
            try:
                await page.goto(login_url, wait_until="domcontentloaded")
                debug_notes.append(f"Opened login page {page.url}.")

                await self._fill_first(page, self.USERNAME_SELECTORS, credentials.username)
                await self._fill_first(page, self.PASSWORD_SELECTORS, credentials.password)
                await self._click_submit(page)

                requires_sms = await self._wait_for_sms_or_success(page, login_url, config.login_timeout_seconds)
                if requires_sms:
                    debug_notes.append("An SMS challenge was detected after the first login submit.")
                    sms_code = await request_sms_code()
                    await self._fill_first(page, self.OTP_SELECTORS, sms_code)
                    await self._click_submit(page)
                else:
                    debug_notes.append("No SMS challenge was detected after the first login submit.")

                if not await self._wait_for_ready_state(page, login_url, config.login_timeout_seconds):
                    body_text = await page.locator("body").inner_text()
                    snippet = " ".join(body_text.split())[:240]
                    html = await page.content()
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                    raise RuntimeError(
                        "The backend could not confirm a successful ONS login. "
                        f"Last page snippet: {snippet}"
                    )

                target_url = config.roster_url or config.post_login_url
                if target_url:
                    await page.goto(target_url, wait_until="networkidle")
                    debug_notes.append(f"Navigated to the configured post-login page {page.url}.")

                # The last authenticated page is persisted for the HTTPS debug endpoint.
                html = await page.content()
                await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                page_title = await page.title()
                roster_items, extraction_notes = self._extract_roster_items(html)
                debug_notes.extend(extraction_notes)
                debug_notes.append(f"Detected {len(roster_items)} roster-like entries on the last page.")

                return AuthenticationResult(
                    final_url=page.url,
                    page_title=page_title,
                    roster_items=roster_items,
                    debug_notes=debug_notes,
                    auth_ready=True,
                )
            finally:
                await browser.close()

    async def _fill_first(self, page, selectors: tuple[str, ...], value: str) -> None:
        for selector in selectors:
            locator = page.locator(selector).first
            try:
                await locator.wait_for(state="visible", timeout=1_500)
                await locator.fill(value)
                return
            except PlaywrightTimeoutError:
                continue
        raise RuntimeError(f"No matching selector was found for {selectors!r}.")

    async def _click_submit(self, page) -> None:
        for selector in self.SUBMIT_SELECTORS:
            locator = page.locator(selector).first
            try:
                await locator.wait_for(state="visible", timeout=1_500)
                await locator.click()
                return
            except PlaywrightTimeoutError:
                continue
        raise RuntimeError("No submit button could be found on the login page.")

    async def _wait_for_sms_or_success(self, page, login_url: str, timeout_seconds: int) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            if await self._has_visible_selector(page, self.OTP_SELECTORS):
                return True
            if await self._looks_logged_in(page, login_url):
                return False
            await page.wait_for_timeout(400)
        if await self._has_visible_selector(page, self.OTP_SELECTORS):
            return True
        if await self._looks_logged_in(page, login_url):
            return False
        raise RuntimeError("The ONS login page did not expose a challenge or a success state in time.")

    async def _wait_for_ready_state(self, page, login_url: str, timeout_seconds: int) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            if await self._looks_logged_in(page, login_url):
                return True
            await page.wait_for_timeout(400)
        return await self._looks_logged_in(page, login_url)

    async def _looks_logged_in(self, page, login_url: str) -> bool:
        if await self._has_visible_selector(page, self.USERNAME_SELECTORS):
            return False
        if await self._has_visible_selector(page, self.PASSWORD_SELECTORS):
            return False
        if await self._has_visible_selector(page, self.OTP_SELECTORS):
            return False
        return page.url.rstrip("/") != login_url.rstrip("/") or bool((await page.title()).strip())

    async def _has_visible_selector(self, page, selectors: tuple[str, ...]) -> bool:
        for selector in selectors:
            locator = page.locator(selector).first
            try:
                return await locator.is_visible(timeout=250)
            except Exception:
                continue
        return False

    def _extract_roster_items(self, html: str) -> tuple[list[RosterItem], list[str]]:
        notes: list[str] = []
        soup = BeautifulSoup(html, "html.parser")
        time_pattern = re.compile(r"\b\d{1,2}:\d{2}\b")
        date_pattern = re.compile(r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b")
        items: list[RosterItem] = []
        seen: set[tuple[str, str, str, str]] = set()

        # The fallback scraper deliberately looks for generic date and time patterns until real selectors are known.
        for element in soup.select("tr, li, article, section, div"):
            text = " ".join(fragment.strip() for fragment in element.stripped_strings)
            if len(text) < 12:
                continue

            times = time_pattern.findall(text)
            if not times:
                continue

            date_match = date_pattern.search(text)
            candidate = RosterItem(
                date=date_match.group(0) if date_match else "",
                start=times[0],
                end=times[1] if len(times) > 1 else "",
                description=text[:200],
                raw={"text": text[:500]},
            )
            identity = (candidate.date, candidate.start, candidate.end, candidate.description)
            if identity in seen:
                continue
            seen.add(identity)
            items.append(candidate)
            if len(items) >= 100:
                break

        if not items:
            notes.append("No roster-like rows were detected with the fallback HTML heuristics.")

        return items, notes


class HttpLoginAutomationClient(PlaywrightAutomationClient):
    LOGIN_ERROR_MARKERS = (
        "gebruikersnaam/wachtwoord combinatie is onjuist",
        "username/password combination you entered is not correct",
        "didn't enter a username or password",
        "geen wachtwoord of gebruikersnaam hebt ingevuld",
        "verify_credentials_error",
        "incorrect_credentials",
        "sso_required_error",
    )
    LOGIN_ERROR_CODE_MESSAGES = {
        "incorrect_credentials": "De ONS-site meldt dat de gebruikersnaam of het wachtwoord onjuist is.",
        "verify_credentials_error": "De ONS-site heeft de ingevoerde gebruikersnaam of het wachtwoord afgekeurd.",
        "sso_required_error": "De ONS-site vereist aanmelden via de aangeboden SSO-provider.",
    }
    MICROSOFT_USERNAME_SELECTORS = (
        'input[name="loginfmt"]',
        'input[type="email"]',
        'input[autocomplete="username"]',
    )
    MICROSOFT_PASSWORD_SELECTORS = (
        'input[name="passwd"]',
        'input[type="password"]',
        'input[autocomplete="current-password"]',
    )
    MICROSOFT_PRIMARY_BUTTON_SELECTORS = (
        '#idSIButton9',
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Volgende")',
        'button:has-text("Next")',
        'button:has-text("Aanmelden")',
        'button:has-text("Sign in")',
        'button:has-text("Inloggen")',
        'button:has-text("Login")',
    )
    MICROSOFT_DECLINE_BUTTON_SELECTORS = (
        '#idBtn_Back',
        'button:has-text("Nee")',
        'button:has-text("No")',
    )
    MICROSOFT_OTP_SELECTORS = (
        '#idTxtBx_SAOTCC_OTC',
        'input[name="otc"]',
        'input[name="code"]',
        'input[name="otp"]',
        'input[autocomplete="one-time-code"]',
        'input[inputmode="numeric"]',
    )
    MICROSOFT_OTP_SUBMIT_SELECTORS = (
        '#idSubmit_SAOTCC_Continue',
        '#idSIButton9',
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Verify")',
        'button:has-text("Verifiëren")',
        'button:has-text("Continue")',
        'button:has-text("Doorgaan")',
        'button:has-text("Volgende")',
    )
    MICROSOFT_PROOF_SELECTION_SELECTORS = (
        '#idDiv_SAOTCS_Title',
        '[data-value="OneWaySMS"]',
        '[data-value="TwoWaySMS"]',
        'div:has-text("Bevestig uw identiteit")',
        'div:has-text("Confirm your identity")',
    )
    SSO_REQUIRED_ERROR_CODE = "sso_required_error"
    SSO_PROVIDER_TITLE_MARKERS = ("microsoft", "entra", "azure", "office")

    async def authenticate_and_scrape(
        self,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        session_checkpoint: dict[str, Any] | None = None,
        prepare_sms_relay: SmsRelayPrimer | None = None,
        wait_for_sms_code: SmsCodeAwaiter | None = None,
    ) -> AuthenticationResult:
        loop = asyncio.get_running_loop()

        def sync_progress(event: dict[str, Any]) -> None:
            if report_progress is None:
                return
            future = asyncio.run_coroutine_threadsafe(report_progress(event), loop)
            future.result(timeout=max(config.login_timeout_seconds, 5))

        return await asyncio.to_thread(
            self._authenticate_sync,
            credentials,
            request_sms_code,
            snapshot_path,
            config,
            sync_progress,
            session_checkpoint,
            prepare_sms_relay,
            wait_for_sms_code,
        )

    def _authenticate_sync(
        self,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], None] | None,
        session_checkpoint: dict[str, Any] | None,
        prepare_sms_relay: SmsRelayPrimer | None,
        wait_for_sms_code: SmsCodeAwaiter | None,
    ) -> AuthenticationResult:
        debug_notes: list[str] = []
        login_url = credentials.login_url or config.default_login_url
        trace_index = 1

        if session_checkpoint is not None:
            debug_notes.append("Continuing from the stored authentication session.")
            return asyncio.run(
                self._continue_from_session_checkpoint(
                    credentials=credentials,
                    request_sms_code=request_sms_code,
                    snapshot_path=snapshot_path,
                    config=config,
                    report_progress=report_progress,
                    trace_index=trace_index,
                    debug_notes=debug_notes,
                    session_checkpoint=session_checkpoint,
                    prepare_sms_relay=prepare_sms_relay,
                    wait_for_sms_code=wait_for_sms_code,
                )
            )

        with requests.Session() as session:
            session.headers.update(
                {
                    "User-Agent": "ons-rooster-backend/0.1",
                    "Accept-Language": "nl-NL,nl;q=0.9,en;q=0.8",
                }
            )

            login_response = session.get(
                login_url,
                allow_redirects=True,
                timeout=config.login_timeout_seconds,
            )
            login_response.raise_for_status()
            debug_notes.append(f"Opened login page {login_response.url}.")
            trace_index = self._record_response_step(
                report_progress,
                config=config,
                snapshot_path=snapshot_path,
                trace_index=trace_index,
                label="Open login page",
                message=f"De backend heeft de inlogpagina geopend op {login_response.url}.",
                phase="login_opened",
                response=login_response,
            )

            login_form = self._extract_login_form(login_response.url, login_response.text)
            sso_providers = self._extract_sso_providers(login_response.url, login_response.text)
            preferred_sso_provider, sso_reason = self._select_sso_provider(
                credentials.username,
                sso_providers,
                login_form,
            )
            if preferred_sso_provider is not None:
                provider_label = self._sso_provider_label(preferred_sso_provider)
                debug_notes.append(
                    f"Selected SSO provider {provider_label} ({sso_reason}) from {login_response.url}."
                )
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Select SSO provider",
                    message=f"De backend heeft {provider_label} geselecteerd voor de SSO-flow.",
                    phase="sso_selected",
                    url=login_response.url,
                    page_title=self._extract_page_title(login_response.text),
                    snapshot_name=self._write_trace_snapshot(
                        config.auth_trace_dir,
                        trace_index,
                        "sso-provider-selection",
                        login_response.text,
                    ),
                    status_code=login_response.status_code,
                )
                trace_index += 1
                return asyncio.run(
                    self._authenticate_with_sso_playwright(
                        credentials=credentials,
                        login_url=login_url,
                        sso_provider=preferred_sso_provider,
                        snapshot_path=snapshot_path,
                        config=config,
                        report_progress=report_progress,
                        trace_index=trace_index,
                        debug_notes=debug_notes,
                    )
                )

            csrf_token = self._resolve_csrf_token(
                session,
                login_response,
                config.login_timeout_seconds,
                debug_notes,
            )
            if csrf_token:
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Resolve CSRF",
                    message="De backend heeft een CSRF-token voor de eerste loginstap opgehaald.",
                    phase="csrf_resolved",
                    url=login_response.url,
                )
                trace_index += 1
            submit_url = (
                login_form["action_url"]
                if login_form is not None
                else urljoin(login_response.url, "/verify_credentials")
            )
            submit_payload = dict(login_form["hidden_fields"]) if login_form is not None else {}
            submit_payload["_utf8"] = submit_payload.get("_utf8", "✓")
            submit_payload["username"] = credentials.username
            submit_payload["password"] = credentials.password
            if csrf_token:
                submit_payload["_csrf_token"] = csrf_token
            self._record_event(
                report_progress,
                trace_index=trace_index,
                label="Submit credentials",
                message=f"De backend heeft de credential-POST voorbereid voor {submit_url}.",
                phase="credentials_submitted",
                url=submit_url,
            )
            trace_index += 1

            submit_response = session.post(
                submit_url,
                data=submit_payload,
                headers={
                    "Origin": self._origin_for(submit_url),
                    "Referer": login_response.url,
                },
                allow_redirects=True,
                timeout=config.login_timeout_seconds,
            )
            debug_notes.extend(self._redirect_notes(submit_response.history))
            debug_notes.append(f"Submitted credentials and landed on {submit_response.url}.")
            trace_index = self._record_response_step(
                report_progress,
                config=config,
                snapshot_path=snapshot_path,
                trace_index=trace_index,
                label="Credential response",
                message=f"De backend heeft de antwoordpagina na credential-submit ontvangen op {submit_response.url}.",
                phase="credential_response",
                response=submit_response,
            )

            html = submit_response.text
            page_title = self._extract_page_title(html)

            challenge = self._extract_otp_checkpoint(submit_response.url, html)
            if challenge is not None:
                snapshot_path.write_text(html, encoding="utf-8")
                debug_notes.append(
                    f"OTP challenge detected at {challenge['action_url']}."
                )
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="OTP challenge detected",
                    message=f"De backend heeft een OTP-pagina gevonden op {challenge['action_url']}.",
                    phase="otp_detected",
                    url=submit_response.url,
                    page_title=page_title,
                )
                return AuthenticationResult(
                    final_url=submit_response.url,
                    page_title=page_title,
                    roster_items=[],
                    debug_notes=debug_notes,
                    auth_ready=False,
                    session_checkpoint=self._build_session_checkpoint(
                        session=session,
                        login_url=login_url,
                        current_url=submit_response.url,
                        page_title=page_title,
                        challenge=challenge,
                    ),
                )

            login_error_code = self._extract_login_error_code(html)
            if login_error_code == self.SSO_REQUIRED_ERROR_CODE:
                fallback_sso_provider, fallback_reason = self._select_sso_provider(
                    credentials.username,
                    sso_providers,
                    login_form,
                    force=True,
                )
                if fallback_sso_provider is not None:
                    provider_label = self._sso_provider_label(fallback_sso_provider)
                    snapshot_path.write_text(html, encoding="utf-8")
                    debug_notes.append(
                        f"Native login returned {self.SSO_REQUIRED_ERROR_CODE}; switching to {provider_label} ({fallback_reason})."
                    )
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="Switch to SSO",
                        message=(
                            f"De backend schakelt over op {provider_label} nadat de ONS-site aangaf dat SSO verplicht is."
                        ),
                        phase="sso_selected",
                        url=submit_response.url,
                        page_title=page_title,
                        snapshot_name=self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "sso-required",
                            html,
                        ),
                        status_code=submit_response.status_code,
                    )
                    trace_index += 1
                    return asyncio.run(
                        self._authenticate_with_sso_playwright(
                            credentials=credentials,
                            login_url=login_url,
                            sso_provider=fallback_sso_provider,
                            snapshot_path=snapshot_path,
                            config=config,
                            report_progress=report_progress,
                            trace_index=trace_index,
                            debug_notes=debug_notes,
                        )
                    )

            login_error = self._extract_login_error(submit_response, html)
            if login_error:
                snapshot_path.write_text(html, encoding="utf-8")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Login error",
                    message=login_error,
                    phase="login_error",
                    url=submit_response.url,
                    page_title=page_title,
                    snapshot_name=self._write_trace_snapshot(config.auth_trace_dir, trace_index, "login-error", html),
                    status_code=submit_response.status_code,
                )
                raise RuntimeError(login_error)

            if self._response_still_looks_like_login(submit_response.url, html, login_url):
                snapshot_path.write_text(html, encoding="utf-8")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Login still pending",
                    message="De backend kwam terug op een pagina die nog steeds op de loginflow lijkt.",
                    phase="login_unconfirmed",
                    url=submit_response.url,
                    page_title=page_title,
                    snapshot_name=self._write_trace_snapshot(config.auth_trace_dir, trace_index, "login-unconfirmed", html),
                    status_code=submit_response.status_code,
                )
                raise RuntimeError(
                    "De backend kon niet bevestigen dat de ingevoerde ONS-gegevens zijn geaccepteerd. "
                    f"Laatste pagina: {self._text_snippet(html)}"
                )

            page_response = submit_response
            target_url = config.roster_url or config.post_login_url
            if target_url:
                resolved_target_url = urljoin(page_response.url, target_url)
                page_response = session.get(
                    resolved_target_url,
                    allow_redirects=True,
                    timeout=config.login_timeout_seconds,
                )
                page_response.raise_for_status()
                html = page_response.text
                page_title = self._extract_page_title(html)
                debug_notes.extend(self._redirect_notes(page_response.history))
                debug_notes.append(
                    f"Navigated to the configured post-login page {page_response.url}."
                )
                trace_index = self._record_response_step(
                    report_progress,
                    config=config,
                    snapshot_path=snapshot_path,
                    trace_index=trace_index,
                    label="Post-login navigation",
                    message=f"De backend heeft de ingestelde post-login pagina geopend op {page_response.url}.",
                    phase="post_login_page",
                    response=page_response,
                )

            snapshot_path.write_text(html, encoding="utf-8")
            roster_items, extraction_notes = self._extract_roster_items(html)
            debug_notes.extend(extraction_notes)
            debug_notes.append(
                f"Detected {len(roster_items)} roster-like entries on the last page."
            )
            self._record_event(
                report_progress,
                trace_index=trace_index,
                label="Authentication ready",
                message=f"De backend heeft de loginflow afgerond en {len(roster_items)} roosterregels gedetecteerd.",
                phase="ready",
                url=page_response.url,
                page_title=page_title,
            )

            return AuthenticationResult(
                final_url=page_response.url,
                page_title=page_title,
                roster_items=roster_items,
                debug_notes=debug_notes,
                auth_ready=True,
            )

    async def _authenticate_with_sso_playwright(
        self,
        *,
        credentials: LoginCredentials,
        login_url: str,
        sso_provider: dict[str, Any],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], None] | None,
        trace_index: int,
        debug_notes: list[str],
    ) -> AuthenticationResult:
        provider_label = self._sso_provider_label(sso_provider)
        provider_url = str(sso_provider.get("jump_url", "")).strip() or login_url

        async with async_playwright() as playwright:
            browser = None
            page = None
            try:
                browser = await playwright.chromium.launch(headless=config.playwright_headless)
                context = await browser.new_context(locale="nl-NL")
                page = await context.new_page()
                await page.goto(provider_url, wait_until="domcontentloaded")
                debug_notes.append(f"Opened SSO provider {provider_label} on {page.url}.")
                trace_index = await self._record_playwright_page_step(
                    report_progress,
                    config=config,
                    snapshot_path=snapshot_path,
                    trace_index=trace_index,
                    label="Open SSO provider",
                    message=f"De backend heeft de {provider_label} SSO-provider geopend op {page.url}.",
                    phase="sso_opened",
                    page=page,
                )

                await self._fill_first_visible(
                    page,
                    self.MICROSOFT_USERNAME_SELECTORS,
                    credentials.username,
                    config.login_timeout_seconds,
                )
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Submit SSO username",
                    message="De backend heeft de Microsoft gebruikersnaam ingevoerd.",
                    phase="sso_username_submitted",
                    url=page.url,
                )
                trace_index += 1
                await self._click_first_visible(
                    page,
                    self.MICROSOFT_PRIMARY_BUTTON_SELECTORS,
                    config.login_timeout_seconds,
                )

                await self._fill_first_visible(
                    page,
                    self.MICROSOFT_PASSWORD_SELECTORS,
                    credentials.password,
                    config.login_timeout_seconds,
                )
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Submit SSO password",
                    message="De backend heeft het Microsoft wachtwoord ingevoerd.",
                    phase="sso_password_submitted",
                    url=page.url,
                )
                trace_index += 1
                await self._click_first_visible(
                    page,
                    self.MICROSOFT_PRIMARY_BUTTON_SELECTORS,
                    config.login_timeout_seconds,
                )

                if await self._maybe_dismiss_stay_signed_in_prompt(page, min(config.login_timeout_seconds, 6)):
                    debug_notes.append("Dismissed the Microsoft 'stay signed in' prompt.")
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="Dismiss keep-signed-in prompt",
                        message="De backend heeft de Microsoft prompt om aangemeld te blijven afgewezen.",
                        phase="sso_prompt_handled",
                        url=page.url,
                    )
                    trace_index += 1

                await self._wait_for_sso_destination(page, config.login_timeout_seconds)

                html = await page.content()
                page_title = await page.title()
                proof_selection = self._extract_microsoft_proof_selection(page.url, html)
                if proof_selection is not None:
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                    sms_proof = proof_selection.get("sms_proof")
                    sms_display = ""
                    if isinstance(sms_proof, dict):
                        sms_display = str(sms_proof.get("display", "")).strip()
                    debug_notes.append(
                        "Microsoft verification method selection detected"
                        f"{f' for {sms_display}' if sms_display else ''}; SMS not sent."
                    )
                    message = "De backend heeft de Microsoft verificatiekeuze bereikt; de SMS is nog niet verzonden."
                    if sms_display:
                        message = (
                            "De backend heeft de Microsoft verificatiekeuze bereikt en kan nu een SMS sturen naar "
                            f"{sms_display}, maar heeft dat nog niet gedaan."
                        )
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="MFA selection detected",
                        message=message,
                        phase="mfa_selection_detected",
                        url=page.url,
                        page_title=page_title,
                        snapshot_name=self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "mfa-selection-after-sso",
                            html,
                        ),
                    )
                    return AuthenticationResult(
                        final_url=page.url,
                        page_title=page_title,
                        roster_items=[],
                        debug_notes=debug_notes,
                        auth_ready=False,
                        session_checkpoint=self._build_browser_session_checkpoint(
                            cookies=await context.cookies(),
                            login_url=login_url,
                            current_url=page.url,
                            page_title=page_title,
                            challenge=proof_selection,
                        ),
                    )

                challenge = self._extract_otp_checkpoint(page.url, html)
                if challenge is not None:
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                    debug_notes.append(f"OTP challenge detected after SSO at {challenge['action_url']}.")
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="OTP challenge detected",
                        message=f"De backend heeft na de SSO-flow een OTP-pagina gevonden op {challenge['action_url']}.",
                        phase="otp_detected",
                        url=page.url,
                        page_title=page_title,
                        snapshot_name=self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "otp-after-sso",
                            html,
                        ),
                    )
                    return AuthenticationResult(
                        final_url=page.url,
                        page_title=page_title,
                        roster_items=[],
                        debug_notes=debug_notes,
                        auth_ready=False,
                        session_checkpoint=self._build_browser_session_checkpoint(
                            cookies=await context.cookies(),
                            login_url=login_url,
                            current_url=page.url,
                            page_title=page_title,
                            challenge=challenge,
                        ),
                    )

                login_error = self._extract_login_error(self._synthetic_response(200), html)
                if login_error:
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="SSO login error",
                        message=login_error,
                        phase="login_error",
                        url=page.url,
                        page_title=page_title,
                        snapshot_name=self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "sso-login-error",
                            html,
                        ),
                    )
                    raise RuntimeError(login_error)

                if self._response_still_looks_like_login(page.url, html, login_url):
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                    self._record_event(
                        report_progress,
                        trace_index=trace_index,
                        label="SSO still pending",
                        message="De backend kwam na de SSO-flow terug op een pagina die nog steeds op de loginflow lijkt.",
                        phase="login_unconfirmed",
                        url=page.url,
                        page_title=page_title,
                        snapshot_name=self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "sso-login-unconfirmed",
                            html,
                        ),
                    )
                    raise RuntimeError(
                        "De backend kon niet bevestigen dat de Microsoft SSO-aanmelding is geaccepteerd. "
                        f"Laatste pagina: {self._text_snippet(html)}"
                    )

                target_url = config.roster_url or config.post_login_url
                if target_url:
                    resolved_target_url = urljoin(page.url, target_url)
                    await page.goto(resolved_target_url, wait_until="networkidle")
                    debug_notes.append(f"Navigated to the configured post-login page {page.url}.")
                    trace_index = await self._record_playwright_page_step(
                        report_progress,
                        config=config,
                        snapshot_path=snapshot_path,
                        trace_index=trace_index,
                        label="Post-login navigation",
                        message=f"De backend heeft de ingestelde post-login pagina geopend op {page.url}.",
                        phase="post_login_page",
                        page=page,
                    )

                html = await page.content()
                page_title = await page.title()
                await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                roster_items, extraction_notes = self._extract_roster_items(html)
                debug_notes.extend(extraction_notes)
                debug_notes.append(f"Detected {len(roster_items)} roster-like entries on the last page.")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Authentication ready",
                    message=f"De backend heeft de SSO-flow afgerond en {len(roster_items)} roosterregels gedetecteerd.",
                    phase="ready",
                    url=page.url,
                    page_title=page_title,
                )

                return AuthenticationResult(
                    final_url=page.url,
                    page_title=page_title,
                    roster_items=roster_items,
                    debug_notes=debug_notes,
                    auth_ready=True,
                )
            except RuntimeError:
                raise
            except Exception as exc:
                html = ""
                page_title = ""
                current_url = provider_url
                if page is not None:
                    html = await page.content()
                    page_title = await page.title()
                    current_url = page.url
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="SSO automation error",
                    message="De backend kon de Microsoft SSO-flow niet afronden.",
                    phase="sso_error",
                    url=current_url,
                    page_title=page_title,
                    snapshot_name=(
                        self._write_trace_snapshot(
                            config.auth_trace_dir,
                            trace_index,
                            "sso-automation-error",
                            html,
                        )
                        if html
                        else ""
                    ),
                )
                raise RuntimeError(
                    "De backend kon de Microsoft SSO-flow niet afronden. "
                    f"Laatste pagina: {self._text_snippet(html) if html else str(exc)}"
                ) from exc
            finally:
                if browser is not None:
                    await browser.close()

    async def _continue_from_session_checkpoint(
        self,
        *,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], None] | None,
        trace_index: int,
        debug_notes: list[str],
        session_checkpoint: dict[str, Any],
        prepare_sms_relay: SmsRelayPrimer | None,
        wait_for_sms_code: SmsCodeAwaiter | None,
    ) -> AuthenticationResult:
        challenge = session_checkpoint.get("challenge", {})
        if not isinstance(challenge, dict):
            raise RuntimeError("De opgeslagen authenticatiesessie bevat geen geldige vervolgstap.")

        challenge_kind = str(challenge.get("challenge_kind", "")).strip().lower()
        if challenge_kind == "microsoft_proof_selection":
            return await self._continue_from_microsoft_proof_selection(
                credentials=credentials,
                request_sms_code=request_sms_code,
                snapshot_path=snapshot_path,
                config=config,
                report_progress=report_progress,
                trace_index=trace_index,
                debug_notes=debug_notes,
                session_checkpoint=session_checkpoint,
                prepare_sms_relay=prepare_sms_relay,
                wait_for_sms_code=wait_for_sms_code,
            )

        raise RuntimeError(
            "De backend kan de opgeslagen authenticatiesessie nog niet automatisch hervatten voor "
            f"{challenge_kind or 'deze stap'}."
        )

    async def _continue_from_microsoft_proof_selection(
        self,
        *,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], None] | None,
        trace_index: int,
        debug_notes: list[str],
        session_checkpoint: dict[str, Any],
        prepare_sms_relay: SmsRelayPrimer | None,
        wait_for_sms_code: SmsCodeAwaiter | None,
    ) -> AuthenticationResult:
        challenge = session_checkpoint.get("challenge", {})
        if not isinstance(challenge, dict):
            raise RuntimeError("De opgeslagen Microsoft-sessie bevat geen geldige verificatiekeuze.")

        login_url = credentials.login_url or config.default_login_url
        current_url = str(session_checkpoint.get("current_url", "")).strip() or login_url
        stored_cookies = session_checkpoint.get("cookies", [])
        sms_relay_task: asyncio.Task[str] | None = None
        sms_challenge_id = ""

        async with async_playwright() as playwright:
            browser = None
            page = None
            try:
                browser = await playwright.chromium.launch(headless=config.playwright_headless)
                context = await browser.new_context(locale="nl-NL")
                if isinstance(stored_cookies, list) and stored_cookies:
                    await context.add_cookies(self._playwright_cookies(stored_cookies))
                page = await context.new_page()
                await page.goto(current_url, wait_until="domcontentloaded")
                debug_notes.append(f"Resumed the stored Microsoft verification page on {page.url}.")
                trace_index = await self._record_playwright_page_step(
                    report_progress,
                    config=config,
                    snapshot_path=snapshot_path,
                    trace_index=trace_index,
                    label="Resume SSO session",
                    message="De backend heeft de opgeslagen Microsoft verificatiepagina opnieuw geopend.",
                    phase="sso_resumed",
                    page=page,
                )

                html = await page.content()
                proof_selection = self._extract_microsoft_proof_selection(page.url, html)
                if proof_selection is None:
                    raise RuntimeError(
                        "De opgeslagen Microsoft verificatiepagina kon niet opnieuw worden geladen. "
                        f"Laatste pagina: {self._text_snippet(html)}"
                    )

                if prepare_sms_relay is not None and wait_for_sms_code is not None:
                    sms_challenge_id = await prepare_sms_relay()
                else:
                    sms_relay_task = asyncio.create_task(request_sms_code())
                    await asyncio.sleep(0)
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Arm SMS relay",
                    message="De backend heeft de Android-app eerst klaar gezet om de komende OTP-SMS op te vangen.",
                    phase="sms_relay_armed",
                    url=page.url,
                    page_title=await page.title(),
                )
                trace_index += 1

                await self._click_microsoft_sms_proof(
                    page,
                    proof_selection=proof_selection,
                    timeout_seconds=config.login_timeout_seconds,
                )
                debug_notes.append("Requested the Microsoft SMS verification code after arming the Android relay.")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Request SMS code",
                    message="De backend heeft nu de Microsoft optie gekozen om de OTP-SMS te verzenden.",
                    phase="sms_requested",
                    url=page.url,
                    page_title=await page.title(),
                )
                trace_index += 1

                await self._wait_for_microsoft_otp_page(page, config.login_timeout_seconds)
                trace_index = await self._record_playwright_page_step(
                    report_progress,
                    config=config,
                    snapshot_path=snapshot_path,
                    trace_index=trace_index,
                    label="OTP entry page",
                    message="De backend heeft de Microsoft OTP-invoerpagina bereikt en wacht op de code van Android.",
                    phase="otp_page_opened",
                    page=page,
                )

                if sms_relay_task is not None:
                    sms_code = await sms_relay_task
                elif wait_for_sms_code is not None and sms_challenge_id:
                    sms_code = await wait_for_sms_code(sms_challenge_id)
                else:
                    sms_code = await request_sms_code()
                debug_notes.append("Received the SMS OTP from the Android relay.")

                await self._fill_first_visible(
                    page,
                    self.MICROSOFT_OTP_SELECTORS,
                    sms_code,
                    config.login_timeout_seconds,
                )
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Submit OTP code",
                    message="De backend heeft de door Android teruggestuurde OTP-code ingevoerd.",
                    phase="otp_submitted",
                    url=page.url,
                    page_title=await page.title(),
                )
                trace_index += 1
                await self._click_first_visible(
                    page,
                    self.MICROSOFT_OTP_SUBMIT_SELECTORS,
                    config.login_timeout_seconds,
                )

                await self._wait_for_post_otp_page(page, config.login_timeout_seconds)
                html = await page.content()
                page_title = await page.title()
                page_summary = self._text_snippet(html)
                await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                debug_notes.append(f"Submitted the SMS OTP and reached {page.url}.")
                self._record_event(
                    report_progress,
                    trace_index=trace_index,
                    label="Post-OTP page detected",
                    message=f"De backend heeft de eerste pagina na OTP-submit bereikt op {page.url}.",
                    phase="post_otp_page_detected",
                    url=page.url,
                    page_title=page_title,
                    snapshot_name=self._write_trace_snapshot(
                        config.auth_trace_dir,
                        trace_index,
                        "post-otp-page",
                        html,
                    ),
                )

                return AuthenticationResult(
                    final_url=page.url,
                    page_title=page_title,
                    roster_items=[],
                    debug_notes=debug_notes,
                    auth_ready=False,
                    session_checkpoint=self._build_browser_session_checkpoint(
                        cookies=await context.cookies(),
                        login_url=login_url,
                        current_url=page.url,
                        page_title=page_title,
                        challenge={
                            "challenge_kind": "post_otp_result_page",
                            "page_summary": page_summary,
                            "source": "microsoft_sso",
                        },
                    ),
                )
            except RuntimeError:
                raise
            except Exception as exc:
                html = ""
                page_title = ""
                page_url = current_url
                if page is not None:
                    html = await page.content()
                    page_title = await page.title()
                    page_url = page.url
                    await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
                raise RuntimeError(
                    "De backend kon de Microsoft SSO-vervolgstap niet afronden. "
                    f"Laatste pagina: {self._text_snippet(html) if html else str(exc)}"
                ) from exc
            finally:
                if browser is not None:
                    await browser.close()

    @staticmethod
    def _playwright_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for cookie in cookies:
            normalized_cookie = {
                "name": str(cookie.get("name", "")),
                "value": str(cookie.get("value", "")),
                "domain": str(cookie.get("domain", "")),
                "path": str(cookie.get("path", "/")),
                "secure": bool(cookie.get("secure", False)),
            }
            expires = cookie.get("expires")
            if expires not in {None, -1, ""}:
                normalized_cookie["expires"] = expires
            normalized.append(normalized_cookie)
        return normalized

    async def _click_microsoft_sms_proof(
        self,
        page,
        *,
        proof_selection: dict[str, Any],
        timeout_seconds: int,
    ) -> None:
        selectors: list[str] = []
        sms_value = str(proof_selection.get("sms_proof_value", "")).strip()
        if sms_value:
            selectors.extend(
                [
                    f'[data-value="{sms_value}"]',
                    f'[role="button"][data-value="{sms_value}"]',
                    f'div[data-value="{sms_value}"]',
                ]
            )
        selectors.extend(
            [
                'div:has-text("Sms verzenden naar")',
                '[role="button"]:has-text("Sms verzenden naar")',
                'div:has-text("Text")',
            ]
        )
        await self._click_first_visible(page, tuple(selectors), timeout_seconds)

    async def _wait_for_microsoft_otp_page(self, page, timeout_seconds: int) -> None:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        otp_selectors = self.MICROSOFT_OTP_SELECTORS + self.OTP_SELECTORS
        while asyncio.get_running_loop().time() < deadline:
            if await self._has_visible_selector(page, otp_selectors):
                return
            html = await page.content()
            login_error = self._extract_login_error(self._synthetic_response(200), html)
            if login_error:
                raise RuntimeError(login_error)
            await page.wait_for_timeout(250)

        html = await page.content()
        raise RuntimeError(
            "De Microsoft pagina toonde geen OTP-invoerveld nadat de SMS-verzending was gestart. "
            f"Laatste pagina: {self._text_snippet(html)}"
        )

    async def _wait_for_post_otp_page(self, page, timeout_seconds: int) -> None:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        otp_selectors = self.MICROSOFT_OTP_SELECTORS + self.OTP_SELECTORS
        while asyncio.get_running_loop().time() < deadline:
            if not await self._has_visible_selector(page, otp_selectors):
                return
            await page.wait_for_timeout(250)

        html = await page.content()
        raise RuntimeError(
            "De backend bleef op de Microsoft OTP-invoerpagina staan nadat de code was ingestuurd. "
            f"Laatste pagina: {self._text_snippet(html)}"
        )

    async def _record_playwright_page_step(
        self,
        report_progress: Callable[[dict[str, Any]], None] | None,
        *,
        config: AppConfig,
        snapshot_path: Path,
        trace_index: int,
        label: str,
        message: str,
        phase: str,
        page,
    ) -> int:
        html = await page.content()
        await asyncio.to_thread(snapshot_path.write_text, html, encoding="utf-8")
        self._record_event(
            report_progress,
            trace_index=trace_index,
            label=label,
            message=message,
            phase=phase,
            url=page.url,
            page_title=await page.title(),
            snapshot_name=self._write_trace_snapshot(config.auth_trace_dir, trace_index, label, html),
        )
        return trace_index + 1

    async def _fill_first_visible(
        self,
        page,
        selectors: tuple[str, ...],
        value: str,
        timeout_seconds: int,
    ) -> None:
        locator = await self._wait_for_first_visible_locator(page, selectors, timeout_seconds)
        await locator.fill(value)

    async def _click_first_visible(
        self,
        page,
        selectors: tuple[str, ...],
        timeout_seconds: int,
    ) -> None:
        locator = await self._wait_for_first_visible_locator(page, selectors, timeout_seconds)
        await locator.click()

    async def _wait_for_first_visible_locator(self, page, selectors: tuple[str, ...], timeout_seconds: int):
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            for selector in selectors:
                locator = page.locator(selector).first
                try:
                    if await locator.is_visible(timeout=250):
                        return locator
                except Exception:
                    continue
            await page.wait_for_timeout(250)
        raise RuntimeError(f"No matching selector was found for {selectors!r}.")

    async def _maybe_dismiss_stay_signed_in_prompt(self, page, timeout_seconds: int) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            if not self._looks_like_external_sso_host(page.url):
                return False
            if await self._has_visible_selector(page, self.MICROSOFT_PROOF_SELECTION_SELECTORS):
                return False
            if await self._has_visible_selector(page, self.OTP_SELECTORS):
                return False
            for selector in self.MICROSOFT_DECLINE_BUTTON_SELECTORS:
                locator = page.locator(selector).first
                try:
                    if await locator.is_visible(timeout=250):
                        await locator.click()
                        await page.wait_for_timeout(250)
                        return True
                except Exception:
                    continue
            await page.wait_for_timeout(250)
        return False

    async def _wait_for_sso_destination(self, page, timeout_seconds: int) -> None:
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            if await self._has_visible_selector(page, self.OTP_SELECTORS):
                return
            if await self._has_visible_selector(page, self.MICROSOFT_PROOF_SELECTION_SELECTORS):
                return
            if not self._looks_like_external_sso_host(page.url):
                return
            await page.wait_for_timeout(250)

    @staticmethod
    def _looks_like_external_sso_host(url: str) -> bool:
        host = urlparse(url).netloc.lower()
        return any(
            marker in host
            for marker in ("microsoftonline.com", "login.live.com", "live.com")
        )

    def _build_browser_session_checkpoint(
        self,
        *,
        cookies: list[dict[str, Any]],
        login_url: str,
        current_url: str,
        page_title: str,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "saved_at": self._utc_timestamp(),
            "login_url": login_url,
            "current_url": current_url,
            "page_title": page_title,
            "challenge": challenge,
            "cookies": self._serialize_browser_cookies(cookies),
        }

    @staticmethod
    def _serialize_browser_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        serialized: list[dict[str, Any]] = []
        for cookie in cookies:
            expires = cookie.get("expires")
            serialized.append(
                {
                    "name": str(cookie.get("name", "")),
                    "value": str(cookie.get("value", "")),
                    "domain": str(cookie.get("domain", "")),
                    "path": str(cookie.get("path", "/")),
                    "secure": bool(cookie.get("secure", False)),
                    "expires": None if expires in {None, -1} else expires,
                }
            )
        return serialized

    @staticmethod
    def _synthetic_response(status_code: int) -> requests.Response:
        response = requests.Response()
        response.status_code = status_code
        return response

    def _extract_microsoft_proof_selection(self, current_url: str, html: str) -> dict[str, Any] | None:
        soup = BeautifulSoup(html, "html.parser")
        heading = ""
        heading_element = soup.select_one("#idDiv_SAOTCS_Title")
        if heading_element is not None:
            heading = " ".join(fragment.strip() for fragment in heading_element.stripped_strings)

        config = self._extract_script_assignment_object(html, "$Config")
        proofs: list[dict[str, Any]] = []
        raw_proofs = config.get("arrUserProofs") if config else None
        if isinstance(raw_proofs, list):
            for item in raw_proofs:
                if not isinstance(item, dict):
                    continue
                auth_method_id = str(item.get("authMethodId", "")).strip()
                data_value = str(item.get("data", "")).strip()
                display = str(item.get("display", "")).strip()
                if not (auth_method_id or data_value or display):
                    continue
                proofs.append(
                    {
                        "auth_method_id": auth_method_id,
                        "data": data_value,
                        "display": display,
                        "is_default": bool(item.get("isDefault", False)),
                        "is_location_aware": bool(item.get("isLocationAware", False)),
                        "phone_number_suffix": self._masked_phone_suffix(display),
                    }
                )

        if not proofs:
            for element in soup.select("[data-value]"):
                value = str(element.get("data-value", "")).strip()
                display = " ".join(fragment.strip() for fragment in element.stripped_strings)
                if not (value or display):
                    continue
                proofs.append(
                    {
                        "auth_method_id": value,
                        "data": value,
                        "display": display,
                        "is_default": False,
                        "is_location_aware": False,
                        "phone_number_suffix": self._masked_phone_suffix(display),
                    }
                )

        normalized_heading = heading.lower()
        looks_like_selection = bool(proofs) and (
            "bevestig uw identiteit" in normalized_heading
            or "confirm your identity" in normalized_heading
            or any(self._proof_looks_like_sms(proof) for proof in proofs)
        )
        if not looks_like_selection:
            return None

        form = soup.select_one("form")
        action_url = current_url
        method = "post"
        if form is not None:
            action = str(form.get("action", "")).strip()
            action_url = urljoin(current_url, action or current_url)
            method = str(form.get("method", "post")).strip().lower() or "post"
        elif config:
            action_url = str(config.get("urlPost", "")).strip() or current_url

        proof_input_name = str(config.get("sAuthMethodInputFieldName", "mfaAuthMethod")).strip() or "mfaAuthMethod"
        hidden_fields: dict[str, str] = {}
        flow_token_name = str(config.get("sFTName", "flowToken")).strip() or "flowToken"
        flow_token = str(config.get("sFT", "")).strip()
        if flow_token:
            hidden_fields[flow_token_name] = flow_token
        context_value = str(config.get("sCtx", "")).strip()
        if context_value:
            hidden_fields["ctx"] = context_value
        canary = str(config.get("canary", "")).strip()
        if canary:
            hidden_fields["canary"] = canary

        sms_proof = next((proof for proof in proofs if self._proof_looks_like_sms(proof)), None)
        sms_proof_value = ""
        if sms_proof is not None:
            sms_proof_value = str(sms_proof.get("data") or sms_proof.get("auth_method_id") or "").strip()

        return {
            "challenge_kind": "microsoft_proof_selection",
            "action_url": action_url,
            "method": method,
            "proof_input_name": proof_input_name,
            "sms_proof_value": sms_proof_value,
            "sms_proof": sms_proof or {},
            "proofs": proofs,
            "hidden_fields": hidden_fields,
        }

    @staticmethod
    def _proof_looks_like_sms(proof: dict[str, Any]) -> bool:
        combined = " ".join(
            [
                str(proof.get("auth_method_id", "")).lower(),
                str(proof.get("data", "")).lower(),
                str(proof.get("display", "")).lower(),
            ]
        )
        return any(marker in combined for marker in ("sms", "text", "verzenden"))

    @staticmethod
    def _masked_phone_suffix(display: str) -> str:
        digits = re.sub(r"\D", "", display)
        return digits[-2:] if len(digits) >= 2 else ""

    def _resolve_csrf_token(
        self,
        session: requests.Session,
        login_response: requests.Response,
        timeout_seconds: int,
        debug_notes: list[str],
    ) -> str:
        inline_token = self._extract_hidden_input(login_response.text, "_csrf_token")
        if inline_token:
            debug_notes.append("Found a CSRF token in the login page HTML.")
            return inline_token

        csrf_url = urljoin(login_response.url, "/csrf")
        csrf_response = session.get(
            csrf_url,
            headers={"Referer": login_response.url},
            timeout=timeout_seconds,
        )
        if csrf_response.ok:
            try:
                token = str(csrf_response.json().get("token", "")).strip()
            except ValueError:
                token = ""
            if token:
                debug_notes.append(f"Fetched a CSRF token from {csrf_url}.")
                return token

        debug_notes.append("No CSRF token was exposed; continuing with a plain form submit.")
        return ""

    def _extract_sso_providers(self, current_url: str, html: str) -> list[dict[str, Any]]:
        if self._extract_window_bootstrap_value(html, "sso_enabled") is False:
            return []

        providers: list[dict[str, Any]] = []
        raw_value = self._extract_window_bootstrap_value(html, "sso_providers")
        if isinstance(raw_value, list):
            for item in raw_value:
                if not isinstance(item, dict):
                    continue
                jump_url = urljoin(current_url, str(item.get("jump_url", "")).strip())
                if not jump_url:
                    continue
                providers.append(
                    {
                        "id": str(item.get("id", "")).strip(),
                        "title": str(item.get("title", "")).strip(),
                        "button_text": str(item.get("button_text", "")).strip(),
                        "jump_url": jump_url,
                        "ready": bool(item.get("ready", True)),
                        "default": bool(item.get("default", False)),
                        "hidden": bool(item.get("hidden", False)),
                    }
                )

        if providers:
            return providers

        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.select('a[href*="/auth/oidc/"]'):
            href = str(anchor.get("href", "")).strip()
            if not href:
                continue
            text = " ".join(fragment.strip() for fragment in anchor.stripped_strings)
            providers.append(
                {
                    "id": "",
                    "title": text,
                    "button_text": text,
                    "jump_url": urljoin(current_url, href),
                    "ready": True,
                    "default": False,
                    "hidden": False,
                }
            )

        return providers

    def _select_sso_provider(
        self,
        username: str,
        providers: list[dict[str, Any]],
        login_form: dict[str, Any] | None,
        *,
        force: bool = False,
    ) -> tuple[dict[str, Any] | None, str]:
        ready_providers = [
            provider
            for provider in providers
            if provider.get("jump_url") and provider.get("ready", True) and not provider.get("hidden", False)
        ]
        if not ready_providers:
            return None, ""

        default_provider = next((provider for provider in ready_providers if provider.get("default")), None)
        labelled_provider = next(
            (
                provider
                for provider in ready_providers
                if any(
                    marker in " ".join(
                        [
                            str(provider.get("title", "")).lower(),
                            str(provider.get("button_text", "")).lower(),
                        ]
                    )
                    for marker in self.SSO_PROVIDER_TITLE_MARKERS
                )
            ),
            None,
        )
        email_like_username = "@" in username

        if force:
            provider = default_provider or labelled_provider or ready_providers[0]
            return provider, "forced_sso_fallback"

        if login_form is None:
            provider = default_provider or labelled_provider or ready_providers[0]
            return provider, "no_native_login_form"

        if email_like_username and default_provider is not None:
            return default_provider, "default_provider_for_email_login"

        if email_like_username and len(ready_providers) == 1:
            provider = labelled_provider or ready_providers[0]
            return provider, "single_ready_provider_for_email_login"

        return None, ""

    @staticmethod
    def _sso_provider_label(provider: dict[str, Any]) -> str:
        for field_name in ("button_text", "title", "id"):
            value = str(provider.get(field_name, "")).strip()
            if value:
                return value
        return "SSO-provider"

    def _extract_hidden_input(self, html: str, name: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        element = soup.select_one(f'input[name="{name}"]')
        if element is None:
            return ""
        return str(element.get("value", "")).strip()

    def _extract_login_form(self, current_url: str, html: str) -> dict[str, Any] | None:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            username_input = form.select_one('input[name="username"], input[autocomplete="username"]')
            password_input = form.select_one('input[name="password"], input[type="password"]')
            action = str(form.get("action", "")).strip()
            if username_input is None or password_input is None:
                if "verify_credentials" not in action:
                    continue

            hidden_fields: dict[str, str] = {}
            for input_element in form.find_all("input", {"type": "hidden"}):
                name = str(input_element.get("name", "")).strip()
                if not name:
                    continue
                hidden_fields[name] = str(input_element.get("value", ""))

            return {
                "action_url": urljoin(current_url, action or current_url),
                "hidden_fields": hidden_fields,
            }

        return None

    def _extract_page_title(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        if soup.title is None or soup.title.string is None:
            return ""
        return soup.title.string.strip()

    def _extract_otp_checkpoint(self, current_url: str, html: str) -> dict[str, Any] | None:
        soup = BeautifulSoup(html, "html.parser")
        current_path = urlparse(current_url).path.rstrip("/")

        for form in soup.find_all("form"):
            action = str(form.get("action", "")).strip()
            action_url = urljoin(current_url, action or current_url)
            visible_inputs: list[tuple[str, str]] = []
            hidden_fields: dict[str, str] = {}

            for input_element in form.find_all("input"):
                name = str(input_element.get("name", "")).strip()
                if not name:
                    continue
                input_type = str(input_element.get("type", "text")).strip().lower() or "text"
                if input_type == "hidden":
                    hidden_fields[name] = str(input_element.get("value", ""))
                    continue
                visible_inputs.append((name, input_type))

            otp_input_name = next(
                (name for name, _ in visible_inputs if name in {"code", "otp", "token"}),
                "",
            )
            looks_like_otp = bool(otp_input_name)
            looks_like_otp = looks_like_otp or "verify_token" in action_url
            looks_like_otp = looks_like_otp or current_path.endswith("/two_factor")
            looks_like_otp = looks_like_otp or current_path.endswith("/app_setup")
            if not looks_like_otp:
                continue

            if not otp_input_name:
                otp_input_name = next(
                    (
                        name
                        for name, input_type in visible_inputs
                        if input_type not in {"submit", "button"}
                    ),
                    "",
                )

            return {
                "challenge_kind": "otp",
                "action_url": action_url,
                "method": str(form.get("method", "post")).strip().lower() or "post",
                "otp_input_name": otp_input_name,
                "hidden_fields": hidden_fields,
            }

        return None

    def _extract_login_error(self, response: requests.Response, html: str) -> str:
        if response.status_code >= 500:
            return f"De ONS-login gaf HTTP {response.status_code} terug."

        soup = BeautifulSoup(html, "html.parser")
        messages: list[str] = []
        for selector in (".notice", ".error", ".errors", ".flash", '[role="alert"]'):
            for element in soup.select(selector):
                text = " ".join(fragment.strip() for fragment in element.stripped_strings)
                if text:
                    messages.append(text)

        flash_error = self._extract_window_bootstrap_object(html, "flash_error")
        if flash_error:
            flash_error_code = str(flash_error.get("error", "")).strip().lower()
            flash_debug = str(flash_error.get("debug", "")).strip()
            if flash_error_code:
                friendly_message = self.LOGIN_ERROR_CODE_MESSAGES.get(
                    flash_error_code,
                    f"De ONS-site gaf de loginfoutcode {flash_error_code} terug.",
                )
                if flash_debug:
                    return f"{friendly_message} Debug: {flash_debug}"
                return friendly_message

        combined = " ".join(messages) if messages else self._text_snippet(html)
        normalized = combined.lower()
        if any(marker in normalized for marker in self.LOGIN_ERROR_MARKERS):
            return combined
        if response.status_code >= 400:
            return f"De ONS-login gaf HTTP {response.status_code} terug."
        return ""

    def _extract_login_error_code(self, html: str) -> str:
        flash_error = self._extract_window_bootstrap_object(html, "flash_error")
        if not flash_error:
            return ""
        return str(flash_error.get("error", "")).strip().lower()

    @staticmethod
    def _extract_window_bootstrap_object(html: str, variable_name: str) -> dict[str, Any]:
        payload = HttpLoginAutomationClient._extract_window_bootstrap_value(html, variable_name)
        if not isinstance(payload, dict):
            return {}
        return payload

    @staticmethod
    def _extract_window_bootstrap_value(html: str, variable_name: str) -> Any | None:
        return HttpLoginAutomationClient._extract_script_assignment_value(html, f"window.{variable_name}")

    @staticmethod
    def _extract_script_assignment_object(html: str, variable_name: str) -> dict[str, Any]:
        payload = HttpLoginAutomationClient._extract_script_assignment_value(html, variable_name)
        if not isinstance(payload, dict):
            return {}
        return payload

    @staticmethod
    def _extract_script_assignment_value(html: str, variable_name: str) -> Any | None:
        match = re.search(
            rf"{re.escape(variable_name)}\s*=\s*",
            html,
            flags=re.IGNORECASE,
        )
        if match is None:
            return None

        start = match.end()
        while start < len(html) and html[start].isspace():
            start += 1
        if start >= len(html):
            return None

        if html[start] in "[{":
            raw_value = HttpLoginAutomationClient._read_balanced_bootstrap_value(html, start)
        else:
            end = html.find(";", start)
            if end == -1:
                return None
            raw_value = html[start:end].strip()

        if not raw_value:
            return None

        try:
            return json.loads(raw_value)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _read_balanced_bootstrap_value(source: str, start: int) -> str:
        stack = [source[start]]
        in_string = ""
        escaped = False

        for index in range(start + 1, len(source)):
            character = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == in_string:
                    in_string = ""
                continue

            if character in {'"', "'"}:
                in_string = character
                continue

            if character in "[{":
                stack.append(character)
                continue

            if character in "]}":
                if not stack:
                    return ""
                stack.pop()
                if not stack:
                    return source[start : index + 1]

        return ""

    def _response_still_looks_like_login(self, current_url: str, html: str, login_url: str) -> bool:
        soup = BeautifulSoup(html, "html.parser")
        if soup.select_one('form[action*="verify_credentials"]') is not None:
            return True
        if soup.select_one('input[name="username"]') and soup.select_one('input[name="password"]'):
            return True

        current_parts = urlparse(current_url)
        login_parts = urlparse(login_url)
        return (
            current_parts.scheme,
            current_parts.netloc,
            current_parts.path.rstrip("/"),
        ) == (
            login_parts.scheme,
            login_parts.netloc,
            login_parts.path.rstrip("/"),
        )

    def _build_session_checkpoint(
        self,
        *,
        session: requests.Session,
        login_url: str,
        current_url: str,
        page_title: str,
        challenge: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "saved_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "login_url": login_url,
            "current_url": current_url,
            "page_title": page_title,
            "challenge": challenge,
            "cookies": self._serialize_cookies(session.cookies),
        }

    def _serialize_cookies(self, cookie_jar) -> list[dict[str, Any]]:
        cookies: list[dict[str, Any]] = []
        for cookie in cookie_jar:
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": bool(cookie.secure),
                    "expires": cookie.expires,
                }
            )
        return cookies

    @staticmethod
    def _redirect_notes(history: list[requests.Response]) -> list[str]:
        notes: list[str] = []
        for response in history:
            location = response.headers.get("Location", "")
            notes.append(f"Redirect {response.status_code} to {location}.")
        return notes

    @staticmethod
    def _origin_for(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _utc_timestamp() -> str:
        return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _trace_entry_id(trace_index: int) -> str:
        return f"step-{trace_index:03d}"

    def _record_response_step(
        self,
        report_progress: Callable[[dict[str, Any]], None] | None,
        *,
        config: AppConfig,
        snapshot_path: Path,
        trace_index: int,
        label: str,
        message: str,
        phase: str,
        response: requests.Response,
    ) -> int:
        html = response.text or ""
        snapshot_path.write_text(html, encoding="utf-8")
        self._record_event(
            report_progress,
            trace_index=trace_index,
            label=label,
            message=message,
            phase=phase,
            url=response.url,
            page_title=self._extract_page_title(html),
            snapshot_name=self._write_trace_snapshot(config.auth_trace_dir, trace_index, label, html),
            status_code=response.status_code,
        )
        return trace_index + 1

    def _record_event(
        self,
        report_progress: Callable[[dict[str, Any]], None] | None,
        *,
        trace_index: int,
        label: str,
        message: str,
        phase: str,
        url: str,
        page_title: str = "",
        snapshot_name: str = "",
        status_code: int | None = None,
    ) -> None:
        if report_progress is None:
            return
        report_progress(
            {
                "entry_id": self._trace_entry_id(trace_index),
                "created_at": self._utc_timestamp(),
                "label": label,
                "message": message,
                "phase": phase,
                "url": url,
                "page_title": page_title,
                "snapshot_name": snapshot_name,
                "status_code": status_code,
            }
        )

    @staticmethod
    def _slugify_trace_label(label: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", label.strip().lower())
        return normalized.strip("-") or "step"

    def _write_trace_snapshot(self, trace_dir: Path, trace_index: int, label: str, html: str) -> str:
        trace_dir.mkdir(parents=True, exist_ok=True)
        file_name = f"{trace_index:03d}-{self._slugify_trace_label(label)}.html"
        (trace_dir / file_name).write_text(html, encoding="utf-8")
        return file_name

    @staticmethod
    def _text_snippet(html: str, limit: int = 240) -> str:
        soup = BeautifulSoup(html, "html.parser")
        text = " ".join(fragment.strip() for fragment in soup.stripped_strings)
        return text[:limit]
