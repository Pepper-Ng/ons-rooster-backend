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
    ) -> AuthenticationResult:
        del report_progress
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
    )

    async def authenticate_and_scrape(
        self,
        credentials: LoginCredentials,
        request_sms_code: Callable[[], Awaitable[str]],
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> AuthenticationResult:
        del request_sms_code
        loop = asyncio.get_running_loop()

        def sync_progress(event: dict[str, Any]) -> None:
            if report_progress is None:
                return
            future = asyncio.run_coroutine_threadsafe(report_progress(event), loop)
            future.result(timeout=max(config.login_timeout_seconds, 5))

        return await asyncio.to_thread(
            self._authenticate_sync,
            credentials,
            snapshot_path,
            config,
            sync_progress,
        )

    def _authenticate_sync(
        self,
        credentials: LoginCredentials,
        snapshot_path: Path,
        config: AppConfig,
        report_progress: Callable[[dict[str, Any]], None] | None,
    ) -> AuthenticationResult:
        debug_notes: list[str] = []
        login_url = credentials.login_url or config.default_login_url
        trace_index = 1

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
            login_form = self._extract_login_form(login_response.url, login_response.text)
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

        combined = " ".join(messages) if messages else self._text_snippet(html)
        normalized = combined.lower()
        if any(marker in normalized for marker in self.LOGIN_ERROR_MARKERS):
            return combined
        if response.status_code >= 400:
            return f"De ONS-login gaf HTTP {response.status_code} terug."
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
