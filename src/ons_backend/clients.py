from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Protocol

import google.auth.transport.requests
import google.oauth2.service_account
import requests
from bs4 import BeautifulSoup
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
    ) -> AuthenticationResult:
        ...


class FcmPushClient:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def is_configured(self) -> bool:
        return bool(
            self.config.fcm_project_id
            and (
                self.config.fcm_service_account_json
                or (self.config.fcm_service_account_file and self.config.fcm_service_account_file.exists())
            )
        )

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
            f"https://fcm.googleapis.com/v1/projects/{self.config.fcm_project_id}/messages:send",
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
        if self.config.fcm_service_account_json:
            return google.oauth2.service_account.Credentials.from_service_account_info(
                json.loads(self.config.fcm_service_account_json),
                scopes=scopes,
            )

        assert self.config.fcm_service_account_file is not None
        return google.oauth2.service_account.Credentials.from_service_account_file(
            str(self.config.fcm_service_account_file),
            scopes=scopes,
        )


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
    ) -> AuthenticationResult:
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
