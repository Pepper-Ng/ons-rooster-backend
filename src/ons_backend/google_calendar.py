from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import google.auth.transport.requests
import google.oauth2.service_account

from .calendar_export import build_roster_calendar_events, timezone_or_utc, utc_window_for_exports

MANAGED_PROP = "ons_rooster_managed"
KEY_PROP = "ons_rooster_key"
MONTH_PROP = "ons_rooster_month"


@dataclass(frozen=True)
class CalendarSyncSummary:
    created: int = 0
    updated: int = 0
    deleted: int = 0
    unchanged: int = 0
    desired: int = 0
    existing: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "created": self.created,
            "updated": self.updated,
            "deleted": self.deleted,
            "unchanged": self.unchanged,
            "desired": self.desired,
            "existing": self.existing,
        }


class GoogleCalendarSyncClient:
    def __init__(
        self,
        *,
        calendar_id: str,
        timezone: str,
        service_account_file: str | None,
        service_account_json: str,
        dry_run: bool = False,
    ) -> None:
        self.calendar_id = calendar_id.strip()
        self.timezone = timezone_or_utc(timezone.strip() or "Europe/Amsterdam").key
        self.service_account_file = service_account_file.strip() if service_account_file else ""
        self.service_account_json = service_account_json.strip()
        self.dry_run = dry_run

    def is_configured(self) -> bool:
        return bool(self.calendar_id and (self.service_account_file or self.service_account_json))

    def sync_exports(self, month_exports: list[dict[str, Any]]) -> CalendarSyncSummary:
        if not self.calendar_id:
            raise RuntimeError("Google Calendar sync mist GOOGLE_CALENDAR_ID.")
        if not month_exports:
            return CalendarSyncSummary()

        desired = self._build_desired_events(month_exports)
        window = self._determine_window(month_exports, desired)
        if window is None:
            return CalendarSyncSummary(desired=0, existing=0)
        time_min, time_max = window

        existing = self._list_managed_events(time_min, time_max)
        existing_by_key = {
            self._extract_key(event): event
            for event in existing
            if self._extract_key(event)
        }

        created = 0
        updated = 0
        unchanged = 0
        deleted = 0

        desired_by_key = {event["_key"]: event for event in desired}
        for key, event_body in desired_by_key.items():
            existing_event = existing_by_key.get(key)
            if existing_event is None:
                created += 1
                if not self.dry_run:
                    self._insert_event(event_body)
                continue

            if self._needs_update(existing_event, event_body):
                updated += 1
                if not self.dry_run:
                    self._update_event(existing_event["id"], event_body)
            else:
                unchanged += 1

        for key, event in existing_by_key.items():
            if key not in desired_by_key:
                deleted += 1
                if not self.dry_run:
                    self._delete_event(event["id"])

        return CalendarSyncSummary(
            created=created,
            updated=updated,
            deleted=deleted,
            unchanged=unchanged,
            desired=len(desired_by_key),
            existing=len(existing_by_key),
        )

    def _build_desired_events(self, month_exports: list[dict[str, Any]]) -> list[dict[str, Any]]:
        desired: list[dict[str, Any]] = []
        timezone = timezone_or_utc(self.timezone)
        for roster_event in build_roster_calendar_events(month_exports):
            start = roster_event.start_datetime(timezone)
            end = roster_event.end_datetime(timezone)
            if start is None or end is None:
                continue
            desired.append(
                {
                    "id": self._event_id(roster_event.key),
                    "summary": roster_event.title,
                    "description": roster_event.description,
                    "start": {
                        "dateTime": start.strftime("%Y-%m-%dT%H:%M:%S"),
                        "timeZone": self.timezone,
                    },
                    "end": {
                        "dateTime": end.strftime("%Y-%m-%dT%H:%M:%S"),
                        "timeZone": self.timezone,
                    },
                    "extendedProperties": {
                        "private": {
                            MANAGED_PROP: "1",
                            KEY_PROP: roster_event.key,
                            MONTH_PROP: roster_event.month,
                        }
                    },
                    "_key": roster_event.key,
                }
            )
        return desired

    def _determine_window(
        self,
        month_exports: list[dict[str, Any]],
        desired: list[dict[str, Any]],
    ) -> tuple[str, str] | None:
        return utc_window_for_exports(
            month_exports,
            build_roster_calendar_events(month_exports) if desired else [],
            self.timezone,
        )

    @staticmethod
    def _event_id(event_key: str) -> str:
        # Calendar event IDs should use only a small ASCII subset; hex is safe.
        return f"onsr{event_key[:40]}"

    def _extract_key(self, event: dict[str, Any]) -> str:
        props = event.get("extendedProperties", {}).get("private", {})
        return str(props.get(KEY_PROP, "")).strip()

    @staticmethod
    def _needs_update(existing_event: dict[str, Any], desired_event: dict[str, Any]) -> bool:
        comparable_fields = ("summary", "description", "start", "end", "extendedProperties")
        for field_name in comparable_fields:
            if existing_event.get(field_name) != desired_event.get(field_name):
                return True
        return False

    def _insert_event(self, event_body: dict[str, Any]) -> None:
        body = {key: value for key, value in event_body.items() if not key.startswith("_")}
        path = f"/calendar/v3/calendars/{quote(self.calendar_id, safe='')}/events"
        self._request("POST", path, json_body=body)

    def _update_event(self, event_id: str, event_body: dict[str, Any]) -> None:
        body = {key: value for key, value in event_body.items() if not key.startswith("_")}
        path = (
            f"/calendar/v3/calendars/{quote(self.calendar_id, safe='')}/events/"
            f"{quote(event_id, safe='')}"
        )
        self._request("PUT", path, json_body=body)

    def _delete_event(self, event_id: str) -> None:
        path = (
            f"/calendar/v3/calendars/{quote(self.calendar_id, safe='')}/events/"
            f"{quote(event_id, safe='')}"
        )
        self._request("DELETE", path)

    def _list_managed_events(self, time_min: str, time_max: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page_token = ""
        while True:
            query = {
                "singleEvents": "true",
                "showDeleted": "false",
                "maxResults": "2500",
                "timeMin": time_min,
                "timeMax": time_max,
                "privateExtendedProperty": f"{MANAGED_PROP}=1",
            }
            if page_token:
                query["pageToken"] = page_token

            path = f"/calendar/v3/calendars/{quote(self.calendar_id, safe='')}/events"
            response = self._request("GET", path, query=query)
            page_items = response.get("items", [])
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
            page_token = str(response.get("nextPageToken", "")).strip()
            if not page_token:
                return items

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self._authorized_session()
        url = f"https://www.googleapis.com{path}"
        response = session.request(method, url, params=query, json=json_body, timeout=30)
        if response.status_code >= 400:
            raise RuntimeError(
                f"Google Calendar API fout ({response.status_code}): {response.text[:400]}"
            )
        if response.status_code == 204:
            return {}
        payload = response.json()
        if not isinstance(payload, dict):
            return {}
        return payload

    def _authorized_session(self):
        scopes = ["https://www.googleapis.com/auth/calendar"]
        credentials = self._load_credentials(scopes)
        return google.auth.transport.requests.AuthorizedSession(credentials)

    def _load_credentials(self, scopes: list[str]):
        if self.service_account_json:
            try:
                info = json.loads(self.service_account_json)
            except json.JSONDecodeError as exc:
                raise RuntimeError("GOOGLE_SERVICE_ACCOUNT_JSON is geen geldige JSON.") from exc
            return google.oauth2.service_account.Credentials.from_service_account_info(
                info,
                scopes=scopes,
            )
        if self.service_account_file:
            return google.oauth2.service_account.Credentials.from_service_account_file(
                self.service_account_file,
                scopes=scopes,
            )
        raise RuntimeError("Geen Google service-account bron geconfigureerd.")