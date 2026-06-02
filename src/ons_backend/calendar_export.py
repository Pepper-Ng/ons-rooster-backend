from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from icalendar import Calendar, Event


@dataclass(frozen=True)
class RosterCalendarEvent:
    key: str
    month: str
    source_url: str
    date: str
    start: str
    end: str
    title: str
    description: str

    def start_datetime(self, timezone: ZoneInfo) -> datetime | None:
        return parse_local_datetime(self.date, self.start, timezone)

    def end_datetime(self, timezone: ZoneInfo) -> datetime | None:
        start = self.start_datetime(timezone)
        end = parse_local_datetime(self.date, self.end, timezone)
        if start is not None and end is not None and end <= start:
            return end + timedelta(days=1)
        return end


def timezone_or_utc(timezone_name: str) -> ZoneInfo:
    try:
        return ZoneInfo(timezone_name.strip() or "Europe/Amsterdam")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def build_roster_calendar_events(month_exports: Iterable[dict[str, Any]]) -> list[RosterCalendarEvent]:
    events: list[RosterCalendarEvent] = []
    seen_event_keys: set[str] = set()

    for export_payload in month_exports:
        month = str(export_payload.get("month", "")).strip()
        source_url = str(export_payload.get("source_url", "")).strip()
        items = export_payload.get("items", [])
        if not isinstance(items, list):
            continue

        for item in items:
            if not isinstance(item, dict):
                continue
            if not bool(item.get("is_planned_hours")):
                continue

            date_value = str(item.get("date", "")).strip()
            start_value = str(item.get("start", "")).strip()
            end_value = str(item.get("end", "")).strip()
            if not date_value or not start_value or not end_value:
                continue

            event_key = roster_event_key(
                month=month,
                source_url=source_url,
                item=item,
            )
            if event_key in seen_event_keys:
                continue
            seen_event_keys.add(event_key)

            title = str(item.get("title", "")).strip() or str(item.get("description", "")).strip() or "Dienst"
            description_parts = [str(item.get("description", "")).strip()]
            if source_url:
                description_parts.append(f"Source: {source_url}")
            description = "\n".join(part for part in description_parts if part)

            events.append(
                RosterCalendarEvent(
                    key=event_key,
                    month=month,
                    source_url=source_url,
                    date=date_value,
                    start=start_value,
                    end=end_value,
                    title=title,
                    description=description,
                )
            )

    return events


def roster_event_key(
    *,
    month: str,
    source_url: str,
    item: dict[str, Any],
    occurrence_index: int = 0,
) -> str:
    payload = {
        "date": str(item.get("date", "")).strip(),
        "start": str(item.get("start", "")).strip(),
        "end": str(item.get("end", "")).strip(),
    }
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def utc_window_for_exports(
    month_exports: Iterable[dict[str, Any]],
    events: Iterable[RosterCalendarEvent],
    timezone_name: str,
) -> tuple[str, str] | None:
    timezone = timezone_or_utc(timezone_name)
    month_starts = [_parse_month_start(str(export.get("month", "")).strip()) for export in month_exports]
    valid_month_starts = [month_start for month_start in month_starts if month_start is not None]
    if valid_month_starts:
        first_month = min(valid_month_starts)
        month_after_last = _add_months(max(valid_month_starts), 1)
        return (
            _to_rfc3339_utc(datetime(first_month.year, first_month.month, 1, tzinfo=timezone)),
            _to_rfc3339_utc(datetime(month_after_last.year, month_after_last.month, 1, tzinfo=timezone)),
        )

    starts: list[datetime] = []
    ends: list[datetime] = []
    for event in events:
        start = event.start_datetime(timezone)
        end = event.end_datetime(timezone)
        if start is not None:
            starts.append(start)
        if end is not None:
            ends.append(end)

    if not starts or not ends:
        return None
    return (
        _to_rfc3339_utc(min(starts) - timedelta(days=1)),
        _to_rfc3339_utc(max(ends) + timedelta(days=1)),
    )


def build_icalendar(month_exports: Iterable[dict[str, Any]], *, timezone_name: str) -> bytes:
    timezone = timezone_or_utc(timezone_name)
    generated_at = datetime.now(UTC).replace(microsecond=0)
    calendar = Calendar()
    calendar.add("prodid", "-//ONS Rooster Backend//NL")
    calendar.add("version", "2.0")
    calendar.add("x-wr-calname", "ONS Rooster")
    calendar.add("x-wr-timezone", timezone.key)
    calendar.add("method", "PUBLISH")

    for roster_event in build_roster_calendar_events(month_exports):
        start = roster_event.start_datetime(timezone)
        end = roster_event.end_datetime(timezone)
        if start is None or end is None:
            continue

        event = Event()
        event.add("uid", f"ons-rooster-{roster_event.key}@ons-rooster-backend")
        event.add("summary", roster_event.title)
        if roster_event.description:
            event.add("description", roster_event.description)
        event.add("dtstart", start)
        event.add("dtend", end)
        event.add("dtstamp", generated_at)
        event.add("last-modified", generated_at)
        event.add("categories", ["ONS Rooster"])
        calendar.add_component(event)

    return calendar.to_ical()


def parse_local_datetime(date_value: str, time_value: str, timezone: ZoneInfo) -> datetime | None:
    if not date_value or not time_value:
        return None
    normalized_date = date_value.replace("/", "-")
    for fmt in ("%Y-%m-%d %H:%M", "%d-%m-%Y %H:%M", "%d-%m-%y %H:%M"):
        try:
            parsed = datetime.strptime(f"{normalized_date} {time_value}", fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone)
    return None


def _parse_month_start(month_key: str) -> date | None:
    try:
        return datetime.strptime(month_key, "%Y-%m").date().replace(day=1)
    except ValueError:
        return None


def _add_months(month_start: date, offset: int) -> date:
    total_months = month_start.year * 12 + (month_start.month - 1) + offset
    year = total_months // 12
    month = total_months % 12 + 1
    return date(year=year, month=month, day=1)


def _to_rfc3339_utc(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")