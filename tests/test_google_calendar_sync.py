from __future__ import annotations

from ons_backend.calendar_export import build_icalendar
from ons_backend.google_calendar import GoogleCalendarSyncClient


class InMemoryCalendarSyncClient(GoogleCalendarSyncClient):
    def __init__(self) -> None:
        super().__init__(
            calendar_id="calendar-id@example.com",
            timezone="Europe/Amsterdam",
            service_account_file="fake.json",
            service_account_json="",
            dry_run=False,
        )
        self.existing_events: list[dict] = []
        self.inserted: list[dict] = []
        self.updated: list[tuple[str, dict]] = []
        self.deleted: list[str] = []

    def _list_managed_events(self, time_min: str, time_max: str) -> list[dict]:
        del time_min, time_max
        return list(self.existing_events)

    def _insert_event(self, event_body: dict) -> None:
        self.inserted.append(event_body)

    def _update_event(self, event_id: str, event_body: dict) -> None:
        self.updated.append((event_id, event_body))

    def _delete_event(self, event_id: str) -> None:
        self.deleted.append(event_id)



def _sample_export(title: str = "A1-SOM-2-MA") -> dict:
    return {
        "format": "ons-rooster-month-export",
        "version": 1,
        "month": "2026-06",
        "source_url": "https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
        "page_title": "Rooster",
        "items": [
            {
                "date": "2026-06-01",
                "start": "15:00",
                "end": "23:30",
                "title": title,
                "description": "15:00 23:30 (30M PAUZE) A1-SOM-2-MA",
                "category": "planned_hours",
                "is_planned_hours": True,
                "classes": ["roster_slot", "shiftassignment"],
            },
            {
                "date": "2026-06-02",
                "start": "09:00",
                "end": "17:00",
                "title": "Vaste vrije dag",
                "description": "09:00 17:00 Vaste vrije dag",
                "category": "availability",
                "is_planned_hours": False,
                "classes": ["roster_slot", "unavailability"],
            },
        ],
    }


def test_event_key_is_deterministic() -> None:
    client = InMemoryCalendarSyncClient()
    first = client._build_desired_events([_sample_export()])
    second = client._build_desired_events([_sample_export()])

    assert len(first) == 1
    assert first[0]["_key"] == second[0]["_key"]
    assert first[0]["id"] == second[0]["id"]


def test_event_key_ignores_mutable_roster_text() -> None:
    client = InMemoryCalendarSyncClient()
    first = client._build_desired_events([_sample_export(title="A1-SOM-2-MA")])
    changed_title = _sample_export(title="A1-SOM-2-MA GEWIJZIGD")
    changed_title["items"][0]["description"] = "15:00 23:30 gewijzigde omschrijving"
    second = client._build_desired_events([changed_title])

    assert first[0]["_key"] == second[0]["_key"]
    assert first[0]["summary"] != second[0]["summary"]


def test_window_uses_export_month_in_local_timezone() -> None:
    client = InMemoryCalendarSyncClient()
    export = _sample_export()

    assert client._determine_window([export], client._build_desired_events([export])) == (
        "2026-05-31T22:00:00Z",
        "2026-06-30T22:00:00Z",
    )


def test_icalendar_uses_same_planned_month_exports() -> None:
    payload = build_icalendar([_sample_export()], timezone_name="Europe/Amsterdam").decode("utf-8")

    assert "BEGIN:VCALENDAR" in payload
    assert "BEGIN:VEVENT" in payload
    assert "UID:ons-rooster-" in payload
    assert "SUMMARY:A1-SOM-2-MA" in payload
    assert "Vaste vrije dag" not in payload


def test_sync_exports_creates_updates_and_deletes() -> None:
    client = InMemoryCalendarSyncClient()
    desired = client._build_desired_events([_sample_export(title="NEW-TITLE")])
    desired_key = desired[0]["_key"]

    client.existing_events = [
        {
            "id": "event-to-update",
            "summary": "OLD-TITLE",
            "description": desired[0]["description"],
            "start": desired[0]["start"],
            "end": desired[0]["end"],
            "extendedProperties": {
                "private": {
                    "ons_rooster_managed": "1",
                    "ons_rooster_key": desired_key,
                    "ons_rooster_month": "2026-06",
                }
            },
        },
        {
            "id": "event-to-delete",
            "summary": "Obsolete",
            "description": "obsolete",
            "start": desired[0]["start"],
            "end": desired[0]["end"],
            "extendedProperties": {
                "private": {
                    "ons_rooster_managed": "1",
                    "ons_rooster_key": "old-key",
                    "ons_rooster_month": "2026-06",
                }
            },
        },
    ]

    summary = client.sync_exports([_sample_export(title="NEW-TITLE")])

    assert summary.created == 0
    assert summary.updated == 1
    assert summary.deleted == 1
    assert summary.unchanged == 0
    assert client.inserted == []
    assert len(client.updated) == 1
    assert client.updated[0][0] == "event-to-update"
    assert client.deleted == ["event-to-delete"]
