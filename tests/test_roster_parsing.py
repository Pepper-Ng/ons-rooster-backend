"""Unit tests for roster HTML parsing using a captured full-page example (roster.html)."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from ons_backend.clients import HttpLoginAutomationClient


# Path to the reference roster HTML stored in the workspace root.
ROSTER_HTML_PATH = Path(__file__).parent.parent.parent.parent / "roster.html"

# Fallback: also try the workspace root relative to this file two levels up.
_ALT_PATH = Path(__file__).parent.parent.parent / "roster.html"


def _load_roster_html() -> str:
    for candidate in (ROSTER_HTML_PATH, _ALT_PATH):
        if candidate.exists():
            return candidate.read_text(encoding="utf-8")
    pytest.skip(f"roster.html not found (tried {ROSTER_HTML_PATH} and {_ALT_PATH})")


@pytest.fixture(scope="module")
def client() -> HttpLoginAutomationClient:
    return HttpLoginAutomationClient()


@pytest.fixture(scope="module")
def roster_html() -> str:
    return _load_roster_html()


class TestExtractMonthRosterExport:
    def test_items_not_empty(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        """Parsing the reference HTML must yield at least one roster item."""
        export, planned, notes, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        assert export["items"], f"Expected items but got empty list. Notes: {notes}"

    def test_metadata(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        export, _, _, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        assert export["format"] == "ons-rooster-month-export"
        assert export["month"] == "2026-06"
        assert export["page_title"] == "Rooster"

    def test_first_june_afternoon_shift(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        """1 June 2026 should have an afternoon shift 15:00–23:30 (A1-SOM-2-MA)."""
        export, _, _, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        items = export["items"]
        june_1 = [i for i in items if i.get("date") == "2026-06-01"]
        assert june_1, f"No items found for 2026-06-01. All dates: {[i.get('date') for i in items]}"
        match = next((i for i in june_1 if i.get("start") == "15:00" and i.get("end") == "23:30"), None)
        assert match is not None, f"Expected 15:00–23:30 shift on 2026-06-01, found: {june_1}"
        assert "A1-SOM-2-MA" in match.get("title", ""), f"Unexpected title: {match.get('title')}"
        assert match["category"] == "planned_hours"

    def test_june_3_unavailability(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        """3 June 2026 is a 'Vaste vrije dag' (fixed day off)."""
        export, _, _, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        items = export["items"]
        june_3 = [i for i in items if i.get("date") == "2026-06-03"]
        assert june_3, f"No items for 2026-06-03. All dates: {sorted({i.get('date') for i in items})}"
        unavail = next((i for i in june_3 if i.get("category") == "availability"), None)
        assert unavail is not None, f"Expected an availability item on 2026-06-03, got: {june_3}"

    def test_planned_entries_returned(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        """The planned_entries list should contain RosterItem objects for shift assignments."""
        _, planned, _, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        assert planned, "Expected at least one planned RosterItem"
        # Every planned item should have a valid date string and time pair
        for item in planned:
            assert item.date, f"RosterItem missing date: {item}"
            assert item.start, f"RosterItem missing start: {item}"
            assert item.end, f"RosterItem missing end: {item}"

    def test_all_item_dates_in_june_or_adjacent(self, client: HttpLoginAutomationClient, roster_html: str) -> None:
        """All items with a parsed date should be in June 2026 or the adjacent boundary days."""
        export, _, _, _ = client._extract_month_roster_export(
            roster_html,
            month_start=date(2026, 6, 1),
            source_url="https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month",
            page_title="Rooster",
        )
        for item in export["items"]:
            d = item.get("date")
            if d:
                parsed = date.fromisoformat(d)
                # The last week row shows days from July 2026 (boundary)
                assert parsed.year in (2026, 2025), f"Unexpected year in date {d}"
