"""Snapshot test for roster HTML parsing.

The test data lives in tests/data/:
  roster.html                   — captured full-page HTML for June 2026
  expected_export_2026-06.json  — golden output produced by _extract_month_roster_export()

The test parses roster.html, strips the volatile ``generated_at`` timestamp from
the result, and compares it field-for-field against the golden file.  Any change
to the parsing logic that alters the output will cause this test to fail.

To regenerate the golden file after an intentional parsing change, run:

    python scripts/regenerate_golden.py  (or delete the JSON and re-run the
    generate block below with UPDATE_GOLDEN=1 env var)
"""
from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path

import pytest

from ons_backend.clients import HttpLoginAutomationClient

DATA_DIR = Path(__file__).parent / "data"
ROSTER_HTML = DATA_DIR / "roster.html"
GOLDEN_JSON = DATA_DIR / "expected_export_2026-06.json"

MONTH_START = date(2026, 6, 1)
SOURCE_URL = "https://landvanhorne.hasmoves.com/onsdraaiboek/roster/2026-06-01/month"
PAGE_TITLE = "Rooster"


@pytest.fixture(scope="module")
def client() -> HttpLoginAutomationClient:
    return HttpLoginAutomationClient()


@pytest.fixture(scope="module")
def parsed_export(client: HttpLoginAutomationClient) -> dict:
    """Parse roster.html and return the export dict (without volatile generated_at)."""
    if not ROSTER_HTML.exists():
        pytest.skip(f"Test fixture not found: {ROSTER_HTML}")
    html = ROSTER_HTML.read_text(encoding="utf-8")
    export, _, _, _ = client._extract_month_roster_export(
        html,
        month_start=MONTH_START,
        source_url=SOURCE_URL,
        page_title=PAGE_TITLE,
    )
    export.pop("generated_at", None)
    return export


@pytest.fixture(scope="module")
def golden() -> dict:
    """Load the golden/expected JSON from tests/data/."""
    if not GOLDEN_JSON.exists():
        pytest.skip(f"Golden file not found: {GOLDEN_JSON}")
    return json.loads(GOLDEN_JSON.read_text(encoding="utf-8"))


class TestRosterParsingSnapshot:
    def test_export_matches_golden(self, parsed_export: dict, golden: dict) -> None:
        """Full snapshot check: parsed output must exactly match the golden file."""
        assert parsed_export == golden, (
            "Roster parsing output no longer matches the golden file "
            f"({GOLDEN_JSON.name}).  If this change is intentional, regenerate "
            "the golden file by running: "
            "python -c \"import json; ...\" (see module docstring)."
        )

    def test_items_not_empty(self, parsed_export: dict) -> None:
        assert parsed_export["items"], "Expected at least one item"

    def test_metadata(self, parsed_export: dict) -> None:
        assert parsed_export["format"] == "ons-rooster-month-export"
        assert parsed_export["month"] == "2026-06"
        assert parsed_export["page_title"] == PAGE_TITLE

    def test_planned_entries_have_times(self, client: HttpLoginAutomationClient) -> None:
        """The planned_entries list returned by the parser must have date/start/end."""
        if not ROSTER_HTML.exists():
            pytest.skip(f"Test fixture not found: {ROSTER_HTML}")
        html = ROSTER_HTML.read_text(encoding="utf-8")
        _, planned, _, _ = client._extract_month_roster_export(
            html,
            month_start=MONTH_START,
            source_url=SOURCE_URL,
            page_title=PAGE_TITLE,
        )
        assert planned, "Expected at least one planned RosterItem"
        for item in planned:
            assert item.date, f"RosterItem missing date: {item}"
            assert item.start, f"RosterItem missing start: {item}"
            assert item.end, f"RosterItem missing end: {item}"
