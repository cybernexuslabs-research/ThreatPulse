#!/usr/bin/env python3
"""
ThreatPulse - Shared CVE lifecycle event helper.

Both cve_collector.py (ingest/score/exploit/POC transitions) and
cve_reporter.py (the `processed` event, written from mark_as_processed())
need to write rows to the cve_events table. This tiny module exists so
neither CLI entrypoint has to import the other just to reuse one INSERT.

See docs/features/TIMELINE_VIEW_FEATURE.md for the event_type vocabulary
and what belongs in `detail` for each one.
"""

import json
import sqlite3
from datetime import datetime
from typing import Optional


def record_event(
    conn: sqlite3.Connection,
    cve_id: str,
    event_type: str,
    detail: Optional[dict] = None,
    event_date: Optional[str] = None,
) -> None:
    """Insert one row into cve_events. Does not commit — caller controls the transaction.

    event_date defaults to now, in local time (datetime.now().isoformat()) —
    matching every other timestamp column in this schema (cves.first_seen/
    last_checked, collections.created_at/updated_at, collection_members.added_at).
    The design doc's original pseudocode used datetime.utcnow(); local time
    was chosen instead to avoid introducing the one UTC column in an
    otherwise all-local-time app, which would silently skew any duration
    math (e.g. days-to-exploit) that compares event_date against
    cves.published_date or other local-time columns.

    event_date accepts an explicit override so tests can assert on exact
    durations without monkeypatching datetime.
    """
    conn.execute(
        "INSERT INTO cve_events (cve_id, event_type, event_date, detail) VALUES (?, ?, ?, ?)",
        (
            cve_id,
            event_type,
            event_date or datetime.now().isoformat(),
            json.dumps(detail or {}),
        ),
    )
